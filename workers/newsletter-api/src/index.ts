export interface Env {
  NEWSLETTER_SUBSCRIBERS: KVNamespace; // dual-write target + rate limit + caches
  R2_BUCKET?: R2Bucket;
  ALLOWED_ORIGIN?: string;
  ENVIRONMENT?: string;
  LINKEDIN_NEWSLETTER_URLS?: string;

  // Listmonk — primary email sender (Welcome / Thanks template via /api/tx)
  LISTMONK_API_URL?: string;
  LISTMONK_API_USER?: string;
  LISTMONK_API_TOKEN?: string;
  LISTMONK_LIST_ID?: string;
  LISTMONK_WELCOME_TEMPLATE_ID?: string;

  // Rollback path: direct Plunk API call (kept as automatic fallback).
  // To force-rollback: remove LISTMONK_* secrets and Worker uses these instead.
  PLUNK_SECRET_KEY?: string;
  ADMIN_TOKEN?: string; // operator bearer token for /api/test-email and admin unsubscribe
  UNSUBSCRIBE_HMAC_SECRET?: string; // signs subscriber-bound unsubscribe tokens
  UNSUBSCRIBE_BASE_URL?: string; // origin used in email unsubscribe links
}

interface NewsletterItem {
  filename: string;
  date: string;
  title: string;
  url: string;
}

const MAX_REQUEST_SIZE = 1024;
const UNSUBSCRIBE_TOKEN_VERSION = 'v1';
// The account's workers.dev subdomain is `philippd`, not `philippdubach`; the
// blog's endpoint configuration previously pointed at a hostname that does not
// resolve.  Override via UNSUBSCRIBE_BASE_URL if a custom domain is added.
const DEFAULT_UNSUBSCRIBE_BASE_URL = 'https://newsletter-api.philippd.workers.dev';
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX_REQUESTS = 5;
const MAX_EMAIL_LENGTH = 320;

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
};

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin');
  const allowedOrigin = env.ALLOWED_ORIGIN || 'https://philippdubach.com';
  const allowedOrigins = allowedOrigin.split(',').map(o => o.trim());

  if (origin && allowedOrigins.some(allowed =>
    origin === allowed ||
    origin.endsWith('.philippdubach.com')
  )) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      ...securityHeaders,
    };
  }

  return {
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...securityHeaders,
  };
}

function handleOptions(request: Request, env: Env): Response {
  return new Response(null, { headers: getCorsHeaders(request, env) });
}

function jsonResponse(data: unknown, status: number, request: Request, env: Env): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...getCorsHeaders(request, env),
      'Content-Type': 'application/json',
    },
  });
}

function htmlResponse(body: string, status: number, request: Request, env: Env): Response {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Newsletter</title></head><body>${body}</body></html>`, {
    status,
    headers: {
      ...getCorsHeaders(request, env),
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    },
  });
}

function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  if (email.length > MAX_EMAIL_LENGTH) return false;
  return EMAIL_REGEX.test(email);
}

interface ParsedBody {
  email?: string;
  token?: string;
  honeypot?: string;
}

type BodyResult =
  | { ok: true; body: ParsedBody }
  | { ok: false; status: number; error: string };

/**
 * Read and validate a POST body with an actual byte limit.
 *
 * Accepts JSON and URL-encoded form bodies (the blog's no-JavaScript native
 * form sends the latter), and rejects malformed input as a client error rather
 * than a 500.  The declared Content-Length is only an early rejection; the
 * streamed body itself is bounded.
 */
async function readBody(request: Request): Promise<BodyResult> {
  const declared = request.headers.get('Content-Length');
  if (declared && parseInt(declared, 10) > MAX_REQUEST_SIZE) {
    return { ok: false, status: 413, error: 'Request too large' };
  }
  let text: string;
  try {
    text = await request.text();
  } catch {
    return { ok: false, status: 400, error: 'Invalid request body' };
  }
  if (text.length > MAX_REQUEST_SIZE) {
    return { ok: false, status: 413, error: 'Request too large' };
  }
  const rawType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  const jsonLike = !rawType || rawType === 'application/json' || rawType === 'text/plain';
  if (jsonLike) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed !== 'object' || parsed === null) {
        return { ok: false, status: 400, error: 'Invalid request body' };
      }
      return { ok: true, body: parsed as ParsedBody };
    } catch {
      // Not JSON; fall through to form parsing for native form submissions.
    }
  }
  if (rawType && !jsonLike && rawType !== 'application/x-www-form-urlencoded') {
    return { ok: false, status: 415, error: 'Unsupported content type' };
  }
  try {
    const params = new URLSearchParams(text);
    return {
      ok: true,
      body: {
        email: params.get('email') ?? undefined,
        token: params.get('token') ?? undefined,
        honeypot: params.get('honeypot') ?? undefined,
      },
    };
  } catch {
    return { ok: false, status: 400, error: 'Invalid request body' };
  }
}

function redactEmail(email: string): string {
  const at = email.indexOf('@');
  if (at <= 1) return '***';
  return `${email[0]}***${email.slice(at)}`;
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Subscriber-bound token: HMAC over the subscriber's email and a server secret. */
async function signUnsubscribeToken(email: string, env: Env): Promise<string | null> {
  if (!env.UNSUBSCRIBE_HMAC_SECRET) return null;
  return `${UNSUBSCRIBE_TOKEN_VERSION}:${await hmacHex(env.UNSUBSCRIBE_HMAC_SECRET, email)}`;
}

async function verifyUnsubscribeToken(email: string, token: string | undefined, env: Env): Promise<boolean> {
  if (!env.UNSUBSCRIBE_HMAC_SECRET || !token) return false;
  const prefix = `${UNSUBSCRIBE_TOKEN_VERSION}:`;
  if (!token.startsWith(prefix)) return false;
  const expected = await hmacHex(env.UNSUBSCRIBE_HMAC_SECRET, email);
  return timingSafeEqual(token.slice(prefix.length), expected);
}

function unsubscribeUrl(email: string, token: string, env: Env): string {
  const base = env.UNSUBSCRIBE_BASE_URL || DEFAULT_UNSUBSCRIBE_BASE_URL;
  return `${base}/api/unsubscribe?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
}

function getClientIP(request: Request): string {
  const cfIP = request.headers.get('CF-Connecting-IP');
  if (cfIP) return cfIP;
  const xff = request.headers.get('X-Forwarded-For');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

async function checkRateLimit(ip: string, env: Env): Promise<boolean> {
  const key = `rate_limit:${ip}`;
  try {
    const current = await env.NEWSLETTER_SUBSCRIBERS.get(key);
    const now = Date.now();

    if (!current) {
      await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify({
        count: 1,
        resetAt: now + RATE_LIMIT_WINDOW_MS,
      }), { expirationTtl: 120 });
      return true;
    }

    const data = JSON.parse(current) as { count: number; resetAt: number };

    if (data.resetAt < now) {
      await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify({
        count: 1,
        resetAt: now + RATE_LIMIT_WINDOW_MS,
      }), { expirationTtl: 120 });
      return true;
    }

    if (data.count >= RATE_LIMIT_MAX_REQUESTS) return false;

    data.count++;
    await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify(data), { expirationTtl: 120 });
    return true;
  } catch {
    return true;
  }
}

/* =============================================================================
 * Listmonk integration
 * KV is the secondary durable store (rate-limit + dual-write safety net).
 * Listmonk is the email-sending source of truth.
 * ========================================================================== */

function isListmonkConfigured(env: Env): boolean {
  return Boolean(env.LISTMONK_API_URL && env.LISTMONK_API_USER && env.LISTMONK_API_TOKEN && env.LISTMONK_LIST_ID);
}

async function callListmonk(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const auth = btoa(`${env.LISTMONK_API_USER}:${env.LISTMONK_API_TOKEN}`);
  const url = `${env.LISTMONK_API_URL}${path}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const resp = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        ...(init.headers || {}),
      },
    });
    clearTimeout(timeoutId);
    return resp;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

async function createListmonkSubscriber(email: string, clientIP: string, env: Env): Promise<{ success: boolean; error?: string }> {
  if (!isListmonkConfigured(env)) {
    return { success: false, error: 'Listmonk not configured' };
  }
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    const resp = await callListmonk(env, '/api/subscribers', {
      method: 'POST',
      body: JSON.stringify({
        email,
        name: '',
        status: 'enabled',
        lists: [listId],
        preconfirm_subscriptions: true,
        attribs: {
          source: 'newsletter-api',
          subscribed_ip: clientIP,
        },
      }),
    });

    if (resp.ok) return { success: true };

    const body = await resp.text();
    // 409 / duplicate is fine — subscriber already exists, treat as success
    if (resp.status === 409 || body.toLowerCase().includes('already exists') || body.toLowerCase().includes('duplicate')) {
      return { success: true };
    }
    return { success: false, error: `Listmonk subscribe HTTP ${resp.status}: ${body.slice(0, 200)}` };
  } catch (err) {
    return { success: false, error: `Listmonk subscribe exception: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function unsubscribeFromListmonk(email: string, env: Env): Promise<{ success: boolean; error?: string }> {
  // Without Listmonk configuration there is nothing to reconcile; the KV entry
  // is the only store and has already been removed by the caller.
  if (!isListmonkConfigured(env)) return { success: true };
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    const safeEmail = email.replace(/'/g, "''");
    // Documented Listmonk route is plural (PUT /api/subscribers/query/lists);
    // the singular path used earlier is not a registered alias.
    const resp = await callListmonk(env, '/api/subscribers/query/lists', {
      method: 'PUT',
      body: JSON.stringify({
        query: `subscribers.email = '${safeEmail}'`,
        action: 'unsubscribe',
        target_list_ids: [listId],
      }),
    });
    if (resp.ok) return { success: true };
    // 401/403 (insufficient permission), 404 and 5xx are all real failures: the
    // subscriber must not be told they are removed while Listmonk still has them.
    const body = await resp.text();
    console.error(`Listmonk unsubscribe failed for ${redactEmail(email)}: HTTP ${resp.status}`);
    const detail = resp.status === 404
      ? 'route or subscriber not found'
      : `Listmonk unsubscribe HTTP ${resp.status}: ${body.slice(0, 120)}`;
    return { success: false, error: detail };
  } catch (err) {
    console.error(`Listmonk unsubscribe exception for ${redactEmail(email)}`);
    return { success: false, error: `Listmonk unsubscribe exception: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function getLatestNewsletterUrl(env: Env): Promise<string | null> {
  try {
    if (env.R2_BUCKET) {
      const newsletters = await listNewslettersFromR2(env.R2_BUCKET);
      if (newsletters.length > 0) return newsletters[0].url;
    }
  } catch (err) {
    console.error(`getLatestNewsletterUrl R2 error: ${err instanceof Error ? err.message : String(err)}`);
  }
  return null;
}

async function sendListmonkWelcome(email: string, env: Env): Promise<{ success: boolean; error?: string }> {
  if (!isListmonkConfigured(env) || !env.LISTMONK_WELCOME_TEMPLATE_ID) {
    return { success: false, error: 'Listmonk welcome template not configured' };
  }
  try {
    const templateId = parseInt(env.LISTMONK_WELCOME_TEMPLATE_ID, 10);
    const latestUrl = await getLatestNewsletterUrl(env);
    const data: Record<string, string> = {};
    if (latestUrl) data.latest_newsletter_url = latestUrl;

    const resp = await callListmonk(env, '/api/tx', {
      method: 'POST',
      body: JSON.stringify({
        subscriber_email: email,
        template_id: templateId,
        data,
        messenger: 'email',
      }),
    });
    if (resp.ok) return { success: true };
    const body = await resp.text();
    return { success: false, error: `Listmonk tx HTTP ${resp.status}: ${body.slice(0, 200)}` };
  } catch (err) {
    return { success: false, error: `Listmonk tx exception: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/* =============================================================================
 * Plunk direct API — automatic fallback if Listmonk path fails OR if Listmonk
 * is intentionally disabled (LISTMONK_* secrets removed). Sends the legacy
 * hardcoded welcome email. Not used during normal operation.
 * ========================================================================== */

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function requireAuth(request: Request, env: Env): boolean {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const expectedToken = env.ADMIN_TOKEN;
  if (!expectedToken) return false;
  return timingSafeEqual(token, expectedToken);
}

async function sendPlunkWelcomeFallback(subscriberEmail: string, env: Env): Promise<{ success: boolean; error?: string }> {
  if (!env.PLUNK_SECRET_KEY) {
    return { success: false, error: 'PLUNK_SECRET_KEY not configured' };
  }

  // Every email carries a subscriber-bound one-click unsubscribe link to match
  // the privacy notice ("every newsletter email has an unsubscribe link, removal
  // is immediate").  Without the signing secret the link cannot be produced, so
  // the previous reply-to fallback remains.
  const token = await signUnsubscribeToken(subscriberEmail, env);
  const unsubscribeHtml = token
    ? `If you no longer wish to receive this newsletter, <a href="${unsubscribeUrl(subscriberEmail, token, env)}">unsubscribe here</a>.`
    : 'To unsubscribe, simply reply to this email.';

  // Plunk generates the plain-text alternative from `body`.
  const emailPayload = {
    from: { name: 'Philipp D. Dubach - AI & Markets', email: 'newsletter@m.philippdubach.com' },
    to: subscriberEmail,
    reply: 'hi@philippdubach.com',
    subject: 'Welcome to the Newsletter',
    body: `
      <p>Thanks for subscribing!</p>
      <p>You'll receive the next newsletter in your inbox. In the meantime, you can <a href="https://philippdubach.com/newsletter-archive/">browse the archive</a>.</p>
      <p style="color: #666; font-size: 0.9em; margin-top: 2em;">${unsubscribeHtml}</p>
    `,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch('https://next-api.useplunk.com/v1/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.PLUNK_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailPayload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const responseText = await response.text();
    if (!response.ok) return { success: false, error: `Plunk HTTP ${response.status}: ${responseText.slice(0, 200)}` };
    return { success: true };
  } catch (error) {
    clearTimeout(timeoutId);
    return { success: false, error: `Plunk exception: ${error instanceof Error ? error.message : String(error)}` };
  }
}

/* ========================================================================== */

async function handleSubscribe(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    // Cheap declared-length rejection before spending rate-limit budget; the
    // streamed body itself is bounded later in readBody.
    const declaredLength = request.headers.get('Content-Length');
    if (declaredLength && parseInt(declaredLength, 10) > MAX_REQUEST_SIZE) {
      return jsonResponse({ success: false, error: 'Request too large' }, 413, request, env);
    }
    const clientIP = getClientIP(request);
    if (!await checkRateLimit(clientIP, env)) {
      return jsonResponse({ success: false, error: 'Too many requests. Please try again later.' }, 429, request, env);
    }

    const parsed = await readBody(request);
    if (!parsed.ok) {
      return jsonResponse({ success: false, error: parsed.error }, parsed.status, request, env);
    }
    const body = parsed.body;

    if (body.honeypot) {
      return jsonResponse({ success: false, error: 'Invalid request' }, 400, request, env);
    }

    const email = (body.email || '').trim().toLowerCase();

    if (!isValidEmail(email)) {
      return jsonResponse({ success: false, error: 'Invalid email address' }, 400, request, env);
    }

    // Idempotency: check KV first for fast path on duplicates
    const existing = await env.NEWSLETTER_SUBSCRIBERS.get(email);
    if (existing) {
      // Make sure Listmonk has them too in case prior write failed
      ctx.waitUntil((async () => {
        await createListmonkSubscriber(email, clientIP, env);
      })());
      return jsonResponse({ success: true, message: 'Already subscribed' }, 200, request, env);
    }

    // Dual-write: both stores see the new subscriber.
    // KV write is fast and synchronous; Listmonk write + welcome happen in waitUntil.
    const subscriptionData = {
      timestamp: new Date().toISOString(),
      ip: clientIP,
      userAgent: request.headers.get('User-Agent') || 'unknown',
    };
    await env.NEWSLETTER_SUBSCRIBERS.put(email, JSON.stringify(subscriptionData));

    ctx.waitUntil((async () => {
      // PRIMARY: Listmonk (subscriber + welcome via /api/tx with thanks.html template)
      const created = await createListmonkSubscriber(email, clientIP, env);
      if (created.success) {
        const sent = await sendListmonkWelcome(email, env);
        if (sent.success) return;
        console.error(`Listmonk welcome send failed for ${redactEmail(email)}: ${sent.error} — using Plunk fallback`);
      } else {
        console.error(`Listmonk subscribe failed for ${redactEmail(email)}: ${created.error} — using Plunk fallback`);
      }
      // FALLBACK: direct Plunk API with legacy hardcoded welcome email
      const fallback = await sendPlunkWelcomeFallback(email, env);
      if (!fallback.success) {
        console.error(`Plunk fallback also failed for ${redactEmail(email)}: ${fallback.error}`);
      }
    })());

    return jsonResponse({ success: true, message: 'Subscribed successfully' }, 200, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

async function handleUnsubscribe(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    const declaredLength = request.headers.get('Content-Length');
    if (declaredLength && parseInt(declaredLength, 10) > MAX_REQUEST_SIZE) {
      return jsonResponse({ success: false, error: 'Request too large' }, 413, request, env);
    }
    const parsed = await readBody(request);
    if (!parsed.ok) {
      return jsonResponse({ success: false, error: parsed.error }, parsed.status, request, env);
    }

    const email = (parsed.body.email || '').trim().toLowerCase();
    if (!isValidEmail(email)) {
      return jsonResponse({ success: false, error: 'Invalid email address' }, 400, request, env);
    }

    // Proof of control: an operator bearer token, or a subscriber-bound signed
    // token covering the exact email address.  An unauthenticated email-only
    // request must not remove another subscriber (audit item 33).
    const operatorAuthed = requireAuth(request, env);
    const tokenValid = await verifyUnsubscribeToken(email, parsed.body.token, env);
    if (!operatorAuthed && !tokenValid) {
      return jsonResponse({ success: false, error: 'Invalid or missing unsubscribe token' }, 403, request, env);
    }

    // Durable intent first: remove the KV dual-write entry synchronously.
    await env.NEWSLETTER_SUBSCRIBERS.delete(email);

    // The Listmonk removal is awaited so the acknowledgement reflects reality;
    // it is idempotent, so a failed attempt can be retried safely.
    const result = await unsubscribeFromListmonk(email, env);
    if (!result.success) {
      return jsonResponse({ success: false, error: 'Unsubscribe failed; please try again later' }, 502, request, env);
    }

    return jsonResponse({ success: true, message: 'Unsubscribed successfully' }, 200, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

async function handleGetNewsletters(request: Request, env: Env): Promise<Response> {
  try {
    if (env.R2_BUCKET) {
      try {
        const newsletters = await listNewslettersFromR2(env.R2_BUCKET);
        if (newsletters.length > 0) {
          return jsonResponse({ newsletters }, 200, request, env);
        }
      } catch {
        // fall through
      }
    }

    try {
      const response = await fetch('https://static.philippdubach.com/newsletter/');
      if (response.ok) {
        const html = await response.text();
        const newsletters = parseNewsletterDirectory(html);
        if (newsletters.length > 0) {
          return jsonResponse({ newsletters }, 200, request, env);
        }
      }
    } catch {
      // fall through
    }

    const fallbackNewsletters: NewsletterItem[] = [
      {
        filename: 'newsletter-2025-12.html',
        date: 'December 2025',
        title: 'December 2025 Newsletter',
        url: 'https://static.philippdubach.com/newsletter/newsletter-2025-12.html',
      },
    ];
    return jsonResponse({ newsletters: fallbackNewsletters }, 200, request, env);
  } catch {
    const fallbackNewsletters: NewsletterItem[] = [
      {
        filename: 'newsletter-2025-12.html',
        date: 'December 2025',
        title: 'December 2025 Newsletter',
        url: 'https://static.philippdubach.com/newsletter/newsletter-2025-12.html',
      },
    ];
    return jsonResponse({ newsletters: fallbackNewsletters }, 200, request, env);
  }
}

async function listNewslettersFromR2(bucket: R2Bucket): Promise<NewsletterItem[]> {
  const newsletters: NewsletterItem[] = [];
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];

  const objects = await bucket.list({ prefix: 'newsletter/' });

  for (const object of objects.objects) {
    const key = object.key;
    const filename = key.split('/').pop() || key;
    const match = filename.match(/newsletter-(\d{4})-(\d{2})\.html/);
    if (!match) continue;
    const year = match[1];
    const month = match[2];
    const monthIndex = parseInt(month, 10) - 1;
    if (monthIndex < 0 || monthIndex > 11) continue;
    const date = `${monthNames[monthIndex]} ${year}`;
    const title = `${monthNames[monthIndex]} ${year} Newsletter`;
    newsletters.push({
      filename,
      date,
      title,
      url: `https://static.philippdubach.com/newsletter/${filename}`,
    });
  }

  newsletters.sort((a, b) => {
    const aMatch = a.filename.match(/newsletter-(\d{4})-(\d{2})/);
    const bMatch = b.filename.match(/newsletter-(\d{4})-(\d{2})/);
    if (!aMatch || !bMatch) return 0;
    return (bMatch[1] + bMatch[2]).localeCompare(aMatch[1] + aMatch[2]);
  });

  return newsletters;
}

function parseNewsletterDirectory(html: string): NewsletterItem[] {
  const newsletters: NewsletterItem[] = [];
  const linkRegex = /<a[^>]+href=["']([^"']*newsletter-(\d{4})-(\d{2})\.html)["'][^>]*>([^<]*)<\/a>/gi;
  let match;
  const seen = new Set<string>();

  while ((match = linkRegex.exec(html)) !== null) {
    const filename = match[1];
    const year = match[2];
    const month = match[3];
    const linkText = match[4].trim();
    if (seen.has(filename)) continue;
    seen.add(filename);
    const monthNames = [
      'January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December',
    ];
    const monthIndex = parseInt(month, 10) - 1;
    const date = `${monthNames[monthIndex]} ${year}`;
    const title = linkText || `${monthNames[monthIndex]} ${year} Newsletter`;
    newsletters.push({
      filename,
      date,
      title,
      url: `https://static.philippdubach.com/newsletter/${filename}`,
    });
  }

  newsletters.sort((a, b) => {
    const aMatch = a.filename.match(/newsletter-(\d{4})-(\d{2})/);
    const bMatch = b.filename.match(/newsletter-(\d{4})-(\d{2})/);
    if (!aMatch || !bMatch) return 0;
    return (bMatch[1] + bMatch[2]).localeCompare(aMatch[1] + aMatch[2]);
  });

  return newsletters;
}

const COMBINED_COUNT_CACHE_KEY = 'cache:subscriber_count';
const LINKEDIN_LAST_KNOWN_PREFIX = 'cache:linkedin_last_known:';
const COMBINED_COUNT_CACHE_TTL = 600;

function linkedInLastKnownKey(url: string): string {
  let hash = 0;
  for (let i = 0; i < url.length; i++) {
    hash = ((hash << 5) - hash + url.charCodeAt(i)) | 0;
  }
  return LINKEDIN_LAST_KNOWN_PREFIX + (hash >>> 0).toString(36);
}

async function fetchOneLinkedInFollowers(url: string, env: Env, ctx: ExecutionContext): Promise<number> {
  const cacheKey = linkedInLastKnownKey(url);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const html = await response.text();
    const match = html.match(/([0-9,]+)\s+followers/);
    if (!match) throw new Error('parse miss');
    const count = parseInt(match[1].replace(/,/g, ''), 10);
    if (!count) throw new Error('parsed zero');
    ctx.waitUntil(env.NEWSLETTER_SUBSCRIBERS.put(cacheKey, String(count)));
    return count;
  } catch {
    clearTimeout(timeoutId);
    const lastKnown = await env.NEWSLETTER_SUBSCRIBERS.get(cacheKey);
    return lastKnown ? parseInt(lastKnown, 10) || 0 : 0;
  }
}

async function fetchListmonkSubscriberCount(env: Env): Promise<number | null> {
  if (!isListmonkConfigured(env)) return null;
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    // Per-list filter via /api/subscribers?list_id=… avoids the JOIN double-count
    // bug in /api/lists/{id}.subscriber_count. per_page=1 keeps the response tiny;
    // we only read data.total.
    const resp = await callListmonk(env, `/api/subscribers?list_id=${listId}&per_page=1`, { method: 'GET' });
    if (!resp.ok) return null;
    const body = await resp.json() as { data?: { total?: number } };
    const total = body?.data?.total;
    return typeof total === 'number' ? total : null;
  } catch {
    return null;
  }
}

async function fetchLinkedInFollowers(env: Env, ctx: ExecutionContext): Promise<number> {
  const raw = env.LINKEDIN_NEWSLETTER_URLS;
  if (!raw) return 0;
  const urls = raw.split(',').map(u => u.trim()).filter(Boolean);
  if (urls.length === 0) return 0;
  const counts = await Promise.all(urls.map(url => fetchOneLinkedInFollowers(url, env, ctx)));
  return counts.reduce((sum, n) => sum + n, 0);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return handleOptions(request, env);

    if (path === '/api/subscribe' && request.method === 'POST') {
      return handleSubscribe(request, env, ctx);
    }

    if (path === '/api/unsubscribe' && request.method === 'POST') {
      return handleUnsubscribe(request, env, ctx);
    }

    // One-click unsubscribe from emails: the request carries the signed token,
    // so it is a benign, non-navigational side effect for the token holder.
    if (path === '/api/unsubscribe' && request.method === 'GET') {
      const email = (url.searchParams.get('email') || '').trim().toLowerCase();
      const token = url.searchParams.get('token') || undefined;
      if (!isValidEmail(email) || !(await verifyUnsubscribeToken(email, token, env))) {
        return htmlResponse('<h1>Unsubscribe link invalid or expired</h1><p>Please contact us and we will remove you manually.</p>', 403, request, env);
      }
      await env.NEWSLETTER_SUBSCRIBERS.delete(email);
      const result = await unsubscribeFromListmonk(email, env);
      return htmlResponse(
        result.success
          ? '<h1>You have been unsubscribed</h1><p>You will no longer receive the newsletter.</p>'
          : '<h1>Could not complete unsubscribe</h1><p>Please try again later.</p>',
        result.success ? 200 : 502,
        request,
        env,
      );
    }

    if (path === '/api/newsletters' && request.method === 'GET') {
      return handleGetNewsletters(request, env);
    }

    if (path === '/api/subscriber-count' && request.method === 'GET') {
      try {
        const cached = await env.NEWSLETTER_SUBSCRIBERS.get(COMBINED_COUNT_CACHE_KEY);
        if (cached) {
          return jsonResponse(JSON.parse(cached), 200, request, env);
        }

        // Listmonk is the source of truth; KV count is the dual-write fallback
        // for the period before Listmonk is solo (and a safety net if Listmonk
        // is unreachable). Run both in parallel and prefer Listmonk's number.
        const kvCountPromise = (async () => {
          let count = 0;
          let cursor: string | undefined;
          do {
            const result = await env.NEWSLETTER_SUBSCRIBERS.list({ cursor, limit: 1000 });
            count += result.keys.filter(key =>
              !key.name.startsWith('rate_limit:') && !key.name.startsWith('cache:')
            ).length;
            cursor = result.list_complete ? undefined : result.cursor;
          } while (cursor);
          return count;
        })();

        const [listmonkCount, kvCount, linkedInCount] = await Promise.all([
          fetchListmonkSubscriberCount(env),
          kvCountPromise,
          fetchLinkedInFollowers(env, ctx),
        ]);

        const subscriberCount = listmonkCount ?? kvCount;
        const total = subscriberCount + linkedInCount;
        const displayCount = Math.ceil(total / 10) * 10;
        const payload = { count: displayCount, display: `${displayCount}+` };

        ctx.waitUntil(
          env.NEWSLETTER_SUBSCRIBERS.put(
            COMBINED_COUNT_CACHE_KEY,
            JSON.stringify(payload),
            { expirationTtl: COMBINED_COUNT_CACHE_TTL }
          )
        );

        return jsonResponse(payload, 200, request, env);
      } catch {
        return jsonResponse({ count: 0, display: '0+' }, 200, request, env);
      }
    }

    if (path === '/api/health' && request.method === 'GET') {
      return jsonResponse({ status: 'ok', timestamp: new Date().toISOString() }, 200, request, env);
    }

    // Test the Plunk fallback path.  Fail closed: refuses when the environment
    // identity is missing or unknown, and requires operator auth in every
    // environment (a development deploy must not send mail unauthenticated).
    if (path === '/api/test-email' && request.method === 'POST') {
      if (env.ENVIRONMENT !== 'production' && env.ENVIRONMENT !== 'development') {
        return jsonResponse({ error: 'Test email route not configured for this environment' }, 503, request, env);
      }
      if (!requireAuth(request, env)) {
        return jsonResponse({ error: 'Unauthorized' }, 401, request, env);
      }
      try {
        const parsed = await readBody(request);
        if (!parsed.ok) {
          return jsonResponse({ success: false, error: parsed.error }, parsed.status, request, env);
        }
        const testEmail = (parsed.body.email || '').trim().toLowerCase() || 'test@example.com';
        if (!isValidEmail(testEmail)) {
          return jsonResponse({ success: false, error: 'Invalid email' }, 400, request, env);
        }
        const result = await sendPlunkWelcomeFallback(testEmail, env);
        if (result.success) {
          return jsonResponse({ success: true, message: 'Test email sent' }, 200, request, env);
        }
        // Surface a generic error to the caller; the provider detail is for logs.
        console.error(`Test email failed for ${redactEmail(testEmail)}: ${result.error}`);
        return jsonResponse({ success: false, error: 'Test email sending failed' }, 500, request, env);
      } catch {
        console.error('Test email exception');
        return jsonResponse({ success: false, error: 'Test email sending failed' }, 500, request, env);
      }
    }

    return jsonResponse({ error: 'Not found' }, 404, request, env);
  },
};
