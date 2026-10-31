export interface Env {
  NEWSLETTER_SUBSCRIBERS: KVNamespace; // dual-write target + rate limit + caches
  // Optional so environments without the migration still run; the coordinator is
  // the production path and serializes writes per address.
  SUBSCRIPTION_COORDINATOR?: DurableObjectNamespace;
  // 'on' routes writes through the coordinator. 'legacy' uses the unserialized
  // inline path while keeping the binding and every pending operation intact,
  // which is what makes a rollback possible without crossing a class creation.
  COORDINATOR_MODE?: string;
  // Overall budget for one provider phase, in milliseconds. Must stay well under
  // the 30-second limit after which a Durable Object is reset.
  PROVIDER_BUDGET_MS?: string;
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
// URL-encoding a 320-character address plus its signed token can exceed 1 KB.
const MAX_UNSUBSCRIBE_REQUEST_SIZE = 2048;
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
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
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
 * Read and validate a POST body with a genuine bounded-byte stream parser.
 *
 * Accepts JSON and URL-encoded form bodies (the blog's no-JavaScript native
 * form sends the latter), and rejects malformed input as a client error rather
 * than a 500.  The body is read incrementally from the request stream with a
 * byte limit enforced during streaming (1 KB by default). Invalid raw UTF-8,
 * malformed or misleading Content-Length, and non-string fields are rejected.
 */
export async function readBody(request: Request, maxBytes = MAX_REQUEST_SIZE): Promise<BodyResult> {
  const declared = request.headers.get('Content-Length');
  if (declared !== null) {
    if (!/^[0-9]+$/.test(declared)) {
      return { ok: false, status: 400, error: 'Invalid Content-Length' };
    }
    const declaredLength = Number(declared);
    if (!Number.isSafeInteger(declaredLength)) {
      return { ok: false, status: 400, error: 'Invalid Content-Length' };
    }
    if (declaredLength > maxBytes) {
      return { ok: false, status: 413, error: 'Request too large' };
    }
  }

  const body = request.body;
  if (!body) {
    return { ok: false, status: 400, error: 'Invalid request body' };
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.length;
      if (totalBytes > maxBytes) {
        // Do not wait indefinitely for an untrusted stream to finish cancelling.
        void reader.cancel().catch(() => {});
        return { ok: false, status: 413, error: 'Request too large' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, status: 400, error: 'Invalid request body' };
  } finally {
    reader.releaseLock();
  }

  // Validate Content-Length against actual bytes read (catches misleading headers).
  if (declared !== null) {
    const declaredLength = Number(declared);
    if (declaredLength !== totalBytes) {
      return { ok: false, status: 400, error: 'Content-Length mismatch' };
    }
  }

  // Decode the accumulated bytes as UTF-8, rejecting overlong sequences.
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  let text: string;
  try {
    const combined = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    text = decoder.decode(combined);
  } catch {
    return { ok: false, status: 400, error: 'Invalid request body' };
  }

  const rawType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  const jsonLike = !rawType || rawType === 'application/json' || rawType === 'text/plain';
  if (jsonLike) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return { ok: false, status: 400, error: 'Invalid request body' };
      }
      // Reject non-string email/token/honeypot fields instead of letting them
      // propagate and potentially cause a 500 downstream.
      const body = parsed as Record<string, unknown>;
      for (const key of ['email', 'token', 'honeypot']) {
        if (key in body && body[key] !== undefined && typeof body[key] !== 'string') {
          return { ok: false, status: 400, error: 'Invalid request body' };
        }
      }
      return { ok: true, body: parsed as ParsedBody };
    } catch {
      // Explicit JSON must never be reinterpreted as a form. Preserve the
      // existing text/plain/no-type compatibility for older clients.
      if (rawType === 'application/json') {
        return { ok: false, status: 400, error: 'Invalid request body' };
      }
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

interface SubscriptionRecord {
  timestamp: string;
  ip: string;
  userAgent: string;
  // Best-effort intent marker. KV is eventually consistent and this value
  // cannot serialize in-flight Listmonk writes with unsubscribe requests.
  seq: number;
}

async function readRecord(email: string, env: Env): Promise<SubscriptionRecord | null> {
  try {
    const raw = await env.NEWSLETTER_SUBSCRIBERS.get(email);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SubscriptionRecord>;
    return {
      timestamp: typeof parsed.timestamp === 'string' ? parsed.timestamp : '',
      ip: typeof parsed.ip === 'string' ? parsed.ip : 'unknown',
      userAgent: typeof parsed.userAgent === 'string' ? parsed.userAgent : 'unknown',
      seq: typeof parsed.seq === 'number' ? parsed.seq : 0,
    };
  } catch {
    return null;
  }
}

/** True only while the address's record is still exactly this intent version. */
async function intentStillCurrent(email: string, seq: number, env: Env): Promise<boolean> {
  const record = await readRecord(email, env);
  return record !== null && record.seq === seq;
}

/**
 * Best-effort signup reconciliation. Intent checks can suppress some stale
 * work, but cannot cancel a Listmonk request already in flight or guarantee
 * ordering across KV and Listmonk. That race requires a durable coordinator.
 */
export async function reconcileSignup(
  email: string,
  seq: number,
  clientIP: string,
  env: Env,
  options: { welcome: boolean } = { welcome: true },
): Promise<void> {
  if (!(await intentStillCurrent(email, seq, env))) return; // superseded (e.g. unsubscribed)

  // PRIMARY: Listmonk (subscriber + welcome via /api/tx with thanks template).
  const created = await createListmonkSubscriber(email, clientIP, env);

  if (!(await intentStillCurrent(email, seq, env))) return; // intent changed mid-flight

  if (created.success && created.duplicate) {
    // Already registered in Listmonk.  Do NOT reactivate it: a blocklisted or
    // unsubscribed Listmonk subscriber must not be silently re-enabled.
  } else if (created.success) {
    if (options.welcome) {
      const sent = await sendListmonkWelcome(email, env);
      if (!sent.success) {
        console.error(`Listmonk welcome send failed for ${redactEmail(email)}: ${sent.error} — using Plunk fallback`);
        await sendFallbackWelcome(email, env);
      }
    }
  } else {
    console.error(`Listmonk subscribe failed for ${redactEmail(email)}: ${created.error} — using Plunk fallback`);
    if (options.welcome) await sendFallbackWelcome(email, env);
  }

  // Do not write a status back to KV here: a check-then-put can resurrect a
  // record deleted by an overlapping unsubscribe. This does not fix the
  // separate in-flight Listmonk ordering race described above.
}

async function sendFallbackWelcome(email: string, env: Env, deadline?: AbortSignal): Promise<void> {
  const fallback = await sendPlunkWelcomeFallback(email, env, deadline);
  if (!fallback.success) {
    console.error(`Plunk fallback also failed for ${redactEmail(email)}: ${fallback.error}`);
  }
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

/**
 * Combines an optional caller deadline with a per-call one. The shorter wins,
 * which is what keeps a sequence of provider calls inside one overall budget.
 */
function combineSignals(own: AbortSignal, external?: AbortSignal | null): AbortSignal {
  if (!external) return own;
  const anySignal = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  if (typeof anySignal === 'function') return anySignal([own, external]);
  // Fallback for runtimes without AbortSignal.any.
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (own.aborted || external.aborted) controller.abort();
  own.addEventListener('abort', abort, { once: true });
  external.addEventListener('abort', abort, { once: true });
  return controller.signal;
}

/**
 * Resolves with `fallback` if the deadline fires first. Used for work that cannot
 * take an AbortSignal itself, so it cannot extend a budgeted phase.
 */
function raceDeadline<T>(work: Promise<T>, deadline: AbortSignal | undefined, fallback: T): Promise<T> {
  if (!deadline) return work;
  if (deadline.aborted) return Promise.resolve(fallback);
  return new Promise<T>((resolve) => {
    const finish = (value: T) => {
      deadline.removeEventListener('abort', onAbort);
      resolve(value);
    };
    const onAbort = () => resolve(fallback);
    deadline.addEventListener('abort', onAbort, { once: true });
    work.then(finish).catch(() => finish(fallback));
  });
}

function isListmonkConfigured(env: Env): boolean {
  return Boolean(env.LISTMONK_API_URL && env.LISTMONK_API_USER && env.LISTMONK_API_TOKEN && env.LISTMONK_LIST_ID);
}

// What the provider says about an address, as far as this Worker can establish.
// 'unverified' means the question could not be answered, which is not the same
// as the address being absent.
type UpstreamState = 'confirmed' | 'unsubscribed' | 'blocklisted' | 'pending' | 'absent' | 'unverified';

/**
 * Calls Listmonk and parses the body while the request deadline is still armed.
 *
 * `callListmonk` clears its timeout when the headers arrive, so a provider that
 * sends headers promptly and then stalls the body would never be aborted. Any
 * caller that needs the body should use this instead.
 */
async function callListmonkJson(
  env: Env,
  path: string,
  init: RequestInit = {},
): Promise<{ ok: boolean; status: number; body: unknown }> {
  const auth = btoa(`${env.LISTMONK_API_USER}:${env.LISTMONK_API_TOKEN}`);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  // Keep the deadline armed through body parsing, and honour a caller's budget.
  const signal = combineSignals(controller.signal, init.signal);
  try {
    const resp = await fetch(`${env.LISTMONK_API_URL}${path}`, {
      ...init,
      signal,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        ...(init.headers || {}),
      },
    });
    // Body parsing happens before the deadline is cleared, so an abort during the
    // body also aborts the read.
    const body = await resp.json().catch(() => null);
    return { ok: resp.ok, status: resp.status, body };
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Reads the provider's current state for one address.
 *
 * A KV record is not evidence that the provider still holds a subscription:
 * Listmonk's own unsubscribe links change that state without this Worker being
 * involved, and the read-only inventory found live cases where the two stores
 * disagreed. So the write path asks before it answers.
 *
 * The answer is only trusted when it is internally consistent: the reported
 * count must be exactly zero or one and must agree with the rows, and the row
 * must carry the exact address that was asked for. A response that contradicts
 * itself is 'unverified', never 'absent', because treating it as absence
 * re-creates a subscriber who deliberately left.
 *
 * `reason` names the cause so an unexplained 'unverified' in production can be
 * diagnosed from the response plus one log line, instead of being invisible.
 */
async function lookupListmonkSubscriber(
  email: string,
  env: Env,
  deadline?: AbortSignal,
): Promise<{ state: UpstreamState; reason: string }> {
  const answered = await lookupListmonkSubscriberRaw(email, env, deadline);
  if (answered.state === 'unverified') {
    // Deliberately a warning: this is the only signal that the check failed,
    // and it must be visible in tail rather than silently returning 200.
    console.warn(`listmonk lookup unverified for ${redactEmail(email)}: ${answered.reason}`);
  }
  return answered;
}

async function lookupListmonkSubscriberRaw(
  email: string,
  env: Env,
  deadline?: AbortSignal,
): Promise<{ state: UpstreamState; reason: string }> {
  if (!isListmonkConfigured(env)) return { state: 'unverified', reason: 'not_configured' };
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    const safeEmail = email.replace(/'/g, "''");
    const query = encodeURIComponent(`subscribers.email = '${safeEmail}'`);
    const resp = await callListmonkJson(env, `/api/subscribers?query=${query}&per_page=1`, { method: 'GET', signal: deadline });
    if (!resp.ok) return { state: 'unverified', reason: `http_${resp.status}` };

    const data = (resp.body as { data?: { results?: unknown; total?: unknown } })?.data;
    const results = data?.results;
    const total = data?.total;
    if (!Array.isArray(results)) return { state: 'unverified', reason: 'no_results_array' };
    // A strict comparison against {0, 1} rather than a `> 1` bound: negative and
    // fractional values are equally uninterpretable, and a range check would let
    // them through to the length tests below.
    if (total !== 0 && total !== 1) return { state: 'unverified', reason: `total_not_zero_or_one:${String(total)}` };
    if (total === 1 && results.length !== 1) return { state: 'unverified', reason: 'count_exceeds_rows' };
    if (total === 0 && results.length !== 0) return { state: 'unverified', reason: 'rows_exceed_count' };
    if (total === 0) return { state: 'absent', reason: 'no_match' };

    const subscriber = results[0] as { email?: unknown; status?: unknown; lists?: unknown };
    const returnedEmail = typeof subscriber?.email === 'string' ? subscriber.email.trim().toLowerCase() : null;
    if (returnedEmail !== email.trim().toLowerCase()) return { state: 'unverified', reason: 'identity_mismatch' };

    if (subscriber?.status === 'blocklisted') return { state: 'blocklisted', reason: 'global_blocklisted' };
    // Confirmation requires an explicitly enabled global subscriber. A missing,
    // disabled or unrecognised global status cannot support "Already subscribed",
    // even when a list entry says confirmed.
    if (subscriber?.status !== 'enabled') return { state: 'unverified', reason: `global_status_${String(subscriber?.status)}` };

    if (!Array.isArray(subscriber?.lists)) return { state: 'unverified', reason: 'no_lists_array' };
    const entry = subscriber.lists.find((candidate) => Number((candidate as { id?: unknown })?.id) === listId) as
      { subscription_status?: unknown } | undefined;
    if (!entry) return { state: 'unverified', reason: 'no_entry_for_target_list' };
    if (entry.subscription_status === 'confirmed') return { state: 'confirmed', reason: 'list_confirmed' };
    if (entry.subscription_status === 'unsubscribed') return { state: 'unsubscribed', reason: 'list_unsubscribed' };
    if (entry.subscription_status === 'unconfirmed') return { state: 'pending', reason: 'list_unconfirmed' };
    return { state: 'unverified', reason: `list_status_${String(entry.subscription_status)}` };
  } catch (error) {
    return { state: 'unverified', reason: `exception:${error instanceof Error ? error.message : String(error)}` };
  }
}

async function callListmonk(env: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const auth = btoa(`${env.LISTMONK_API_USER}:${env.LISTMONK_API_TOKEN}`);
  const url = `${env.LISTMONK_API_URL}${path}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  const signal = combineSignals(controller.signal, init.signal);

  try {
    const resp = await fetch(url, {
      ...init,
      signal,
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

async function createListmonkSubscriber(email: string, clientIP: string, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; duplicate?: boolean; error?: string }> {
  if (!isListmonkConfigured(env)) {
    return { success: false, error: 'Listmonk not configured' };
  }
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    const resp = await callListmonk(env, '/api/subscribers', {
      method: 'POST',
      signal: deadline,
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
    // Only a documented 409 Conflict counts as "already a subscriber".  A 5xx
    // (or any other status) whose body merely contains the word "duplicate"
    // must NOT be treated as success (audit item 35).
    if (resp.status === 409) return { success: true, duplicate: true };
    const body = await resp.text();
    return { success: false, error: `Listmonk subscribe HTTP ${resp.status}: ${body.slice(0, 200)}` };
  } catch (err) {
    return { success: false, error: `Listmonk subscribe exception: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function unsubscribeFromListmonk(email: string, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; error?: string }> {
  // Missing configuration does not prove that Listmonk has no existing
  // subscription. Fail closed rather than falsely acknowledging removal.
  if (!isListmonkConfigured(env)) {
    return { success: false, error: 'Listmonk not configured' };
  }
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    const safeEmail = email.replace(/'/g, "''");
    // Documented Listmonk route is plural (PUT /api/subscribers/query/lists);
    // the singular path used earlier is not a registered alias.
    const resp = await callListmonk(env, '/api/subscribers/query/lists', {
      method: 'PUT',
      signal: deadline,
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

async function sendListmonkWelcome(email: string, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; error?: string }> {
  if (!isListmonkConfigured(env) || !env.LISTMONK_WELCOME_TEMPLATE_ID) {
    return { success: false, error: 'Listmonk welcome template not configured' };
  }
  try {
    const templateId = parseInt(env.LISTMONK_WELCOME_TEMPLATE_ID, 10);
    // The R2 listing has no abort signal of its own, so it races the deadline and
    // degrades to "no link" rather than extending the phase.
    const latestUrl = await raceDeadline(getLatestNewsletterUrl(env), deadline, null);
    const data: Record<string, string> = {};
    if (latestUrl) data.latest_newsletter_url = latestUrl;

    const resp = await callListmonk(env, '/api/tx', {
      method: 'POST',
      signal: deadline,
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

async function sendPlunkWelcomeFallback(subscriberEmail: string, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; error?: string }> {
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
  // The caller's budget must apply here too, and stay armed through the body.
  const signal = combineSignals(controller.signal, deadline);

  try {
    const response = await fetch('https://next-api.useplunk.com/v1/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.PLUNK_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailPayload),
      signal,
    });
    const responseText = await response.text();
    if (!response.ok) return { success: false, error: `Plunk HTTP ${response.status}: ${responseText.slice(0, 200)}` };
    return { success: true };
  } catch (error) {
    return { success: false, error: `Plunk exception: ${error instanceof Error ? error.message : String(error)}` };
  } finally {
    clearTimeout(timeoutId);
  }
}

/* ========================================================================== */

/* Coordinator plumbing ----------------------------------------------------- */

interface IntentResult {
  outcome: SyncOutcome;
  created?: boolean;
  seq?: number;
  attempts?: number;
  error?: string;
  reason?: string;
}

function isLegacyMode(env: Env): boolean {
  return (env.COORDINATOR_MODE ?? 'on') === 'legacy';
}

/** The stub regardless of mode, so legacy requests can still publish intent. */
function coordinatorStubFor(env: Env, email: string): DurableObjectStub | null {
  const namespace = env.SUBSCRIPTION_COORDINATOR;
  if (!namespace) return null;
  try {
    return namespace.get(namespace.idFromName(email.trim().toLowerCase()));
  } catch {
    return null;
  }
}

/**
 * Records a fence for a request that will change intent without this object
 * performing the work. Written before the provider call so a crash still leaves
 * evidence, and read by a retry to decide whether its own work is stale.
 */
async function publishFence(
  env: Env,
  email: string,
  desired: 'subscribed' | 'unsubscribed',
  authenticated: boolean,
): Promise<void> {
  try {
    await env.NEWSLETTER_SUBSCRIBERS.put(
      fenceKey(email),
      JSON.stringify({ desired, at: Date.now(), authenticated } satisfies IntentFence),
      { expirationTtl: 86400 },
    );
  } catch {
    // Best effort: the intent publish below is the primary channel.
  }
}

/**
 * Tells the coordinator what a legacy request did, so older durable work is
 * fenced by the newer intent. Best effort: the legacy path must keep working when
 * the object is unavailable, which is the situation it exists for.
 */
async function publishIntent(
  stub: DurableObjectStub | null,
  desired: 'subscribed' | 'unsubscribed',
  email: string,
  clientIP: string,
  request: Request,
  authenticated = false,
): Promise<IntentResult> {
  if (!stub) return { outcome: 'completed' };
  try {
    const response = await stub.fetch('https://coordinator/intent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        desired,
        email,
        ip: clientIP,
        userAgent: request.headers.get('User-Agent') || 'unknown',
        recordOnly: true,
        authenticated,
      }),
    });
    if (!response.ok) return { outcome: 'failed', error: `coordinator HTTP ${response.status}` };
    return await response.json() as IntentResult;
  } catch {
    // The object is unreachable, which is what the fence is for.
    return { outcome: 'failed', error: 'coordinator unreachable' };
  }
}

function coordinatorFor(env: Env, email: string): DurableObjectStub | null {
  // Rolling back across a Durable Object class creation is not permitted by
  // Cloudflare, so the supported rollback is a forward deploy that keeps the
  // binding and switches this mode. Pending operations and alarms stay live and
  // keep converging, because the class is never removed.
  if ((env.COORDINATOR_MODE ?? 'on') === 'legacy') return null;
  const namespace = env.SUBSCRIPTION_COORDINATOR;
  if (!namespace) return null;
  try {
    return namespace.get(namespace.idFromName(email.trim().toLowerCase()));
  } catch {
    // A malformed binding must not take signup down; fall back to inline.
    return null;
  }
}

async function submitIntent(
  coordinator: DurableObjectStub,
  desired: 'subscribed' | 'unsubscribed',
  email: string,
  clientIP: string,
  request: Request,
  authenticated = false,
): Promise<IntentResult> {
  try {
    const response = await coordinator.fetch('https://coordinator/intent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        desired,
        email,
        ip: clientIP,
        userAgent: request.headers.get('User-Agent') || 'unknown',
        authenticated,
      }),
    });
    if (!response.ok) return { outcome: 'failed', error: `coordinator HTTP ${response.status}` };
    return await response.json() as IntentResult;
  } catch (error) {
    return { outcome: 'failed', error: error instanceof Error ? error.message : String(error) };
  }
}

const TEXT_BLOCKLISTED = 'This address cannot be subscribed. Please contact us.';
const TEXT_UNSUBSCRIBED = 'This address is unsubscribed. Please contact us to resubscribe.';
// An unreadable provider establishes nothing about the subscription, so the
// wording must not claim the address is or is not on the list.
const TEXT_UNVERIFIED = "We couldn't verify your subscription. Please try again later or contact us.";
// Accepted but not finished: the intent is durable and retried by an alarm.
const TEXT_ACCEPTED_SUBSCRIBE = 'We received your request and will finish adding you shortly.';
const TEXT_ACCEPTED_UNSUBSCRIBE = 'We received your request and will finish removing you shortly. If you keep receiving newsletters, please contact us.';

function subscribeResponse(result: IntentResult, request: Request, env: Env): Response {
  switch (result.outcome) {
    case 'completed':
      return jsonResponse(
        { success: true, message: result.created ? 'Subscribed successfully' : 'Already subscribed' },
        200, request, env,
      );
    case 'blocklisted':
      return jsonResponse({ success: false, status: 'blocklisted', error: TEXT_BLOCKLISTED, message: TEXT_BLOCKLISTED }, 200, request, env);
    case 'unsubscribed':
      return jsonResponse({ success: false, status: 'unsubscribed', error: TEXT_UNSUBSCRIBED, message: TEXT_UNSUBSCRIBED }, 200, request, env);
    case 'unverified':
      return jsonResponse({ success: false, status: 'unverified', error: TEXT_UNVERIFIED, message: TEXT_UNVERIFIED }, 200, request, env);
    case 'pending':
    case 'superseded':
      return jsonResponse({ success: true, status: 'accepted', message: TEXT_ACCEPTED_SUBSCRIBE }, 202, request, env);
    default:
      return jsonResponse(
        { success: false, error: 'We could not complete your request. Please try again later.' },
        503, request, env,
      );
  }
}

function unsubscribeResponse(result: IntentResult, request: Request, env: Env): Response {
  switch (result.outcome) {
    case 'completed':
      // A provider 2xx is still not proof of final removal, so this keeps the
      // existing unverified contract rather than claiming success.
      return jsonResponse({
        success: false,
        status: 'unverified',
        message: 'A response was received, but removal could not be verified. If you receive another newsletter, please contact us.',
      }, 202, request, env);
    case 'pending':
    case 'superseded':
      return jsonResponse({ success: false, status: 'accepted', message: TEXT_ACCEPTED_UNSUBSCRIBE }, 202, request, env);
    default:
      return jsonResponse({ success: false, error: 'Unsubscribe failed; please try again later' }, 502, request, env);
  }
}

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

    // The coordinator is the production path: one serialized object per address,
    // so this request cannot interleave with a concurrent unsubscribe.
    const coordinator = coordinatorFor(env, email);
    if (coordinator) {
      const result = await submitIntent(coordinator, 'subscribed', email, clientIP, request, requireAuth(request, env));
      return subscribeResponse(result, request, env);
    }

    if (isLegacyMode(env)) {
      const authenticated = requireAuth(request, env);
      const published = await publishIntent(coordinatorStubFor(env, email), 'subscribed', email, clientIP, request, authenticated);
      // The object may refuse this because a removal is unresolved. A rejected
      // publish must stop the inline path, and must not leave a fence that would
      // let a later retry adopt what was just refused.
      if (published.outcome === 'unsubscribed') {
        return subscribeResponse(published, request, env);
      }
      await publishFence(env, email, 'subscribed', authenticated);
    }

    // Fallback for environments without the binding (unit tests, local runs
    // without migrations). Behaviour matches the pre-coordinator code, including
    // its inability to serialize concurrent requests; the runtime suite covers
    // the bound path.
    const existing = await env.NEWSLETTER_SUBSCRIBERS.get(email);
    if (existing) {
      const { state: upstream } = await lookupListmonkSubscriber(email, env);
      // Map the lookup's vocabulary onto the coordinator's outcome vocabulary.
      const outcome: SyncOutcome = upstream === 'confirmed'
        ? 'completed'
        : upstream === 'pending'
          ? 'unverified'
          : upstream === 'absent'
            ? 'pending'
            : upstream;

      // Absent upstream is the state a failed background write leaves behind. This
      // path must schedule its own recovery: the coordinator may be unreachable,
      // which is the reason it is being used.
      if (upstream === 'absent') {
        const record = await readRecord(email, env);
        ctx.waitUntil(reconcileSignup(email, record?.seq ?? 0, clientIP, env, { welcome: false }));
        return subscribeResponse({ outcome: 'pending', created: false }, request, env);
      }
      return subscribeResponse({ outcome, created: false }, request, env);
    }

    const record: SubscriptionRecord = {
      timestamp: new Date().toISOString(),
      ip: clientIP,
      userAgent: request.headers.get('User-Agent') || 'unknown',
      seq: Date.now(),
    };
    await env.NEWSLETTER_SUBSCRIBERS.put(email, JSON.stringify(record));
    ctx.waitUntil(reconcileSignup(email, record.seq, clientIP, env, { welcome: true }));
    return subscribeResponse({ outcome: 'completed', created: true }, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

async function handleUnsubscribe(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    const parsed = await readBody(request, MAX_UNSUBSCRIBE_REQUEST_SIZE);
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
    // The coordinator records the unsubscribe as a durable intent, so a signup
    // already in flight cannot quietly restore the subscription afterwards.
    const coordinator = coordinatorFor(env, email);
    if (coordinator) {
      const result = await submitIntent(coordinator, 'unsubscribed', email, getClientIP(request), request, true);
      return unsubscribeResponse(result, request, env);
    }

    if (isLegacyMode(env)) {
      // An unsubscribe is always authorized here: the token has been checked.
      await publishFence(env, email, 'unsubscribed', true);
      await publishIntent(coordinatorStubFor(env, email), 'unsubscribed', email, getClientIP(request), request, true);
    }

    if (!isListmonkConfigured(env)) {
      return jsonResponse({ success: false, error: 'Unsubscribe unavailable; please try again later' }, 502, request, env);
    }

    await env.NEWSLETTER_SUBSCRIBERS.delete(email);
    const result = await unsubscribeFromListmonk(email, env);
    if (!result.success) {
      return jsonResponse({ success: false, error: 'Unsubscribe failed; please try again later' }, 502, request, env);
    }
    return unsubscribeResponse({ outcome: 'completed' }, request, env);
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

/* ========================================================================== */
// Durable subscription coordinator
//
// Ties a subscribe and a later unsubscribe for the same address to one serialized
// object, so the two cannot interleave. The object holds the address's intent,
// the pending provider operation and its retry state; KV stays a read shadow but
// is no longer the authority on what was asked for.
//
// What this does and does not guarantee:
//   * It serializes this Worker's own writes per address. Two requests can no
//     longer race each other, which is what let both report success while the
//     stores disagreed.
//   * It cannot recall a provider request already in flight. That is why intent
//     is re-read after each provider call: if it changed, the result is reported
//     as superseded and the newer intent has its own handler.
//   * It cannot stop a native Listmonk unsubscribe, which is an independent
//     writer. Those are observed through the lookup and never overwritten.
//   * Retries survive eviction because they live in storage plus an alarm.

const INTENT_KEY = 'intent';
const PENDING_KEY = 'pending';
const WELCOME_KEY = 'welcome-seq';
const MAX_SYNC_ATTEMPTS = 8;
// The whole provider phase must finish well inside the 30-second limit after which
// a Durable Object is reset for holding blockConcurrencyWhile too long. Individual
// 10-second fetch timers do not bound the sequence, so one budget covers it all.
const DEFAULT_PROVIDER_BUDGET_MS = 20000;
const MIN_PROVIDER_BUDGET_MS = 1000;
const MAX_PROVIDER_BUDGET_MS = 25000;

function providerBudgetMs(env: Env): number {
  const configured = Number(env.PROVIDER_BUDGET_MS);
  if (!Number.isFinite(configured) || configured <= 0) return DEFAULT_PROVIDER_BUDGET_MS;
  return Math.min(Math.max(configured, MIN_PROVIDER_BUDGET_MS), MAX_PROVIDER_BUDGET_MS);
}

// One minute, backing off to an hour, bounded so a permanently broken provider
// does not spin.
function retryDelayMs(attempts: number): number {
  return Math.min(60_000 * Math.pow(4, Math.max(0, attempts - 1)), 60 * 60_000);
}

interface CoordinatorIntent {
  email: string;
  desired: 'subscribed' | 'unsubscribed';
  seq: number;
  updatedAt: string;
  /** Milliseconds, used only to order this intent against a legacy fence. */
  recordedAtMs: number;
  /** Caller metadata, kept here so a retry can repair the shadow correctly. */
  ip?: string;
  userAgent?: string;
  /** Whether the caller proved control of the address. */
  authenticated?: boolean;
}

/**
 * Written by a request that changed intent without reaching this object: the
 * legacy path, or a request whose publish failed. It is the only evidence of
 * supersession for work this object did not record itself.
 */
interface IntentFence {
  desired: 'subscribed' | 'unsubscribed';
  at: number;
  /** Whether the caller proved control of the address. */
  authenticated?: boolean;
}

export function fenceKey(email: string): string {
  return `intent:fence:${email.trim().toLowerCase()}`;
}

/**
 * Whether stored work has been superseded by a newer intent recorded elsewhere.
 *
 * The KV shadow is deliberately not consulted. A shadow that disagrees with the
 * stored intent is at least as likely to be this operation's own unfinished write,
 * or an eventually consistent read, as a newer request. Only an explicit fence
 * newer than the intent supersedes it, and a failed read never does.
 */
export function supersessionDecision(
  intent: { recordedAtMs: number; desired: 'subscribed' | 'unsubscribed'; removalUnresolved?: boolean },
  fence: IntentFence | null,
  fenceReadFailed: boolean,
): 'run' | 'supersede' {
  if (fenceReadFailed) return 'run';
  if (!fence || typeof fence.at !== 'number') return 'run';
  if (fence.at <= intent.recordedAtMs) return 'run';
  // The same authorization rule as the intent path: an unauthenticated signup may
  // not cancel an unsubscribe that has been accepted but not yet completed, so a
  // fence written by one cannot supersede it either.
  if (fence.desired === 'subscribed' && intent.desired === 'unsubscribed'
    && intent.removalUnresolved && fence.authenticated !== true) {
    return 'run';
  }
  return 'supersede';
}

interface CoordinatorPending {
  kind: 'create' | 'remove' | 'shadow';
  seq: number;
  attempts: number;
  lastError: string | null;
  nextAt: number;
}

type SyncOutcome = 'completed' | 'unverified' | 'unsubscribed' | 'blocklisted' | 'pending' | 'failed' | 'superseded';

interface SyncResult {
  outcome: SyncOutcome;
  created?: boolean;
  error?: string;
  reason?: string;
  attempts?: number;
  /** False when retrying cannot help: configuration, credentials, a decision. */
  retryable?: boolean;
}

/**
 * A lookup failure that retrying could plausibly fix. Shape and contract
 * mismatches count, because provider replication lag looks exactly like an
 * inconsistent payload; they are bounded by the attempt budget either way.
 * Definitive answers (blocklisted, unsubscribed, confirmed) never reach here.
 */
function isRetryableLookupReason(reason: string): boolean {
  if (reason === 'not_configured') return false;
  if (/^http_4(0[1-3]|04)$/.test(reason)) return false;
  return true;
}

export class SubscriptionCoordinator {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/intent' && request.method === 'POST') {
        const body = await request.json() as {
          desired: 'subscribed' | 'unsubscribed'; email: string; ip?: string; userAgent?: string;
          recordOnly?: boolean;
        };
        return Response.json(await this.runExclusive(() => this.setIntent(body)));
      }
      if (url.pathname === '/sync' && request.method === 'POST') {
        return Response.json(await this.runExclusive(() => this.sync()));
      }
      if (url.pathname === '/state') {
        return Response.json({
          intent: (await this.state.storage.get(INTENT_KEY)) ?? null,
          pending: (await this.state.storage.get(PENDING_KEY)) ?? null,
          alarm: await this.state.storage.getAlarm(),
        });
      }
      return new Response('not found', { status: 404 });
    } catch (error) {
      return Response.json(
        { outcome: 'failed', error: error instanceof Error ? error.message : String(error) },
        { status: 500 },
      );
    }
  }

  /** Retries whatever the last intent left unfinished. */
  async alarm(): Promise<void> {
    await this.runExclusive(async () => {
      const pending = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
      if (!pending) return;
      const intent = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
      if (!intent || intent.seq !== pending.seq) {
        await this.state.storage.delete(PENDING_KEY);
        return;
      }
      await this.sync();
    });
  }

  /**
   * Runs `work` with no other event delivered concurrently.
   *
   * A Durable Object is single-threaded but NOT serialized across `await`s: two
   * requests interleave freely while one is waiting on an external fetch. Without
   * this, a create and a later remove can be in flight at the same time and the
   * provider commits them in either order — which is the exact failure this
   * coordinator exists to prevent. `blockConcurrencyWhile` holds other events
   * until the promise settles, so provider effects are ordered per address.
   */
  private async runExclusive<T>(work: () => Promise<T>): Promise<T> {
    let result!: T;
    await this.state.blockConcurrencyWhile(async () => {
      result = await work();
    });
    return result;
  }

  /**
   * Records what the caller asked for, then converges the provider.
   *
   * The intent and a pending operation are written *before* any external I/O, and
   * the alarm is armed then too. That ordering is what makes a crash or a failed
   * KV write recoverable: there is never a moment where durable state says one
   * thing and nothing is scheduled to act on it.
   */
  private async setIntent(input: {
    desired: 'subscribed' | 'unsubscribed'; email: string; ip?: string; userAgent?: string;
    recordOnly?: boolean; authenticated?: boolean;
  }): Promise<SyncResult & { seq: number; desired: string }> {
    const email = input.email.trim().toLowerCase();
    const previous = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    const seq = (previous?.seq ?? 0) + 1;
    const recordedAtMs = Date.now();
    const intent: CoordinatorIntent = {
      email,
      desired: input.desired,
      seq,
      updatedAt: new Date(recordedAtMs).toISOString(),
      recordedAtMs,
      ip: input.ip,
      userAgent: input.userAgent,
      authenticated: input.authenticated,
    };

    // An accepted-but-unfinished removal is durable proof of the recipient's
    // intent. An anonymous request must not cancel it; only a caller who proved
    // control of the address may resubscribe while it is in flight.
    const pendingBefore = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
    // The intent is what protects the removal, not the operation that happens to
    // be queued next: a pending shadow repair is still an accepted unsubscribe.
    const removalInFlight = previous?.desired === 'unsubscribed'
      && pendingBefore != null
      && pendingBefore.seq === previous.seq;
    if (input.desired === 'subscribed' && removalInFlight && !input.authenticated) {
      return { outcome: 'unsubscribed', seq: previous!.seq, desired: 'unsubscribed' };
    }

    await this.state.storage.put(INTENT_KEY, intent);
    await this.state.storage.put<CoordinatorPending>(PENDING_KEY, {
      kind: input.desired === 'subscribed' ? 'create' : 'remove',
      seq,
      attempts: 0,
      lastError: null,
      nextAt: Date.now(),
    });
    await this.state.storage.setAlarm(Date.now());
    // This object owns the newest intent now, so an older fence cannot supersede it.
    try {
      await this.env.NEWSLETTER_SUBSCRIBERS.delete(fenceKey(email));
    } catch {
      // Best effort; a stale fence only matters if it is newer.
    }

    if (input.recordOnly) {
      // A legacy request publishes its intent so older durable work is superseded
      // by sequence, but it performs the provider work itself. Existing pending
      // work is left alone: cancelling it here is what let a rollback discard an
      // accepted operation, and the seq bump above already makes it stale.
      return { outcome: 'completed', seq, desired: intent.desired };
    }

    this.pendingInput = { ip: input.ip, userAgent: input.userAgent };
    const result = await this.sync({ fresh: true });
    return { ...result, seq, desired: intent.desired };
  }

  // Set immediately before a sync that follows an intent, so the KV shadow can be
  // written without threading it through every sync call.
  private pendingInput: { ip?: string; userAgent?: string } = {};

  /**
   * Converges the KV shadow and the provider toward the stored intent.
   *
   * `fresh` means this object has just recorded the intent itself, so the shadow
   * is ours to write. Otherwise the work is a retry of older intent, and the
   * shadow may have been updated by a request that never reached this object —
   * in which case the shadow wins and the work is discarded.
   */
  private async sync({ fresh = false }: { fresh?: boolean } = {}): Promise<SyncResult> {
    const intent = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    if (!intent) return { outcome: 'failed', error: 'no intent recorded', retryable: false };

    // A removal must not mutate the shadow before it is known to be performable:
    // otherwise a missing provider configuration leaves KV without the record and
    // Listmonk still mailing them.
    if (intent.desired === 'unsubscribed' && !isListmonkConfigured(this.env)) {
      // Including the first attempt: deleting the shadow first would leave KV
      // without the record while Listmonk still mails them.
      return await this.scheduleRetry(intent, { outcome: 'failed', error: 'Listmonk not configured', retryable: false }, 'remove');
    }

    if (!fresh) {
      const { decision, fence } = await this.readFence(intent);
      if (decision === 'supersede') {
        // A newer request recorded its intent elsewhere and served it itself, so
        // this work is stale. Adopt that intent rather than acting on the old one.
        await this.state.storage.put<CoordinatorIntent>(INTENT_KEY, {
          ...intent,
          desired: fence!.desired,
          seq: intent.seq + 1,
          updatedAt: new Date().toISOString(),
          recordedAtMs: fence!.at,
        });
        await this.state.storage.delete(PENDING_KEY);
        await this.state.storage.deleteAlarm();
        console.warn(`coordinator adopted a newer ${fence!.desired} intent for ${redactEmail(intent.email)} and dropped stale ${intent.desired} work`);
        return { outcome: 'superseded', retryable: false };
      }
    }

    // The shadow is repaired on every attempt, not only the first. Otherwise a
    // failed shadow write is never retried and the two stores drift permanently.
    const shadow = await this.applyShadow(intent);
    if (!shadow.ok) {
      return await this.scheduleRetry(intent, { outcome: 'failed', error: shadow.error, retryable: true }, 'shadow');
    }

    // One deadline covers lookup, create, welcome and fallback, so the exclusive
    // section cannot outlive the runtime's patience.
    const controller = new AbortController();
    const budget = setTimeout(() => controller.abort(), providerBudgetMs(this.env));
    let result: SyncResult;
    try {
      result = intent.desired === 'subscribed'
        ? await this.syncSubscribed(intent, controller.signal)
        : await this.syncUnsubscribed(intent, controller.signal);
    } finally {
      clearTimeout(budget);
    }

    // Fence after the provider call, for the case where an intent somehow changed
    // beneath us. Under `runExclusive` this should not happen, which is why the
    // compensation below is defensive rather than the primary mechanism.
    const current = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    if (!current || current.seq !== intent.seq) {
      if (result.outcome === 'completed' && result.created && intent.desired === 'subscribed') {
        // A create committed for an address that has since asked to leave: undo it.
        const removed = await unsubscribeFromListmonk(intent.email, this.env);
        console.warn(`coordinator compensated a stale create for ${redactEmail(intent.email)}: ${removed.success ? 'removed' : 'removal failed'}`);
      }
      return { ...result, outcome: 'superseded', retryable: false };
    }

    if (result.outcome === 'completed') {
      await this.state.storage.delete(PENDING_KEY);
      await this.state.storage.deleteAlarm();
      return result;
    }
    if (result.outcome === 'unsubscribed' || result.outcome === 'blocklisted') {
      // A decision by the recipient, not a failure.
      await this.state.storage.delete(PENDING_KEY);
      await this.state.storage.deleteAlarm();
      return result;
    }
    return await this.scheduleRetry(intent, result, intent.desired === 'subscribed' ? 'create' : 'remove');
  }

  private async readFence(
    intent: CoordinatorIntent,
  ): Promise<{ decision: 'run' | 'supersede'; fence: IntentFence | null }> {
    try {
      const raw = await this.env.NEWSLETTER_SUBSCRIBERS.get(fenceKey(intent.email));
      if (!raw) return { decision: 'run', fence: null };
      const fence = JSON.parse(raw) as IntentFence;
      const pending = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
      const removalUnresolved = pending != null && pending.seq === intent.seq;
      return {
        decision: supersessionDecision({ ...intent, removalUnresolved }, fence, false),
        fence,
      };
    } catch {
      // An unreadable fence proves nothing. Never erase accepted work for it.
      return { decision: 'run', fence: null };
    }
  }

  private async applyShadow(intent: CoordinatorIntent): Promise<{ ok: boolean; error?: string }> {
    try {
      if (intent.desired === 'subscribed') {
        await this.env.NEWSLETTER_SUBSCRIBERS.put(intent.email, JSON.stringify({
          timestamp: intent.updatedAt,
          ip: intent.ip ?? 'unknown',
          userAgent: intent.userAgent ?? 'unknown',
          seq: Date.now(),
        }));
      } else {
        await this.env.NEWSLETTER_SUBSCRIBERS.delete(intent.email);
      }
      return { ok: true };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private async syncSubscribed(intent: CoordinatorIntent, deadline: AbortSignal): Promise<SyncResult> {
    const { state: upstream, reason } = await lookupListmonkSubscriber(intent.email, this.env, deadline);

    if (upstream === 'confirmed') return { outcome: 'completed', created: false };
    // Both are the recipient's decision, taken elsewhere. Never overwrite them.
    if (upstream === 'blocklisted') return { outcome: 'blocklisted' };
    if (upstream === 'unsubscribed') return { outcome: 'unsubscribed' };
    if (upstream === 'pending') return { outcome: 'unverified', reason, retryable: false };
    if (upstream === 'unverified') {
      // A transient failure keeps its retry budget; a definitive one does not.
      return { outcome: 'unverified', reason, retryable: isRetryableLookupReason(reason) };
    }

    const created = await createListmonkSubscriber(intent.email, 'coordinator', this.env, deadline);
    if (!created.success) return { outcome: 'failed', error: created.error ?? 'create failed', retryable: true };

    // Fence before any mail is sent: a welcome for an intent that has already been
    // superseded is a message the recipient did not ask for.
    const current = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    if (!current || current.seq !== intent.seq || current.desired !== 'subscribed') {
      return { outcome: 'superseded', retryable: false };
    }

    if (!created.duplicate) {
      const welcomed = await this.state.storage.get<number>(WELCOME_KEY);
      if (welcomed !== intent.seq) {
        await this.state.storage.put(WELCOME_KEY, intent.seq);
        const sent = await sendListmonkWelcome(intent.email, this.env, deadline);
        if (!sent.success) {
          console.error(`Listmonk welcome send failed for ${redactEmail(intent.email)}: ${sent.error} — using Plunk fallback`);
          await sendFallbackWelcome(intent.email, this.env, deadline);
        }
      }
    }
    return { outcome: 'completed', created: !created.duplicate };
  }

  private async syncUnsubscribed(intent: CoordinatorIntent, deadline: AbortSignal): Promise<SyncResult> {
    if (!isListmonkConfigured(this.env)) {
      return { outcome: 'failed', error: 'Listmonk not configured', retryable: false };
    }
    const result = await unsubscribeFromListmonk(intent.email, this.env, deadline);
    if (!result.success) return { outcome: 'failed', error: result.error ?? 'unsubscribe failed', retryable: true };
    return { outcome: 'completed' };
  }

  /** Persists the failure and arms an alarm. Retries survive eviction. */
  private async scheduleRetry(
    intent: CoordinatorIntent,
    result: SyncResult,
    kind: 'create' | 'remove' | 'shadow',
  ): Promise<SyncResult> {
    if (result.retryable === false) {
      // Terminal: keep the reason, drop the work, do not wake up again.
      await this.state.storage.delete(PENDING_KEY);
      await this.state.storage.deleteAlarm();
      return result;
    }

    const existing = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
    const attempts = (existing?.attempts ?? 0) + 1;

    if (attempts > MAX_SYNC_ATTEMPTS) {
      console.error(`coordinator gave up after ${MAX_SYNC_ATTEMPTS} attempts for ${redactEmail(intent.email)}: ${result.error ?? result.reason ?? 'unknown'}`);
      await this.state.storage.delete(PENDING_KEY);
      await this.state.storage.deleteAlarm();
      return { outcome: 'failed', error: result.error ?? result.reason ?? 'retries exhausted', attempts, retryable: false };
    }

    const nextAt = Date.now() + retryDelayMs(attempts);
    const pending: CoordinatorPending = {
      kind,
      seq: intent.seq,
      attempts,
      lastError: result.error ?? result.reason ?? null,
      nextAt,
    };
    await this.state.storage.put(PENDING_KEY, pending);
    await this.state.storage.setAlarm(nextAt);

    console.warn(`coordinator scheduled retry ${attempts}/${MAX_SYNC_ATTEMPTS} (${kind}) for ${redactEmail(intent.email)}: ${pending.lastError}`);
    return { outcome: 'pending', attempts, error: pending.lastError ?? undefined };
  }
}

/* ========================================================================== */

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

    // Link scanners commonly prefetch GETs. Viewing a signed link must not
    // mutate a subscription; a human can submit the form with one click.
    if (path === '/api/unsubscribe' && request.method === 'GET') {
      const email = (url.searchParams.get('email') || '').trim().toLowerCase();
      const token = url.searchParams.get('token') || undefined;
      if (!isValidEmail(email) || !(await verifyUnsubscribeToken(email, token, env))) {
        return htmlResponse('<h1>Unsubscribe link invalid or expired</h1><p>Please contact us and we will remove you manually.</p>', 403, request, env);
      }
      const escape = (s: string) => s.replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      }[c]!));
      return htmlResponse(
        `<h1>Unsubscribe from the newsletter</h1><form method="post" action="/api/unsubscribe/confirm">` +
        `<input type="hidden" name="email" value="${escape(email)}">` +
        `<input type="hidden" name="token" value="${escape(token!)}">` +
        '<button type="submit">Unsubscribe</button></form>', 200, request, env,
      );
    }

    // Keep the existing authenticated JSON/form POST API, while presenting a
    // human-readable result for the browser form. No signed values are echoed.
    if (path === '/api/unsubscribe/confirm' && request.method === 'POST') {
      const result = await handleUnsubscribe(request, env, ctx);
      return htmlResponse(
        result.ok
          ? '<h1>Unsubscribe request sent</h1><p>We received a response, but could not verify removal. If you receive another newsletter, please contact us.</p>'
          : '<h1>Could not complete unsubscribe</h1><p>Please try again or contact us.</p>',
        result.status, request, env,
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
              && !key.name.startsWith('intent:')
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
