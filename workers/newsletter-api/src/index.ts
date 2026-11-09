export interface Env {
  NEWSLETTER_SUBSCRIBERS: KVNamespace; // dual-write target + rate limit + caches
  // Optional only for nonproduction unit fixtures; production fails closed.
  SUBSCRIPTION_COORDINATOR?: DurableObjectNamespace;
  // 'on' routes writes through the coordinator. 'legacy' pauses writes; never an inline writer.
  // Historical mode name retained for configuration compatibility. Keep the
  // class, binding and migrations on rollback-forward deployments.
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
  // "on": Listmonk mails an opt-in link and the subscription stays unconfirmed
  // until it is clicked, so the Worker sends no welcome of its own.
  DOUBLE_OPTIN?: string;
  // Comma-separated client IPs refused at /api/subscribe. A secret, because
  // workers.dev traffic does not pass through any zone's WAF rules.
  BLOCKED_IPS?: string;
  // "on": /api/subscribe refuses a caller without a passed Turnstile challenge.
  // Any other value leaves the challenge unenforced, so the Worker can ship
  // before the form does. A token that arrives is still verified.
  TURNSTILE?: string;
  // Turnstile secret key for the siteverify call.
  TURNSTILE_SECRET?: string;

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
// A Turnstile token is up to 2048 characters, on top of a 320-character address.
const MAX_SUBSCRIBE_REQUEST_SIZE = 4096;
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
// The name the Turnstile widget gives its hidden form input.
const TURNSTILE_FIELD = 'cf-turnstile-response';
const MAX_TURNSTILE_TOKEN_LENGTH = 2048;
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
  turnstileToken?: string;
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
      for (const key of ['email', 'token', 'honeypot', TURNSTILE_FIELD]) {
        if (key in body && body[key] !== undefined && typeof body[key] !== 'string') {
          return { ok: false, status: 400, error: 'Invalid request body' };
        }
      }
      return { ok: true, body: { ...(parsed as ParsedBody), turnstileToken: body[TURNSTILE_FIELD] as string | undefined } };
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
        turnstileToken: params.get(TURNSTILE_FIELD) ?? undefined,
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

function isDoubleOptIn(env: Env): boolean {
  return env.DOUBLE_OPTIN === 'on';
}

function isBlockedIP(ip: string, env: Env): boolean {
  return (env.BLOCKED_IPS ?? '').split(',').some((blocked) => blocked.trim() === ip);
}

function getClientIP(request: Request): string {
  const cfIP = request.headers.get('CF-Connecting-IP');
  if (cfIP) return cfIP;
  const xff = request.headers.get('X-Forwarded-For');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

/** The network a request came from, as Cloudflare reports it. Absent off the edge. */
interface NetworkEvidence {
  asn?: number;
  asOrganization?: string;
}

function networkEvidence(request: Request): NetworkEvidence {
  const cf = (request as Request<unknown, IncomingRequestCfProperties>).cf;
  const evidence: NetworkEvidence = {};
  if (typeof cf?.asn === 'number' && Number.isSafeInteger(cf.asn)) evidence.asn = cf.asn;
  if (typeof cf?.asOrganization === 'string' && cf.asOrganization) {
    evidence.asOrganization = cf.asOrganization.slice(0, 200);
  }
  return evidence;
}

interface SubscriptionRecord extends NetworkEvidence {
  timestamp: string;
  ip: string;
  userAgent: string;
  /** True when the signup passed the challenge or carried the operator token. */
  verified?: boolean;
  // Best-effort intent marker. KV is eventually consistent and this value
  // cannot serialize in-flight Listmonk writes with unsubscribe requests.
  seq: number;
}

function parseRecord(raw: string | null): SubscriptionRecord | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<SubscriptionRecord> | null;
    if (typeof parsed !== 'object' || parsed === null) return null;
    return {
      timestamp: typeof parsed.timestamp === 'string' ? parsed.timestamp : '',
      ip: typeof parsed.ip === 'string' ? parsed.ip : 'unknown',
      userAgent: typeof parsed.userAgent === 'string' ? parsed.userAgent : 'unknown',
      ...(typeof parsed.asn === 'number' ? { asn: parsed.asn } : {}),
      ...(typeof parsed.asOrganization === 'string' ? { asOrganization: parsed.asOrganization } : {}),
      ...(typeof parsed.verified === 'boolean' ? { verified: parsed.verified } : {}),
      seq: typeof parsed.seq === 'number' ? parsed.seq : 0,
    };
  } catch {
    return null;
  }
}

async function readRecord(email: string, env: Env): Promise<SubscriptionRecord | null> {
  try {
    return parseRecord(await env.NEWSLETTER_SUBSCRIBERS.get(email));
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
 * Turnstile challenge
 * The form attaches a token; siteverify says whether a browser earned it. A
 * client that posts JSON straight to the endpoint has none.
 * ========================================================================== */

function isChallengeEnforced(env: Env): boolean {
  return env.TURNSTILE === 'on';
}

// 'unavailable' is the Worker's or Cloudflare's fault, never the caller's.
type ChallengeVerdict = 'passed' | 'failed' | 'unavailable';

// Error codes that say the secret or the service is broken, not the token.
const TURNSTILE_SERVICE_ERRORS = ['missing-input-secret', 'invalid-input-secret', 'internal-error'];

/** Asks siteverify about one token. A token is single-use. Never throws. */
async function verifyTurnstileToken(token: string, clientIP: string, env: Env): Promise<ChallengeVerdict> {
  if (token.length > MAX_TURNSTILE_TOKEN_LENGTH) return 'failed';
  try {
    const resp = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET,
        response: token,
        ...(clientIP !== 'unknown' ? { remoteip: clientIP } : {}),
      }),
      signal: AbortSignal.timeout(5000),
    });
    const body = await resp.json() as { success?: unknown; 'error-codes'?: unknown } | null;
    if (body?.success === true) return 'passed';
    const codes = Array.isArray(body?.['error-codes']) ? body['error-codes'].map(String) : [];
    if (body?.success !== false || codes.some((code) => TURNSTILE_SERVICE_ERRORS.includes(code))) {
      console.error(`Turnstile siteverify unusable: HTTP ${resp.status} ${codes.join(',')}`);
      return 'unavailable';
    }
    return 'failed';
  } catch (error) {
    console.error(`Turnstile siteverify exception: ${error instanceof Error ? error.message : String(error)}`);
    return 'unavailable';
  }
}

const TEXT_CHALLENGE_REQUIRED = 'Please complete the verification and try again.';
const TEXT_CHALLENGE_FAILED = 'Verification failed. Please reload the page and try again.';
const TEXT_CHALLENGE_UNAVAILABLE = 'Verification is temporarily unavailable. Please try again later.';

/**
 * Decides whether a signup may proceed, and whether it counts as verified.
 *
 * The operator token stands in for the challenge. With enforcement off nothing
 * is refused, but a token that verifies still marks the signup, so the form can
 * ship and be observed before the gate closes. With enforcement on, every
 * failure is a refusal, including a missing secret: failing open would reopen
 * the endpoint without anyone noticing.
 */
async function checkChallenge(
  token: string | undefined,
  clientIP: string,
  authenticated: boolean,
  request: Request,
  env: Env,
): Promise<{ verified: boolean } | Response> {
  if (authenticated) return { verified: true };
  const candidate = (token ?? '').trim();

  if (!isChallengeEnforced(env)) {
    if (!candidate || !env.TURNSTILE_SECRET) return { verified: false };
    return { verified: await verifyTurnstileToken(candidate, clientIP, env) === 'passed' };
  }

  const refuse = (status: number, code: string, text: string) =>
    jsonResponse({ success: false, status: code, error: text, message: text }, status, request, env);
  if (!env.TURNSTILE_SECRET) {
    console.error('TURNSTILE is on but TURNSTILE_SECRET is not set');
    return refuse(503, 'challenge_unavailable', TEXT_CHALLENGE_UNAVAILABLE);
  }
  if (!candidate) return refuse(400, 'challenge_required', TEXT_CHALLENGE_REQUIRED);
  const verdict = await verifyTurnstileToken(candidate, clientIP, env);
  if (verdict === 'unavailable') return refuse(503, 'challenge_unavailable', TEXT_CHALLENGE_UNAVAILABLE);
  if (verdict === 'failed') return refuse(400, 'challenge_failed', TEXT_CHALLENGE_FAILED);
  return { verified: true };
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

interface ListmonkLookup {
  state: UpstreamState;
  reason: string;
  /** Provider subscriber id, unvalidated. Set only for a 'pending' answer. */
  id?: unknown;
}

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
): Promise<ListmonkLookup> {
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
): Promise<ListmonkLookup> {
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

    const subscriber = results[0] as { id?: unknown; email?: unknown; status?: unknown; lists?: unknown };
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
    if (entry.subscription_status === 'unconfirmed') return { state: 'pending', reason: 'list_unconfirmed', id: subscriber.id };
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

async function createListmonkSubscriber(email: string, clientIP: string, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; duplicate?: boolean; permanent?: boolean; error?: string }> {
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
        preconfirm_subscriptions: !isDoubleOptIn(env),
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
    // The same request gets the same 4xx, so only rate limiting is worth retrying.
    const permanent = resp.status >= 400 && resp.status < 500 && resp.status !== 429;
    return { success: false, permanent, error: `Listmonk subscribe HTTP ${resp.status}: ${body.slice(0, 200)}` };
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

/** Asks Listmonk to mail the opt-in link again. Never throws. */
async function resendListmonkOptin(id: number, env: Env, deadline?: AbortSignal): Promise<{ success: boolean; error?: string }> {
  try {
    const resp = await callListmonk(env, `/api/subscribers/${id}/optin`, { method: 'POST', signal: deadline });
    if (resp.ok) return { success: true };
    return { success: false, error: `Listmonk opt-in HTTP ${resp.status}` };
  } catch (err) {
    return { success: false, error: `Listmonk opt-in exception: ${err instanceof Error ? err.message : String(err)}` };
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
  awaitingConfirmation?: boolean;
  seq?: number;
  attempts?: number;
  error?: string;
  reason?: string;
}

function isLegacyMode(env: Env): boolean {
  return (env.COORDINATOR_MODE ?? 'on') === 'legacy';
}

/** Missing production bindings must never enable an independent writer. */
function coordinatorFor(env: Env, email: string): DurableObjectStub | null {
  try {
    const namespace = env.SUBSCRIPTION_COORDINATOR;
    if (!namespace) return null;
    const stub = namespace.get(namespace.idFromName(email.trim().toLowerCase()));
    return stub && typeof stub.fetch === 'function' ? stub : null;
  } catch {
    return null;
  }
}

function writesUnavailable(env: Env): boolean {
  return isLegacyMode(env) || (env.ENVIRONMENT === 'production' && !coordinatorFor(env, 'binding-check'));
}

function maintenanceResponse(request: Request, env: Env): Response {
  return jsonResponse({ success: false, error: 'Subscriber writes are temporarily unavailable. Please try again later.' }, 503, request, env);
}

async function submitIntent(
  coordinator: DurableObjectStub,
  desired: 'subscribed' | 'unsubscribed',
  email: string,
  clientIP: string,
  request: Request,
  authenticated = false,
  verified = false,
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
        ...networkEvidence(request),
        authenticated,
        verified,
      }),
    });
    if (!response.ok) return { outcome: 'failed', error: `coordinator HTTP ${response.status}` };
    return await response.json() as IntentResult;
  } catch (error) {
    return { outcome: 'failed', error: error instanceof Error ? error.message : String(error) };
  }
}

const TEXT_BLOCKLISTED = 'This address cannot be subscribed. Please contact us.';
const TEXT_CONFIRM_SUBSCRIBE = 'Almost done. Please check your inbox and click the link to confirm your subscription.';
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
      if (result.awaitingConfirmation) {
        return jsonResponse({ success: true, status: 'confirmation_required', message: TEXT_CONFIRM_SUBSCRIBE }, 200, request, env);
      }
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
  if (writesUnavailable(env)) return maintenanceResponse(request, env);
  try {
    // Cheap declared-length rejection before spending rate-limit budget; the
    // streamed body itself is bounded later in readBody.
    const declaredLength = request.headers.get('Content-Length');
    if (declaredLength && parseInt(declaredLength, 10) > MAX_SUBSCRIBE_REQUEST_SIZE) {
      return jsonResponse({ success: false, error: 'Request too large' }, 413, request, env);
    }
    const clientIP = getClientIP(request);
    if (isBlockedIP(clientIP, env) || !await checkRateLimit(clientIP, env)) {
      return jsonResponse({ success: false, error: 'Too many requests. Please try again later.' }, 429, request, env);
    }

    const parsed = await readBody(request, MAX_SUBSCRIBE_REQUEST_SIZE);
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

    // Nothing below this line runs for a refused caller, so no intent is
    // recorded and no mail is sent.
    const authenticated = requireAuth(request, env);
    const challenge = await checkChallenge(body.turnstileToken, clientIP, authenticated, request, env);
    if (challenge instanceof Response) return challenge;

    // The coordinator is the production path: one serialized object per address,
    // so this request cannot interleave with a concurrent unsubscribe.
    const coordinator = coordinatorFor(env, email);
    if (!coordinator && env.ENVIRONMENT === 'production') return maintenanceResponse(request, env);
    if (coordinator) {
      const result = await submitIntent(coordinator, 'subscribed', email, clientIP, request, authenticated, challenge.verified);
      return subscribeResponse(result, request, env);
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
      ...networkEvidence(request),
      verified: challenge.verified,
      seq: Date.now(),
    };
    await env.NEWSLETTER_SUBSCRIBERS.put(email, JSON.stringify(record));
    ctx.waitUntil(reconcileSignup(email, record.seq, clientIP, env, { welcome: true }));
    return subscribeResponse({ outcome: 'completed', created: true }, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

const SUBSCRIBER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// listmonk/static/public/templates/message.html renders the title in an h2, and the
// English title is "Confirmed". That template matches the same string.
const CONFIRMED_PAGE = /<h2[^>]*>\s*Confirmed\s*<\/h2>/;
const TEXT_NOTHING_TO_CONFIRM = 'This link has already been used or the subscription has ended.';

/**
 * Confirms a double opt-in from the blog. The email links to the site and the
 * page posts here, so a mail scanner that only fetches the link confirms nothing.
 *
 * Listmonk answers 200 both when it confirms and when there is nothing left to
 * confirm: a second click, an unsubscribed reader or an unknown id. Only the page
 * title differs, so anything other than the confirmed title gets the neutral answer.
 */
async function handleConfirm(request: Request, env: Env): Promise<Response> {
  if (writesUnavailable(env)) return maintenanceResponse(request, env);
  try {
    const clientIP = getClientIP(request);
    if (isBlockedIP(clientIP, env) || !await checkRateLimit(clientIP, env)) {
      return jsonResponse({ success: false, error: 'Too many requests. Please try again later.' }, 429, request, env);
    }
    const parsed = await readBody(request);
    if (!parsed.ok) return jsonResponse({ success: false, error: parsed.error }, parsed.status, request, env);

    const id = (parsed.body.token || '').trim().toLowerCase();
    if (!SUBSCRIBER_UUID.test(id)) {
      return jsonResponse({ success: false, error: 'Invalid confirmation link' }, 400, request, env);
    }
    if (!isListmonkConfigured(env)) {
      return jsonResponse({ success: false, error: 'Confirmation is unavailable' }, 503, request, env);
    }

    const resp = await callListmonk(env, `/subscription/optin/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'confirm=true',
      // callListmonk disarms its own timer at the headers; this one covers the body.
      signal: AbortSignal.timeout(10000),
    });
    if (resp.ok) {
      if (CONFIRMED_PAGE.test(await resp.text())) return jsonResponse({ success: true }, 200, request, env);
      return jsonResponse({ success: false, status: 'nothing_to_confirm', error: TEXT_NOTHING_TO_CONFIRM }, 200, request, env);
    }
    if (resp.status < 500) return jsonResponse({ success: false, error: 'Invalid confirmation link' }, 400, request, env);
    console.error(`Listmonk confirm failed: HTTP ${resp.status}`);
    return jsonResponse({ success: false, error: 'Confirmation is unavailable' }, 502, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Confirmation is unavailable' }, 502, request, env);
  }
}

async function handleUnsubscribe(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (writesUnavailable(env)) return maintenanceResponse(request, env);
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
    if (!coordinator && env.ENVIRONMENT === 'production') return maintenanceResponse(request, env);
    if (coordinator) {
      const result = await submitIntent(coordinator, 'unsubscribed', email, getClientIP(request), request, true);
      return unsubscribeResponse(result, request, env);
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

/** A KV failure must not hide a healthy Listmonk answer, so a miss is the worst case. */
async function readCountCache(key: string, env: Env): Promise<string | null> {
  try {
    return await env.NEWSLETTER_SUBSCRIBERS.get(key);
  } catch {
    return null;
  }
}

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
    const lastKnown = await readCountCache(cacheKey, env);
    return lastKnown ? parseInt(lastKnown, 10) || 0 : 0;
  }
}

async function fetchListmonkSubscriberCount(env: Env): Promise<number | null> {
  if (!isListmonkConfigured(env)) return null;
  try {
    const listId = parseInt(env.LISTMONK_LIST_ID!, 10);
    // Per-list filter via /api/subscribers?list_id=… avoids the JOIN double-count
    // bug in /api/lists/{id}.subscriber_count. The status filter drops unsubscribed,
    // blocklisted and unconfirmed rows, which list_id alone keeps. per_page=1 keeps
    // the response tiny; we only read data.total.
    const resp = await callListmonk(env, `/api/subscribers?list_id=${listId}&subscription_status=confirmed&per_page=1`, { method: 'GET' });
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
const EXHAUSTED_KEY = 'exhausted';
const WELCOME_KEY = 'welcome-seq';
const OPTIN_RESENT_KEY = 'optin-resent-at';
// Anyone can submit any address, so this bounds the mail one address can receive.
const OPTIN_RESEND_WINDOW_MS = 24 * 60 * 60_000;
const OPTIN_REMINDER_KEY = 'optin-reminder-at';
// One reminder for a link that is still unclicked two days after the signup.
const OPTIN_REMINDER_DELAY_MS = 48 * 60 * 60_000;
// A Listmonk outage delays the reminder. After the limit, the reminder is dropped.
const OPTIN_REMINDER_RETRY_MS = 60 * 60_000;
const OPTIN_REMINDER_MAX_DELAY_MS = 24 * 60 * 60_000;
// Total attempts, including the initial request; at most seven scheduled retries.
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
  /** Caller metadata, kept here so a retry can repair the shadow correctly. */
  ip?: string;
  userAgent?: string;
  asn?: number;
  asOrganization?: string;
  /** Whether the caller proved control of the address. */
  authenticated?: boolean;
  /** Whether a signup passed the challenge or carried the operator token. */
  verified?: boolean;
}

type IntentInput = Pick<CoordinatorIntent,
  'desired' | 'email' | 'ip' | 'userAgent' | 'asn' | 'asOrganization' | 'authenticated' | 'verified'>;

interface CoordinatorPending {
  kind: 'create' | 'remove' | 'shadow';
  seq: number;
  attempts: number;
  lastError: string | null;
  nextAt: number;
  /** The provider removal for this intent succeeded; only the shadow is owed. */
  providerRemoved?: boolean;
}

/** Work dropped after the last attempt. Without this it would look completed. */
interface CoordinatorExhausted {
  seq: number;
  kind: CoordinatorPending['kind'];
  desired: CoordinatorIntent['desired'];
  lastError: string;
  at: string;
}

type SyncOutcome = 'completed' | 'unverified' | 'unsubscribed' | 'blocklisted' | 'pending' | 'failed' | 'superseded';

interface SyncResult {
  outcome: SyncOutcome;
  created?: boolean;
  awaitingConfirmation?: boolean;
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
  // Only an operator can add the list row, so another attempt cannot change this.
  if (reason === 'no_entry_for_target_list') return false;
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
        if (isLegacyMode(this.env)) return new Response('maintenance', { status: 503 });
        const body = await request.json() as IntentInput;
        return Response.json(await this.runExclusive(() => this.setIntent(body)));
      }
      if (url.pathname === '/sync' && request.method === 'POST') {
        return Response.json(await this.runExclusive(() => this.sync()));
      }
      if (url.pathname === '/state') {
        return Response.json({
          intent: (await this.state.storage.get(INTENT_KEY)) ?? null,
          pending: (await this.state.storage.get(PENDING_KEY)) ?? null,
          exhausted: (await this.state.storage.get(EXHAUSTED_KEY)) ?? null,
          reminder: (await this.state.storage.get(OPTIN_REMINDER_KEY)) ?? null,
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
      if (pending) {
        if (isLegacyMode(this.env)) {
          await this.state.storage.setAlarm(Date.now() + 60_000);
          return;
        }
        const intent = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
        if (!intent || intent.seq !== pending.seq) {
          await this.state.storage.delete(PENDING_KEY);
        } else {
          await this.sync();
        }
      }
      await this.sendDueReminder();
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
  private async setIntent(input: IntentInput): Promise<SyncResult & { seq: number; desired: string }> {
    const email = input.email.trim().toLowerCase();
    const previous = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    const seq = (previous?.seq ?? 0) + 1;
    const recordedAtMs = Date.now();
    const intent: CoordinatorIntent = {
      email,
      desired: input.desired,
      seq,
      updatedAt: new Date(recordedAtMs).toISOString(),
      ip: input.ip,
      userAgent: input.userAgent,
      asn: input.asn,
      asOrganization: input.asOrganization,
      authenticated: input.authenticated,
      verified: input.verified,
    };

    // The unsubscribe intent is a durable recipient tombstone, independent of
    // pending work: exhaustion or completion must not permit anonymous signup
    // to restore mail. Proof of control only clears this guard; provider lookup
    // policy still governs whether an authenticated signup may proceed.
    if (input.desired === 'subscribed' && previous?.desired === 'unsubscribed' && !input.authenticated) {
      return { outcome: 'unsubscribed', seq: previous!.seq, desired: 'unsubscribed' };
    }

    await this.state.storage.delete(EXHAUSTED_KEY);
    await this.state.storage.put(INTENT_KEY, intent);
    await this.state.storage.put<CoordinatorPending>(PENDING_KEY, {
      kind: input.desired === 'subscribed' ? 'create' : 'remove',
      seq,
      attempts: 0,
      lastError: null,
      nextAt: Date.now(),
    });
    await this.state.storage.setAlarm(Date.now());
    const result = await this.sync();
    return { ...result, seq, desired: intent.desired };
  }

  /** Converges only this object's authoritative intent; maintenance pauses it. */
  private async sync(): Promise<SyncResult> {
    if (isLegacyMode(this.env)) {
      const pending = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
      if (pending) await this.state.storage.setAlarm(Date.now() + 60_000);
      return { outcome: 'pending' };
    }
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

    // The shadow is repaired on every attempt, not only the first. Otherwise a
    // failed shadow write is never retried and the two stores drift permanently.
    const shadow = await this.applyShadow(intent);
    // A signup waits for the shadow. A removal does not: Listmonk decides who gets
    // mail, so a KV outage must not keep a reader on the list.
    if (!shadow.ok && intent.desired === 'subscribed') {
      return await this.scheduleRetry(intent, { outcome: 'failed', error: shadow.error, retryable: true }, 'shadow');
    }
    const pending = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
    const providerRemoved = pending?.seq === intent.seq && pending.providerRemoved === true;

    // One deadline covers lookup, create, welcome and fallback, so the exclusive
    // section cannot outlive the runtime's patience.
    const controller = new AbortController();
    const budget = setTimeout(() => controller.abort(), providerBudgetMs(this.env));
    let result: SyncResult;
    try {
      if (intent.desired === 'subscribed') result = await this.syncSubscribed(intent, controller.signal);
      else if (providerRemoved) result = { outcome: 'completed' };
      else result = await this.syncUnsubscribed(intent, controller.signal);
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

    if (!shadow.ok && result.outcome === 'completed') {
      return await this.scheduleRetry(intent, { outcome: 'failed', error: shadow.error, retryable: true }, 'shadow', true);
    }
    if (result.outcome === 'completed') {
      await this.state.storage.delete(PENDING_KEY);
      await this.endRetries();
      return result;
    }
    if (result.outcome === 'unsubscribed' || result.outcome === 'blocklisted') {
      // A decision by the recipient, not a failure.
      await this.state.storage.delete(PENDING_KEY);
      await this.endRetries();
      return result;
    }
    return await this.scheduleRetry(intent, result, intent.desired === 'subscribed' ? 'create' : 'remove');
  }

  private async applyShadow(intent: CoordinatorIntent): Promise<{ ok: boolean; error?: string }> {
    try {
      if (intent.desired === 'subscribed') {
        // The record is the signup evidence, so a repeat submission must not replace
        // it. An unsubscribe deletes it, so a real resubscribe writes a new one.
        if (await this.env.NEWSLETTER_SUBSCRIBERS.get(intent.email) !== null) return { ok: true };
        await this.env.NEWSLETTER_SUBSCRIBERS.put(intent.email, JSON.stringify({
          timestamp: intent.updatedAt,
          ip: intent.ip ?? 'unknown',
          userAgent: intent.userAgent ?? 'unknown',
          asn: intent.asn,
          asOrganization: intent.asOrganization,
          verified: intent.verified === true,
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
    const { state: upstream, reason, id } = await lookupListmonkSubscriber(intent.email, this.env, deadline);

    if (upstream === 'confirmed') return { outcome: 'completed', created: false };
    // Both are the recipient's decision, taken elsewhere. Never overwrite them.
    if (upstream === 'blocklisted') return { outcome: 'blocklisted' };
    if (upstream === 'unsubscribed') return { outcome: 'unsubscribed' };
    if (upstream === 'pending') {
      // Under double opt-in this is the normal state of an unclicked link.
      // The reader is told to check their inbox, so make that true: a create here
      // would be refused, and the original mail may be long gone.
      if (isDoubleOptIn(this.env)) {
        await this.resendOptin(intent, id, deadline);
        return { outcome: 'completed', created: false, awaitingConfirmation: true };
      }
      return { outcome: 'unverified', reason, retryable: false };
    }
    if (upstream === 'unverified') {
      // A transient failure keeps its retry budget; a definitive one does not.
      return { outcome: 'unverified', reason, retryable: isRetryableLookupReason(reason) };
    }

    const created = await createListmonkSubscriber(intent.email, intent.ip ?? 'unknown', this.env, deadline);
    if (!created.success) return { outcome: 'failed', error: created.error ?? 'create failed', retryable: !created.permanent };

    // Fence before any mail is sent: a welcome for an intent that has already been
    // superseded is a message the recipient did not ask for.
    const current = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    if (!current || current.seq !== intent.seq || current.desired !== 'subscribed') {
      return { outcome: 'superseded', retryable: false };
    }

    if (isDoubleOptIn(this.env) && !created.duplicate) {
      // Anyone can submit any address. A signup without a passed challenge gets
      // Listmonk's opt-in mail and nothing after it, including a reminder that an
      // earlier signup for this address left armed.
      if (intent.verified === true) {
        await this.state.storage.put(OPTIN_REMINDER_KEY, Date.now() + OPTIN_REMINDER_DELAY_MS);
      } else {
        await this.state.storage.delete(OPTIN_REMINDER_KEY);
      }
      return { outcome: 'completed', created: true, awaitingConfirmation: true };
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

  /**
   * Best effort: the outcome of a resend never reaches the caller or the retry
   * budget. The window is spent before the send, like the welcome marker, so a
   * crash or a failed send cannot lead to a second mail inside it.
   */
  private async resendOptin(intent: CoordinatorIntent, id: unknown, deadline: AbortSignal): Promise<void> {
    try {
      if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) {
        console.warn(`opt-in resend skipped for ${redactEmail(intent.email)}: no usable subscriber id`);
        return;
      }
      const last = await this.state.storage.get<number>(OPTIN_RESENT_KEY);
      if (last !== undefined && Date.now() - last < OPTIN_RESEND_WINDOW_MS) return;
      await this.state.storage.put(OPTIN_RESENT_KEY, Date.now());
      const sent = await resendListmonkOptin(id, this.env, deadline);
      if (!sent.success) console.error(`opt-in resend failed for ${redactEmail(intent.email)}: ${sent.error}`);
    } catch (error) {
      console.error(`opt-in resend failed for ${redactEmail(intent.email)}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Mails the opt-in link once more to an address that has not clicked it. The key
   * goes before the send, so a crash cannot mail twice. Only a lookup that could not
   * answer keeps the reminder. The resend window still applies, so a recent resend
   * uses up the reminder and no second mail goes out.
   */
  private async sendDueReminder(): Promise<void> {
    const due = await this.state.storage.get<number>(OPTIN_REMINDER_KEY);
    if (due === undefined) return;
    // The retry alarm is armed, and endRetries() rearms this reminder.
    if (await this.state.storage.get(PENDING_KEY)) return;
    if (isLegacyMode(this.env)) {
      await this.state.storage.setAlarm(Date.now() + 60_000);
      return;
    }
    if (Date.now() < due) {
      await this.state.storage.setAlarm(due);
      return;
    }
    const intent = await this.state.storage.get<CoordinatorIntent>(INTENT_KEY);
    if (intent?.desired !== 'subscribed' || !isDoubleOptIn(this.env)) {
      await this.state.storage.delete(OPTIN_REMINDER_KEY);
      return;
    }

    const controller = new AbortController();
    const budget = setTimeout(() => controller.abort(), providerBudgetMs(this.env));
    try {
      const { state: upstream, reason, id } = await lookupListmonkSubscriber(intent.email, this.env, controller.signal);
      if (upstream === 'unverified' && isRetryableLookupReason(reason)
        && Date.now() - due < OPTIN_REMINDER_MAX_DELAY_MS) {
        await this.state.storage.setAlarm(Date.now() + OPTIN_REMINDER_RETRY_MS);
        return;
      }
      await this.state.storage.delete(OPTIN_REMINDER_KEY);
      // Any other state means the reader clicked, left or was blocked.
      if (upstream === 'pending') await this.resendOptin(intent, id, controller.signal);
    } finally {
      clearTimeout(budget);
    }
  }

  /** Retry work is over. The one alarm that can remain is a waiting reminder. */
  private async endRetries(): Promise<void> {
    const reminder = await this.state.storage.get<number>(OPTIN_REMINDER_KEY);
    if (reminder === undefined) await this.state.storage.deleteAlarm();
    else await this.state.storage.setAlarm(reminder);
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
    providerRemoved = false,
  ): Promise<SyncResult> {
    if (result.retryable === false) {
      // Terminal: keep the reason, drop the work, do not wake up again.
      await this.state.storage.delete(PENDING_KEY);
      await this.endRetries();
      return result;
    }

    const existing = await this.state.storage.get<CoordinatorPending>(PENDING_KEY);
    const attempts = (existing?.attempts ?? 0) + 1;

    if (attempts >= MAX_SYNC_ATTEMPTS) {
      const lastError = result.error ?? result.reason ?? 'retries exhausted';
      console.error(`coordinator gave up after ${MAX_SYNC_ATTEMPTS} attempts for ${redactEmail(intent.email)}: ${lastError}`);
      await this.state.storage.put<CoordinatorExhausted>(EXHAUSTED_KEY, {
        seq: intent.seq,
        kind,
        desired: intent.desired,
        lastError,
        at: new Date().toISOString(),
      });
      await this.state.storage.delete(PENDING_KEY);
      await this.endRetries();
      return { outcome: 'failed', error: lastError, attempts, retryable: false };
    }

    const nextAt = Date.now() + retryDelayMs(attempts);
    const pending: CoordinatorPending = {
      kind,
      seq: intent.seq,
      attempts,
      lastError: result.error ?? result.reason ?? null,
      nextAt,
      ...(providerRemoved ? { providerRemoved } : {}),
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

    if (path === '/api/confirm' && request.method === 'POST') {
      return handleConfirm(request, env);
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
        const cached = await readCountCache(COMBINED_COUNT_CACHE_KEY, env);
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
        })().catch(() => null);

        const [listmonkCount, kvCount, linkedInCount] = await Promise.all([
          fetchListmonkSubscriberCount(env),
          kvCountPromise,
          fetchLinkedInFollowers(env, ctx),
        ]);

        const subscriberCount = listmonkCount ?? kvCount;
        if (subscriberCount === null) throw new Error('no subscriber count source answered');
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
