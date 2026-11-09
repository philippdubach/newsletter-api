import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock types
interface MockKVNamespace {
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
  list: ReturnType<typeof vi.fn>;
}

interface MockR2Bucket {
  list: ReturnType<typeof vi.fn>;
}

interface MockEnv {
  NEWSLETTER_SUBSCRIBERS: MockKVNamespace;
  R2_BUCKET: MockR2Bucket;
  ALLOWED_ORIGIN: string;
  PLUNK_SECRET_KEY: string;
  ADMIN_TOKEN: string;
  ENVIRONMENT: string;
  UNSUBSCRIBE_HMAC_SECRET: string;
  UNSUBSCRIBE_BASE_URL?: string;
  LISTMONK_API_URL?: string;
  LISTMONK_API_USER?: string;
  LISTMONK_API_TOKEN?: string;
  LISTMONK_LIST_ID?: string;
  LISTMONK_WELCOME_TEMPLATE_ID?: string;
}

// Import the worker
import worker, { reconcileSignup, SubscriptionCoordinator, type Env } from './index';

type EnvLike = Parameters<typeof reconcileSignup>[3];

// The unsubscribe token is HMAC-SHA256 over the email with the server secret;
// this test helper mirrors the signing scheme used by the Worker.
async function unsubscribeToken(email: string, secret = 'test-hmac-secret'): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(email));
  const hex = [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `v1:${hex}`;
}

function listmonkOk(): Response {
  return new Response('{}', { status: 200 });
}

// Payload for the single-address lookup the existing-record path performs.
function listmonkLookup({ status = 'enabled', listStatus = 'confirmed' }: { status?: string; listStatus?: string } = {}): Response {
  return new Response(
    JSON.stringify({
      data: {
        results: [{ email: 'existing@example.com', status, lists: [{ id: 3, subscription_status: listStatus }] }],
        total: 1,
      },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('Newsletter API', () => {
  let mockEnv: MockEnv & Env;
  let mockCtx: ExecutionContext;
  let pending: Promise<unknown>[];
  let deniedFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    deniedFetch = vi.fn().mockRejectedValue(new Error('Unexpected outbound request in test'));
    vi.stubGlobal('fetch', deniedFetch);
    pending = [];
    mockEnv = {
      NEWSLETTER_SUBSCRIBERS: {
        get: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(),
      },
      R2_BUCKET: {
        list: vi.fn(),
      },
      ALLOWED_ORIGIN: 'https://example.com',
      PLUNK_SECRET_KEY: 'test_api_key',
      ADMIN_TOKEN: 'test_token',
      ENVIRONMENT: 'development',
      UNSUBSCRIBE_HMAC_SECRET: 'test-hmac-secret',
      LISTMONK_API_URL: 'https://mail.example.com',
      LISTMONK_API_USER: 'user',
      LISTMONK_API_TOKEN: 'token',
      LISTMONK_LIST_ID: '3',
      LISTMONK_WELCOME_TEMPLATE_ID: '5',
    } as unknown as MockEnv & Env;

    mockCtx = {
      waitUntil: vi.fn((promise: Promise<unknown>) => { pending.push(promise); }),
      passThroughOnException: vi.fn(),
    } as unknown as ExecutionContext;

    vi.clearAllMocks();
  });

  afterEach(async () => {
    await Promise.allSettled(pending);
    vi.unstubAllGlobals();
    expect(deniedFetch).not.toHaveBeenCalled();
  });

  describe('OPTIONS requests', () => {
    it('should return CORS headers', async () => {
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'OPTIONS',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    });
  });

  describe('POST /api/subscribe', () => {
    it('should subscribe a valid email', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; message: string };

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.message).toBe('Subscribed successfully');
    });

    it('should reject invalid email', async () => {
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'invalid-email' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; error: string };

      expect(response.status).toBe(400);
      expect(body.success).toBe(false);
      expect(body.error).toBe('Invalid email address');
    });

    it('should handle already subscribed email when the provider confirms it', async () => {
      global.fetch = vi.fn().mockResolvedValue(listmonkLookup());
      mockEnv.NEWSLETTER_SUBSCRIBERS.get
        .mockResolvedValueOnce(null) // rate limit check
        .mockResolvedValueOnce(JSON.stringify({ timestamp: '2025-01-01' })); // existing subscription

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'existing@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; message: string };

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.message).toBe('Already subscribed');
    });

    it('should not claim an existing record is subscribed when the provider cannot be read', async () => {
      // An unreachable provider is not evidence that the address is subscribed.
      global.fetch = vi.fn().mockRejectedValue(new Error('provider unreachable'));
      mockEnv.NEWSLETTER_SUBSCRIBERS.get
        .mockResolvedValueOnce(null) // rate limit check
        .mockResolvedValueOnce(JSON.stringify({ timestamp: '2025-01-01' })); // existing subscription

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'existing@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; message: string; status?: string };

      expect(body.success).toBe(false);
      expect(body.message).not.toBe('Already subscribed');
      expect(body.status).toBe('unverified');
    });

    it('should not reactivate a blocklisted address', async () => {
      global.fetch = vi.fn().mockResolvedValue(listmonkLookup({ status: 'blocklisted', listStatus: 'unsubscribed' }));
      mockEnv.NEWSLETTER_SUBSCRIBERS.get
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(JSON.stringify({ timestamp: '2025-01-01' }));

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'existing@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; status?: string };

      expect(body.success).toBe(false);
      expect(body.status).toBe('blocklisted');
      // A blocklist entry must not be re-created or re-enabled.
      const methods = (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.map(([, init]) => (init as RequestInit)?.method);
      expect(methods).not.toContain('POST');
    });

    it('should accept a native URL-encoded form submission (no-JavaScript)', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Origin: 'https://example.com',
        },
        body: 'email=form%40example.com',
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean };

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
    });

    it('should reject malformed JSON as a client error, not a 500', async () => {
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: '{not json',
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(400);
    });

    it('should reject honeypot submissions', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);

      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com', honeypot: 'spam' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; error: string };

      expect(response.status).toBe(400);
      expect(body.success).toBe(false);
    });

    it('should reject oversized requests', async () => {
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': '10000',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; error: string };

      expect(response.status).toBe(413);
      expect(body.error).toBe('Request too large');
    });
  });

  describe('POST /api/unsubscribe', () => {
    it('should reject an email-only request without proof of control', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(403);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
    });

    it('reports provider acknowledgement as unverified with a valid token', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());
      const token = await unsubscribeToken('test@example.com');

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com', token }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; status: string; message: string };

      expect(response.status).toBe(202);
      expect(body.success).toBe(false);
      expect(body.status).toBe('unverified');
      expect(body.message).toContain('could not be verified');
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).toHaveBeenCalledWith('test@example.com');
    });

    it('does not claim completion for an asynchronous provider response', async () => {
      global.fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 202 }));
      const token = await unsubscribeToken('test@example.com');
      const response = await worker.fetch(new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', token }),
      }), mockEnv, mockCtx);
      expect(response.status).toBe(202);
      expect(await response.json()).toMatchObject({ success: false, status: 'unverified' });
    });

    it('should use the documented plural Listmonk route', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());
      const token = await unsubscribeToken('test@example.com');

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com', token }),
      });
      await worker.fetch(request, mockEnv, mockCtx);

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toMatch(/\/api\/subscribers\/query\/lists$/);
      expect(call[1].method).toBe('PUT');
    });

    it('should reject a token signed for a different address', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());
      const token = await unsubscribeToken('other@example.com');

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com', token }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(403);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
    });

    it('should allow an operator bearer token without a subscriber token', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
          Authorization: 'Bearer test_token',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(202);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).toHaveBeenCalledWith('test@example.com');
    });

    it('should surface a Listmonk failure instead of claiming success', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 404 }));
      const token = await unsubscribeToken('test@example.com');

      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com', token }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(502);
      // KV is removed, but there is no durable retry or ordering guarantee.
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).toHaveBeenCalledWith('test@example.com');
    });

    it('rejects an unsubscribe body over the 2 KB limit', async () => {
      const response = await worker.fetch(new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'a'.repeat(2049) }),
      }), mockEnv, mockCtx);
      expect(response.status).toBe(413);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
    });

    it('does not acknowledge or delete KV when Listmonk configuration is incomplete', async () => {
      mockEnv.LISTMONK_API_TOKEN = '';
      const token = await unsubscribeToken('test@example.com');
      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', token }),
      });
      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(502);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('should reject invalid email on unsubscribe', async () => {
      const request = new Request('https://api.example.com/api/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'not-an-email' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { success: boolean; error: string };

      expect(response.status).toBe(400);
      expect(body.error).toBe('Invalid email address');
    });
  });

  describe('unsubscribe email links', () => {
    it('does not unsubscribe when a valid link is prefetched; a form POST does', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());
      const email = "te'st&x@example.com";
      const token = await unsubscribeToken(email);

      const request = new Request(
        `https://api.example.com/api/unsubscribe?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`,
        { method: 'GET' },
      );
      const response = await worker.fetch(request, mockEnv, mockCtx);
      const html = await response.text();
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/html');
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
      expect(html).toContain('te&#39;st&amp;x@example.com');
      expect(html).toContain('action="/api/unsubscribe/confirm"');
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
      expect(global.fetch).not.toHaveBeenCalled();

      const post = new Request('https://api.example.com/api/unsubscribe/confirm', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email, token }).toString(),
      });
      const confirmation = await worker.fetch(post, mockEnv, mockCtx);
      expect(confirmation.status).toBe(202);
      expect(await confirmation.text()).toContain('could not verify removal');
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).toHaveBeenCalledWith(email);
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('accepts the form encoding of an accepted 320-character email', async () => {
      const email = '&'.repeat(315) + '@x.co';
      const token = await unsubscribeToken(email);
      const body = new URLSearchParams({ email, token }).toString();
      expect(new TextEncoder().encode(body).length).toBeGreaterThan(1024);
      global.fetch = vi.fn().mockResolvedValue(listmonkOk());
      const get = await worker.fetch(new Request(
        `https://api.example.com/api/unsubscribe?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`,
      ), mockEnv, mockCtx);
      expect(get.status).toBe(200);
      const post = await worker.fetch(new Request('https://api.example.com/api/unsubscribe/confirm', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      }), mockEnv, mockCtx);
      expect(post.status).toBe(202);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).toHaveBeenCalledWith(email);
    });

    it('does not claim success when the upstream unsubscribe fails', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);
      global.fetch = vi.fn().mockResolvedValue(new Response('', { status: 500 }));
      const token = await unsubscribeToken('test@example.com');
      const post = new Request('https://api.example.com/api/unsubscribe/confirm', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'test@example.com', token }).toString(),
      });
      const response = await worker.fetch(post, mockEnv, mockCtx);
      expect(response.status).toBe(502);
      expect(await response.text()).toContain('Could not complete unsubscribe');
    });

    it('should reject a missing or invalid token', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.delete.mockResolvedValue(undefined);

      const request = new Request(
        'https://api.example.com/api/unsubscribe?email=test%40example.com',
        { method: 'GET', headers: { Origin: 'https://example.com' } },
      );

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(403);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.delete).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/newsletters', () => {
    it('should return newsletters from R2', async () => {
      mockEnv.R2_BUCKET.list.mockResolvedValue({
        objects: [
          { key: 'newsletter/newsletter-2025-01.html' },
          { key: 'newsletter/newsletter-2024-12.html' },
        ],
      });

      const request = new Request('https://api.example.com/api/newsletters', {
        method: 'GET',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { newsletters: Array<{ filename: string }> };

      expect(response.status).toBe(200);
      expect(body.newsletters).toHaveLength(2);
      expect(body.newsletters[0].filename).toBe('newsletter-2025-01.html');
    });

    it('should return fallback when R2 is empty', async () => {
      mockEnv.R2_BUCKET.list.mockResolvedValue({ objects: [] });
      global.fetch = vi.fn().mockRejectedValue(new Error('Synthetic archive failure'));

      const request = new Request('https://api.example.com/api/newsletters', {
        method: 'GET',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { newsletters: Array<{ filename: string }> };

      expect(response.status).toBe(200);
      expect(body.newsletters.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('POST /api/confirm', () => {
    it('reports a provider failure when the 200 body cannot be read', async () => {
      const broken = new ReadableStream({ start(controller) { controller.error(new Error('stream reset')); } });
      global.fetch = vi.fn().mockResolvedValue(new Response(broken, { status: 200 }));

      const response = await worker.fetch(new Request('https://api.example.com/api/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: '0d8f6a52-3c1e-4b7a-9f10-2a6c5e7b1d34' }),
      }), mockEnv, mockCtx);

      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({ success: false, error: 'Confirmation is unavailable' });
    });
  });

  describe('GET /api/subscriber-count', () => {
    it('should return subscriber count', async () => {
      mockEnv.LISTMONK_API_TOKEN = ''; // This fixture exercises the KV-only fallback.
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockResolvedValue({
        keys: [
          { name: 'user1@example.com' },
          { name: 'user2@example.com' },
          { name: 'rate_limit:127.0.0.1' },
        ],
        list_complete: true,
      });

      const request = new Request('https://api.example.com/api/subscriber-count', {
        method: 'GET',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { count: number; display: string };

      // Two subscriber keys round up to 10+.  (The separate displayed-count
      // semantics are tracked as an open item in the audit, not this fixture.)
      expect(response.status).toBe(200);
      expect(body.count).toBe(10);
      expect(body.display).toBe('10+');
    });

    function listmonkCount(total: number): Response {
      return new Response(JSON.stringify({ data: { total } }), { status: 200 });
    }

    async function count(): Promise<{ count: number; display: string }> {
      const response = await worker.fetch(new Request('https://api.example.com/api/subscriber-count'), mockEnv, mockCtx);
      expect(response.status).toBe(200);
      return await response.json() as { count: number; display: string };
    }

    it('keeps the Listmonk number when the KV list fails', async () => {
      global.fetch = vi.fn().mockResolvedValue(listmonkCount(123));
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockRejectedValue(new Error('kv unavailable'));

      expect(await count()).toEqual({ count: 130, display: '130+' });
    });

    it('keeps the Listmonk number when every KV read fails', async () => {
      mockEnv.LINKEDIN_NEWSLETTER_URLS = 'https://linkedin.example.com/newsletter';
      global.fetch = vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).startsWith('https://linkedin.example.com')) return new Response('down', { status: 503 });
        return listmonkCount(123);
      }) as unknown as typeof fetch;
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockRejectedValue(new Error('kv unavailable'));
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockRejectedValue(new Error('kv unavailable'));

      expect(await count()).toEqual({ count: 130, display: '130+' });
    });

    it('keeps the live answer when the cache write fails', async () => {
      global.fetch = vi.fn().mockResolvedValue(listmonkCount(123));
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockResolvedValue({ keys: [], list_complete: true });
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockRejectedValue(new Error('kv unavailable'));

      expect(await count()).toEqual({ count: 130, display: '130+' });
    });

    it('answers 0+ and caches nothing when both sources fail', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('provider unreachable'));
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockRejectedValue(new Error('kv unavailable'));

      expect(await count()).toEqual({ count: 0, display: '0+' });
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.put).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const request = new Request('https://api.example.com/api/health', {
        method: 'GET',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { status: string; timestamp: string };

      expect(response.status).toBe(200);
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBeDefined();
    });
  });

  describe('POST /api/test-email', () => {
    it('should require auth in production', async () => {
      mockEnv.ENVIRONMENT = 'production';

      const request = new Request('https://api.example.com/api/test-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(401);
    });

    it('should require auth in development too (fail closed)', async () => {
      mockEnv.ENVIRONMENT = 'development';

      const request = new Request('https://api.example.com/api/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(401);
    });

    it('should refuse the route when the environment identity is missing', async () => {
      mockEnv.ENVIRONMENT = undefined as unknown as string;

      const request = new Request('https://api.example.com/api/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(503);
    });

    it('should refuse the route for an unknown environment', async () => {
      mockEnv.ENVIRONMENT = 'staging-typo';

      const request = new Request('https://api.example.com/api/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.com' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      expect(response.status).toBe(503);
    });

    it('should allow with valid auth token', async () => {
      mockEnv.ENVIRONMENT = 'production';

      // Mock fetch for Plunk API
      global.fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));

      const request = new Request('https://api.example.com/api/test-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.com',
          Authorization: 'Bearer test_token',
        },
        body: JSON.stringify({ email: 'test@example.com' }),
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);
    });
  });

  describe('Unknown routes', () => {
    it('should return 404 for unknown paths', async () => {
      const request = new Request('https://api.example.com/api/unknown', {
        method: 'GET',
        headers: { Origin: 'https://example.com' },
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);
      const body = await response.json() as { error: string };

      expect(response.status).toBe(404);
      expect(body.error).toBe('Not found');
    });
  });

  describe('Turnstile challenge on /api/subscribe', () => {
    const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    type Answer = { success: boolean; status?: string; error?: string; message?: string };

    // Stands in for the Durable Object, so a test can see whether an intent was
    // submitted and what it carried.
    function bindCoordinator(): ReturnType<typeof vi.fn> {
      const intent = vi.fn(async (_url: string, _init: RequestInit) =>
        new Response(JSON.stringify({ outcome: 'completed', created: true }), { status: 200 }));
      (mockEnv as Env).SUBSCRIPTION_COORDINATOR = {
        idFromName: (name: string) => name,
        get: () => ({ fetch: intent }),
      } as unknown as DurableObjectNamespace;
      return intent;
    }

    const intentBody = (intent: ReturnType<typeof vi.fn>): Record<string, unknown> =>
      JSON.parse(String((intent.mock.calls[0][1] as RequestInit).body));

    function stubSiteverify(answer: unknown, status = 200): ReturnType<typeof vi.fn> {
      const f = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(typeof answer === 'string' ? answer : JSON.stringify(answer), { status }));
      global.fetch = f as unknown as typeof fetch;
      return f;
    }

    function signup(fields: Record<string, unknown>, headers: Record<string, string> = {}): Request {
      return new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.7', ...headers },
        body: JSON.stringify({ email: 'reader@example.com', ...fields }),
      });
    }

    beforeEach(() => {
      (mockEnv as Env).TURNSTILE = 'on';
      (mockEnv as Env).TURNSTILE_SECRET = 'test-turnstile-secret';
    });

    it('refuses a signup without a token before any intent or outbound call', async () => {
      const intent = bindCoordinator();

      const response = await worker.fetch(signup({}), mockEnv, mockCtx);
      const body = await response.json() as Answer;

      expect(response.status).toBe(400);
      expect(body).toMatchObject({ success: false, status: 'challenge_required' });
      expect(body.error).toBe(body.message);
      expect(intent).not.toHaveBeenCalled();
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.put).not.toHaveBeenCalledWith('reader@example.com', expect.anything());
    });

    it('refuses a token that siteverify rejects', async () => {
      const intent = bindCoordinator();
      const siteverify = stubSiteverify({ success: false, 'error-codes': ['invalid-input-response'] });

      const response = await worker.fetch(signup({ 'cf-turnstile-response': 'forged' }), mockEnv, mockCtx);
      const body = await response.json() as Answer;

      expect(response.status).toBe(400);
      expect(body).toMatchObject({ success: false, status: 'challenge_failed' });
      expect(siteverify).toHaveBeenCalledTimes(1);
      expect(intent).not.toHaveBeenCalled();
    });

    it('sends the secret, the token and the caller address to siteverify, then submits a verified intent', async () => {
      const intent = bindCoordinator();
      const siteverify = stubSiteverify({ success: true });

      const response = await worker.fetch(signup({ 'cf-turnstile-response': ' good-token ' }), mockEnv, mockCtx);

      expect(response.status).toBe(200);
      const [url, init] = siteverify.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(SITEVERIFY);
      expect(init.method).toBe('POST');
      expect(JSON.parse(String(init.body))).toEqual({
        secret: 'test-turnstile-secret', response: 'good-token', remoteip: '203.0.113.7',
      });
      expect(intent).toHaveBeenCalledTimes(1);
      expect(intentBody(intent)).toMatchObject({ desired: 'subscribed', authenticated: false, verified: true });
    });

    it('accepts the widget field from a URL-encoded form', async () => {
      const intent = bindCoordinator();
      const siteverify = stubSiteverify({ success: true });
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'email=reader%40example.com&cf-turnstile-response=form-token',
      });

      const response = await worker.fetch(request, mockEnv, mockCtx);

      expect(response.status).toBe(200);
      expect(JSON.parse(String((siteverify.mock.calls[0][1] as RequestInit).body)).response).toBe('form-token');
      expect(intentBody(intent).verified).toBe(true);
    });

    it('accepts a token of the maximum length and refuses a longer one unasked', async () => {
      const intent = bindCoordinator();
      const siteverify = stubSiteverify({ success: true });

      const longest = await worker.fetch(signup({ 'cf-turnstile-response': 'x'.repeat(2048) }), mockEnv, mockCtx);
      expect(longest.status).toBe(200);
      expect(siteverify).toHaveBeenCalledTimes(1);

      const tooLong = await worker.fetch(signup({ 'cf-turnstile-response': 'x'.repeat(2049) }), mockEnv, mockCtx);
      expect(tooLong.status).toBe(400);
      expect((await tooLong.json() as Answer).status).toBe('challenge_failed');
      expect(siteverify).toHaveBeenCalledTimes(1);
      expect(intent).toHaveBeenCalledTimes(1);
    });

    it('rejects a token that is not a string as a malformed body', async () => {
      const intent = bindCoordinator();

      const response = await worker.fetch(signup({ 'cf-turnstile-response': { nested: true } }), mockEnv, mockCtx);

      expect(response.status).toBe(400);
      expect((await response.json() as Answer).error).toBe('Invalid request body');
      expect(intent).not.toHaveBeenCalled();
    });

    it.each([
      ['a siteverify outage', () => stubSiteverify('upstream down', 502)],
      ['a siteverify answer without a verdict', () => stubSiteverify({})],
      ['a rejected secret', () => stubSiteverify({ success: false, 'error-codes': ['invalid-input-secret'] })],
      ['a siteverify internal error', () => stubSiteverify({ success: false, 'error-codes': ['internal-error'] })],
      ['a network failure', () => {
        global.fetch = vi.fn().mockRejectedValue(new Error('connection reset')) as unknown as typeof fetch;
      }],
    ])('answers 503 and submits nothing after %s', async (_name, arrange) => {
      const intent = bindCoordinator();
      arrange();
      const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

      const response = await worker.fetch(signup({ 'cf-turnstile-response': 'token' }), mockEnv, mockCtx);

      expect(response.status).toBe(503);
      expect((await response.json() as Answer).status).toBe('challenge_unavailable');
      expect(intent).not.toHaveBeenCalled();
      expect(logged).toHaveBeenCalled();
      logged.mockRestore();
    });

    it('fails closed when enforcement is on and the secret is missing', async () => {
      const intent = bindCoordinator();
      delete (mockEnv as Env).TURNSTILE_SECRET;
      const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

      const response = await worker.fetch(signup({ 'cf-turnstile-response': 'token' }), mockEnv, mockCtx);

      expect(response.status).toBe(503);
      expect(intent).not.toHaveBeenCalled();
      logged.mockRestore();
    });

    it('lets the operator token stand in for the challenge', async () => {
      const intent = bindCoordinator();

      const response = await worker.fetch(signup({}, { Authorization: 'Bearer test_token' }), mockEnv, mockCtx);

      expect(response.status).toBe(200);
      expect(intentBody(intent)).toMatchObject({ authenticated: true, verified: true });
    });

    it('does not accept a wrong operator token in place of the challenge', async () => {
      const intent = bindCoordinator();

      const response = await worker.fetch(signup({}, { Authorization: 'Bearer wrong' }), mockEnv, mockCtx);

      expect(response.status).toBe(400);
      expect(intent).not.toHaveBeenCalled();
    });

    describe('with enforcement off', () => {
      beforeEach(() => {
        (mockEnv as Env).TURNSTILE = 'off';
      });

      it('accepts a signup without a token and marks it unverified', async () => {
        const intent = bindCoordinator();

        const response = await worker.fetch(signup({}), mockEnv, mockCtx);

        expect(response.status).toBe(200);
        expect(intentBody(intent)).toMatchObject({ authenticated: false, verified: false });
      });

      it('marks a signup verified when its token passes', async () => {
        const intent = bindCoordinator();
        stubSiteverify({ success: true });

        await worker.fetch(signup({ 'cf-turnstile-response': 'good-token' }), mockEnv, mockCtx);

        expect(intentBody(intent).verified).toBe(true);
      });

      it.each([
        ['fails', () => stubSiteverify({ success: false, 'error-codes': ['timeout-or-duplicate'] })],
        ['cannot be checked', () => stubSiteverify('upstream down', 502)],
      ])('still accepts a signup whose token %s, as unverified', async (_name, arrange) => {
        const intent = bindCoordinator();
        arrange();
        const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

        const response = await worker.fetch(signup({ 'cf-turnstile-response': 'token' }), mockEnv, mockCtx);

        expect(response.status).toBe(200);
        expect(intentBody(intent).verified).toBe(false);
        logged.mockRestore();
      });

      it('does not call siteverify without a secret', async () => {
        const intent = bindCoordinator();
        delete (mockEnv as Env).TURNSTILE_SECRET;

        const response = await worker.fetch(signup({ 'cf-turnstile-response': 'token' }), mockEnv, mockCtx);

        expect(response.status).toBe(200);
        expect(intentBody(intent).verified).toBe(false);
      });

      it('treats any value other than "on" as off', async () => {
        const intent = bindCoordinator();
        (mockEnv as Env).TURNSTILE = 'On';

        const response = await worker.fetch(signup({}), mockEnv, mockCtx);

        expect(response.status).toBe(200);
        expect(intent).toHaveBeenCalledTimes(1);
      });
    });

    it('stores the verdict on the record of a signup without a coordinator', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
      stubSiteverify({ success: true });

      const response = await worker.fetch(signup({ 'cf-turnstile-response': 'good-token' }), mockEnv, mockCtx);

      expect(response.status).toBe(200);
      const stored = mockEnv.NEWSLETTER_SUBSCRIBERS.put.mock.calls.find(call => call[0] === 'reader@example.com');
      expect(JSON.parse(stored![1] as string).verified).toBe(true);
    });
  });

  describe('Network evidence on the signup record', () => {
    // Node's Request has no `cf`; the edge attaches it.
    function signupFrom(cf: unknown): Request {
      const request = new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.8', 'User-Agent': 'evidence-agent' },
        body: JSON.stringify({ email: 'evidence@example.com' }),
      });
      if (cf !== undefined) Object.defineProperty(request, 'cf', { value: cf });
      return request;
    }

    function storedRecord(): Record<string, unknown> {
      const stored = mockEnv.NEWSLETTER_SUBSCRIBERS.put.mock.calls.find(call => call[0] === 'evidence@example.com');
      return JSON.parse(stored![1] as string);
    }

    beforeEach(() => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
    });

    it('stores the ASN and its organization next to the IP and user agent', async () => {
      await worker.fetch(signupFrom({ asn: 56971, asOrganization: 'Example Hosting Ltd' }), mockEnv, mockCtx);

      expect(storedRecord()).toMatchObject({
        ip: '203.0.113.8', userAgent: 'evidence-agent', asn: 56971, asOrganization: 'Example Hosting Ltd',
      });
    });

    it('passes the same evidence to the coordinator', async () => {
      const intent = vi.fn(async (_url: string, _init: RequestInit) =>
        new Response(JSON.stringify({ outcome: 'completed', created: true }), { status: 200 }));
      (mockEnv as Env).SUBSCRIPTION_COORDINATOR = {
        idFromName: (name: string) => name,
        get: () => ({ fetch: intent }),
      } as unknown as DurableObjectNamespace;

      await worker.fetch(signupFrom({ asn: 19318, asOrganization: 'Example Transit' }), mockEnv, mockCtx);

      expect(JSON.parse(String((intent.mock.calls[0][1] as RequestInit).body))).toMatchObject({
        ip: '203.0.113.8', userAgent: 'evidence-agent', asn: 19318, asOrganization: 'Example Transit',
      });
    });

    it.each([
      ['no cf object', undefined],
      ['an empty cf object', {}],
      ['values of the wrong type', { asn: 'AS56971', asOrganization: 42 }],
    ])('stores no network fields for %s', async (_name, cf) => {
      await worker.fetch(signupFrom(cf), mockEnv, mockCtx);

      const record = storedRecord();
      expect(record.ip).toBe('203.0.113.8');
      expect('asn' in record).toBe(false);
      expect('asOrganization' in record).toBe(false);
    });

    it('bounds the length of the organization name', async () => {
      await worker.fetch(signupFrom({ asn: 64500, asOrganization: 'x'.repeat(500) }), mockEnv, mockCtx);

      expect((storedRecord().asOrganization as string).length).toBe(200);
    });
  });

  describe('Coordinator mail after a signup', () => {
    const HOUR = 3_600_000;
    const EMAIL = 'coordinated@example.com';

    // In-memory stand-in for the Durable Object state. The workerd suite covers
    // the real scheduler; this only needs storage and the alarm slot.
    function fakeState() {
      const data = new Map<string, unknown>();
      let alarm: number | null = null;
      const state = {
        storage: {
          get: async (key: string) => data.get(key),
          put: async (key: string, value: unknown) => { data.set(key, value); },
          delete: async (key: string) => data.delete(key),
          setAlarm: async (at: number) => { alarm = at; },
          getAlarm: async () => alarm,
          deleteAlarm: async () => { alarm = null; },
        },
        blockConcurrencyWhile: async (work: () => Promise<void>) => work(),
      } as unknown as DurableObjectState;
      return { state, data, alarm: () => alarm };
    }

    // Listmonk answers the lookup from `subscriber` and accepts everything else.
    function stubListmonk(subscriber: unknown = null): ReturnType<typeof vi.fn> {
      const f = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).includes('/api/subscribers?query=') && (init?.method ?? 'GET') === 'GET') {
          const results = subscriber ? [subscriber] : [];
          return new Response(JSON.stringify({ data: { results, total: results.length } }), { status: 200 });
        }
        return new Response('{}', { status: 200 });
      });
      global.fetch = f as unknown as typeof fetch;
      return f;
    }

    const callsTo = (f: ReturnType<typeof vi.fn>, method: string, path: RegExp): number =>
      (f.mock.calls as Array<[RequestInfo | URL, RequestInit | undefined]>)
        .filter(([input, init]) => (init?.method ?? 'GET') === method && path.test(new URL(String(input)).pathname)).length;

    async function submit(coordinator: SubscriptionCoordinator, verified: boolean): Promise<Record<string, unknown>> {
      const response = await coordinator.fetch(new Request('https://coordinator/intent', {
        method: 'POST',
        body: JSON.stringify({ desired: 'subscribed', email: EMAIL, ip: '203.0.113.9', userAgent: 'test', verified }),
      }));
      return await response.json() as Record<string, unknown>;
    }

    beforeEach(() => {
      (mockEnv as Env).DOUBLE_OPTIN = 'on';
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
    });

    it('arms the 48-hour reminder for a signup that passed the challenge', async () => {
      const { state, data, alarm } = fakeState();
      const listmonk = stubListmonk();
      const before = Date.now();

      const result = await submit(new SubscriptionCoordinator(state, mockEnv), true);

      expect(result).toMatchObject({ outcome: 'completed', created: true, awaitingConfirmation: true });
      expect(callsTo(listmonk, 'POST', /^\/api\/subscribers$/)).toBe(1);
      const due = data.get('optin-reminder-at') as number;
      expect(Math.abs(due - before - 48 * HOUR)).toBeLessThan(5000);
      expect(alarm()).toBe(due);
    });

    it('arms no reminder and leaves no alarm for a signup without a passed challenge', async () => {
      const { state, data, alarm } = fakeState();
      const listmonk = stubListmonk();

      const result = await submit(new SubscriptionCoordinator(state, mockEnv), false);

      // The create still happens, so Listmonk mails the opt-in link once.
      expect(result).toMatchObject({ outcome: 'completed', created: true, awaitingConfirmation: true });
      expect(callsTo(listmonk, 'POST', /^\/api\/subscribers$/)).toBe(1);
      expect(data.has('optin-reminder-at')).toBe(false);
      expect(alarm()).toBeNull();
    });

    describe('for an address whose link is still unclicked', () => {
      const pending = { id: 4242, email: EMAIL, status: 'enabled', lists: [{ id: 3, subscription_status: 'unconfirmed' }] };

      it('resends the opt-in for a caller that passed the challenge', async () => {
        const listmonk = stubListmonk(pending);

        const result = await submit(new SubscriptionCoordinator(fakeState().state, mockEnv), true);

        expect(result).toMatchObject({ outcome: 'completed', created: false, awaitingConfirmation: true });
        expect(callsTo(listmonk, 'POST', /^\/api\/subscribers\/4242\/optin$/)).toBe(1);
      });

      it('gives an unverified caller the same answer and sends nothing', async () => {
        const listmonk = stubListmonk(pending);
        const { state, data } = fakeState();
        // The resend window is open, so only the caller decides.
        data.set('optin-resent-at', Date.now() - 25 * HOUR);

        const result = await submit(new SubscriptionCoordinator(state, mockEnv), false);

        expect(result).toMatchObject({ outcome: 'completed', created: false, awaitingConfirmation: true });
        expect(callsTo(listmonk, 'POST', /optin$/)).toBe(0);
        expect(callsTo(listmonk, 'POST', /^\/api\/subscribers$/)).toBe(0);
      });
    });

    it('drops a reminder an earlier signup armed when an unverified signup recreates the address', async () => {
      const { state, data, alarm } = fakeState();
      stubListmonk();
      data.set('optin-reminder-at', Date.now() + 47 * HOUR);

      await submit(new SubscriptionCoordinator(state, mockEnv), false);

      expect(data.has('optin-reminder-at')).toBe(false);
      expect(alarm()).toBeNull();
    });
  });

  describe('GET /api/signup-stats', () => {
    const HOUR = 3_600_000;
    type Signup = { hoursAgo: number; ip?: string; userAgent?: string; asn?: number; asOrganization?: string; verified?: boolean };
    type Report = {
      records: number;
      undated: number;
      windows: Record<'24h' | '7d', {
        signups: number;
        unverified: number;
        byIp: Array<{ ip: string; count: number }>;
        byAsn: Array<{ asn: number | null; asOrganization: string | null; count: number }>;
        byUserAgent: Array<{ userAgent: string; count: number }>;
      }>;
      alert: { triggered: boolean; reasons: Array<Record<string, unknown>>; thresholds: Record<string, number> };
    };

    // One record per address, each from its own IP and user agent unless told otherwise.
    function records(signups: Signup[]): Record<string, string> {
      return Object.fromEntries(signups.map(({ hoursAgo, ...rest }, i) => [
        `reader${i}@example.com`,
        JSON.stringify({
          timestamp: new Date(Date.now() - hoursAgo * HOUR).toISOString(),
          ip: `198.51.100.${i}`,
          userAgent: `agent-${i}`,
          seq: i,
          ...rest,
        }),
      ]));
    }

    function serveKv(store: Record<string, string | null>, pageSize = 1000): void {
      const names = Object.keys(store);
      mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockImplementation(async ({ cursor }: { cursor?: string } = {}) => {
        const start = cursor ? Number(cursor) : 0;
        const end = start + pageSize;
        return {
          keys: names.slice(start, end).map(name => ({ name })),
          list_complete: end >= names.length,
          cursor: end >= names.length ? undefined : String(end),
        };
      });
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockImplementation(async (keys: string[]) =>
        new Map(keys.map(key => [key, store[key] ?? null])));
    }

    async function report(headers: Record<string, string> = { Authorization: 'Bearer test_token' }): Promise<Response> {
      return worker.fetch(new Request('https://api.example.com/api/signup-stats', { headers }), mockEnv, mockCtx);
    }

    const distinct = (count: number, hoursAgo = 1): Signup[] => Array.from({ length: count }, () => ({ hoursAgo }));

    it.each([
      ['no token', {}],
      ['a wrong token', { Authorization: 'Bearer wrong' }],
    ])('refuses %s without reading KV', async (_name, headers) => {
      const response = await report(headers as Record<string, string>);

      expect(response.status).toBe(401);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.list).not.toHaveBeenCalled();
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.get).not.toHaveBeenCalled();
    });

    it('counts signups per window, IP, ASN and user agent', async () => {
      const hosting = { asn: 56971, asOrganization: 'Example Hosting Ltd' };
      serveKv({
        ...records([
          { hoursAgo: 1, ip: '203.0.113.5', userAgent: 'Chrome/124', ...hosting, verified: false },
          { hoursAgo: 2, ip: '203.0.113.5', userAgent: 'Chrome/124', ...hosting, verified: false },
          { hoursAgo: 23, ip: '203.0.113.6', userAgent: 'Firefox/130', asn: 3303, asOrganization: 'Example Access', verified: true },
          { hoursAgo: 25, ip: '203.0.113.5', userAgent: 'Chrome/124', ...hosting },
          { hoursAgo: 6 * 24, ip: '203.0.113.7', userAgent: 'Safari/18' },
          { hoursAgo: 8 * 24, ip: '203.0.113.8', userAgent: 'old' },
        ]),
        'rate_limit:203.0.113.5': '{"count":1,"resetAt":0}',
        'cache:subscriber_count': '{"count":10,"display":"10+"}',
        'intent:fence:reader@example.com': '{"desired":"unsubscribed"}',
      });

      const response = await report();
      const text = await response.text();
      const body = JSON.parse(text) as Report;

      expect(response.status).toBe(200);
      expect(response.headers.get('Cache-Control')).toBe('no-store');
      expect(body.records).toBe(6);
      expect(body.undated).toBe(0);
      expect(body.windows['24h']).toEqual({
        signups: 3,
        unverified: 2,
        byIp: [{ ip: '203.0.113.5', count: 2 }, { ip: '203.0.113.6', count: 1 }],
        byAsn: [{ ...hosting, count: 2 }, { asn: 3303, asOrganization: 'Example Access', count: 1 }],
        byUserAgent: [{ userAgent: 'Chrome/124', count: 2 }, { userAgent: 'Firefox/130', count: 1 }],
      });
      expect(body.windows['7d'].signups).toBe(5);
      expect(body.windows['7d'].unverified).toBe(4);
      expect(body.windows['7d'].byIp[0]).toEqual({ ip: '203.0.113.5', count: 3 });
      expect(body.windows['7d'].byAsn).toEqual([
        { ...hosting, count: 3 },
        { asn: 3303, asOrganization: 'Example Access', count: 1 },
        { asn: null, asOrganization: null, count: 1 },
      ]);
      expect(body.alert.thresholds).toEqual({ signups24h: 10, repeat24h: 3 });
      // The report is evidence about traffic, not a subscriber export.
      expect(text).not.toContain('@example.com');
    });

    it.each([
      ['ten signups from ten sources', distinct(10), []],
      ['eleven signups from eleven sources', distinct(11), [{ rule: 'signups_24h', count: 11 }]],
      ['two signups from one IP', [{ hoursAgo: 1, ip: '203.0.113.5' }, { hoursAgo: 2, ip: '203.0.113.5' }], []],
      ['three signups from one IP',
        [1, 2, 3].map(hoursAgo => ({ hoursAgo, ip: '203.0.113.5' })),
        [{ rule: 'ip_24h', ip: '203.0.113.5', count: 3 }]],
      ['three signups with one user agent from three IPs',
        [1, 2, 3].map(hoursAgo => ({ hoursAgo, userAgent: 'Chrome/124.0.0.0' })),
        [{ rule: 'user_agent_24h', userAgent: 'Chrome/124.0.0.0', count: 3 }]],
      ['three signups from one IP, one of them older than a day',
        [1, 2, 25].map(hoursAgo => ({ hoursAgo, ip: '203.0.113.5' })), []],
      ['a spike that ended more than a day ago', distinct(20, 30), []],
    ] as Array<[string, Signup[], Array<Record<string, unknown>>]>)('alert for %s', async (_name, signups, reasons) => {
      serveKv(records(signups));

      const body = await (await report()).json() as Report;

      expect(body.alert.reasons).toEqual(reasons);
      expect(body.alert.triggered).toBe(reasons.length > 0);
    });

    it('names every rule that fired', async () => {
      serveKv(records(Array.from({ length: 12 }, (_, i) => ({ hoursAgo: 1, ip: i < 4 ? '203.0.113.5' : `198.51.100.${i}`, userAgent: 'Chrome/124' }))));

      const body = await (await report()).json() as Report;

      expect(body.alert.triggered).toBe(true);
      expect(body.alert.reasons).toEqual([
        { rule: 'signups_24h', count: 12 },
        { rule: 'ip_24h', ip: '203.0.113.5', count: 4 },
        { rule: 'user_agent_24h', userAgent: 'Chrome/124', count: 12 },
      ]);
    });

    it('follows the listing cursor and reads values 100 at a time', async () => {
      serveKv(records(distinct(250, 48)), 120);

      const body = await (await report()).json() as Report;

      expect(body.records).toBe(250);
      expect(body.windows['7d'].signups).toBe(250);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.list).toHaveBeenCalledTimes(3);
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.get.mock.calls.map(call => (call[0] as string[]).length)).toEqual([100, 100, 50]);
    });

    it('bounds each breakdown but raises the alert from all rows', async () => {
      const busy = [1, 2, 3].map(hoursAgo => ({ hoursAgo, ip: '203.0.113.5', userAgent: `busy-${hoursAgo}` }));
      serveKv(records([...distinct(60), ...busy]));

      const body = await (await report()).json() as Report;

      expect(body.windows['24h'].signups).toBe(63);
      expect(body.windows['24h'].byIp).toHaveLength(50);
      expect(body.windows['24h'].byIp[0]).toEqual({ ip: '203.0.113.5', count: 3 });
      expect(body.windows['24h'].byUserAgent).toHaveLength(50);
      expect(body.alert.reasons).toContainEqual({ rule: 'ip_24h', ip: '203.0.113.5', count: 3 });
    });

    it('counts a record it cannot date instead of dropping or dating it', async () => {
      serveKv({
        ...records(distinct(2)),
        'broken@example.com': '{not json',
        'legacy@example.com': JSON.stringify({ ip: '203.0.113.9', userAgent: 'legacy' }),
        'vanished@example.com': null,
      });

      const body = await (await report()).json() as Report;

      expect(body.records).toBe(5);
      expect(body.undated).toBe(2);
      expect(body.windows['7d'].signups).toBe(2);
    });

    it.each([
      ['the listing', () => mockEnv.NEWSLETTER_SUBSCRIBERS.list.mockRejectedValue(new Error('kv down'))],
      ['a value read', () => mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockRejectedValue(new Error('kv down'))],
    ])('answers 500 rather than an empty report when %s fails', async (_name, breakKv) => {
      serveKv(records(distinct(3)));
      breakKv();
      const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

      const response = await report();

      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({ error: 'Signup report unavailable' });
      logged.mockRestore();
    });
  });

  describe('Listmonk reconciliation (audit item 35)', () => {
    const recordJson = (seq: number): string =>
      JSON.stringify({ timestamp: '2026-01-01T00:00:00Z', ip: '1.2.3.4', userAgent: 'test', seq });

    function stubFetch(subscribersStatus = 200, subscribersBody = '{}'): ReturnType<typeof vi.fn> {
      const f = vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/api/subscribers')) {
          return Promise.resolve(new Response(subscribersBody, { status: subscribersStatus }));
        }
        return Promise.resolve(new Response('{}', { status: 200 }));
      });
      global.fetch = f as unknown as typeof fetch;
      return f;
    }

    const urlsOf = (f: ReturnType<typeof vi.fn>): string[] =>
      (f.mock.calls as Array<Array<RequestInfo | URL>>).map(call => String(call[0]));

    it('skips Listmonk when the record was removed (slow signup after unsubscribe)', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(null);
      const f = stubFetch();
      await reconcileSignup('late@example.com', 123, '1.2.3.4', mockEnv as unknown as EnvLike, { welcome: true });
      expect(f).not.toHaveBeenCalled();
    });

    it('treats 409 as an existing subscriber without reactivating or resending the welcome', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(recordJson(7));
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
      const f = stubFetch(409);
      await reconcileSignup('dup@example.com', 7, '1.2.3.4', mockEnv as unknown as EnvLike, { welcome: true });
      const urls = urlsOf(f);
      expect(urls.filter(u => u.includes('mail.example.com')).length).toBe(1); // create only
      expect(urls.some(u => u.includes('useplunk.com'))).toBe(false);         // no welcome on duplicate
    });

    it('treats a 500 whose body mentions "duplicate" as a real failure (Plunk fallback)', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(recordJson(8));
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
      const f = stubFetch(500, '{"error":"duplicate conflict"}');
      await reconcileSignup('faildup@example.com', 8, '1.2.3.4', mockEnv as unknown as EnvLike, { welcome: true });
      const urls = urlsOf(f);
      expect(urls.filter(u => u.includes('mail.example.com')).length).toBe(1); // failed create only
      expect(urls.some(u => u.includes('useplunk.com'))).toBe(true);          // fallback welcome
    });

    it('sends the welcome through Listmonk tx after a successful create', async () => {
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(recordJson(9));
      mockEnv.NEWSLETTER_SUBSCRIBERS.put.mockResolvedValue(undefined);
      const f = stubFetch(200);
      await reconcileSignup('ok@example.com', 9, '1.2.3.4', mockEnv as unknown as EnvLike, { welcome: true });
      const urls = urlsOf(f);
      expect(urls.filter(u => u.includes('/api/tx')).length).toBe(1);
      expect(urls.some(u => u.includes('useplunk.com'))).toBe(false);
    });

    it('does not rewrite a checked record to KV after reconciliation', async () => {
      // A check-then-put here could restore a record deleted between those two
      // operations, even when both reads still see the same intent.
      mockEnv.NEWSLETTER_SUBSCRIBERS.get.mockResolvedValue(recordJson(5));
      const f = stubFetch(200);
      await reconcileSignup('race@example.com', 5, '1.2.3.4', mockEnv as unknown as EnvLike, { welcome: false });
      expect(f).toHaveBeenCalled();
      expect(mockEnv.NEWSLETTER_SUBSCRIBERS.put).not.toHaveBeenCalled();
    });
  });
});

describe('Email Validation', () => {
  // Testing the email regex pattern
  const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

  const validEmails = [
    'test@example.com',
    'user.name@domain.com',
    'user+tag@example.org',
    'a@b.co',
    'test123@test123.com',
  ];

  const invalidEmails = [
    '',
    'invalid',
    '@example.com',
    'test@',
    'test@.com',
    'test@com',
    'test@@example.com',
  ];

  validEmails.forEach((email) => {
    it(`should accept valid email: ${email}`, () => {
      expect(EMAIL_REGEX.test(email)).toBe(true);
    });
  });

  invalidEmails.forEach((email) => {
    it(`should reject invalid email: ${email}`, () => {
      expect(EMAIL_REGEX.test(email)).toBe(false);
    });
  });
});
