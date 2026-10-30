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
import worker, { reconcileSignup, type Env } from './index';

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

    it('should handle already subscribed email', async () => {
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
