import { describe, it, expect, vi, beforeEach } from 'vitest';

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
  RESEND_API_KEY: string;
  ADMIN_TOKEN: string;
  ENVIRONMENT: string;
}

// Import the worker
import worker from './index';

describe('Newsletter API', () => {
  let mockEnv: MockEnv;
  let mockCtx: ExecutionContext;

  beforeEach(() => {
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
      RESEND_API_KEY: 'test_api_key',
      ADMIN_TOKEN: 'test_token',
      ENVIRONMENT: 'development',
    };

    mockCtx = {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn(),
    } as unknown as ExecutionContext;

    vi.clearAllMocks();
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
    it('should unsubscribe a valid email', async () => {
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
      const body = await response.json() as { success: boolean; message: string };

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.message).toBe('Unsubscribed successfully');
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

      expect(response.status).toBe(200);
      expect(body.count).toBe(2); // excludes rate_limit key
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

    it('should allow with valid auth token', async () => {
      mockEnv.ENVIRONMENT = 'production';
      
      // Mock fetch for Resend API
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{}'),
      });

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
