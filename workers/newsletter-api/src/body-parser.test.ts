import { describe, it, expect } from 'vitest';
import { readBody } from './index';

describe('readBody — bounded-byte stream body parser', () => {
  const MAX = 1024;

  function makeRequest(body: BodyInit, contentType?: string): Request {
    const headers: Record<string, string> = {};
    if (contentType) headers['Content-Type'] = contentType;
    return new Request('https://api.example.com/api/subscribe', {
      method: 'POST',
      headers,
      body,
    });
  }

  it('parses a valid JSON body', async () => {
    const result = await readBody(
      makeRequest(JSON.stringify({ email: 'test@example.com' }), 'application/json'),
    );
    expect(result.ok).toBe(true);
    expect((result as { ok: true; body: { email?: string } }).body.email).toBe('test@example.com');
  });

  it('parses a valid URL-encoded form body', async () => {
    const result = await readBody(
      makeRequest('email=form%40example.com', 'application/x-www-form-urlencoded'),
    );
    expect(result.ok).toBe(true);
    expect((result as { ok: true; body: { email?: string } }).body.email).toBe('form@example.com');
  });

  it('parses a JSON body with no Content-Type header', async () => {
    const result = await readBody(
      makeRequest(JSON.stringify({ email: 'test@example.com' })),
    );
    expect(result.ok).toBe(true);
    expect((result as { ok: true; body: { email?: string } }).body.email).toBe('test@example.com');
  });

  it('rejects a body larger than 1024 bytes with 413', async () => {
    const oversized = 'x'.repeat(MAX + 1);
    const result = await readBody(makeRequest(oversized, 'application/json'));
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(413);
  });

  it('rejects an overlong UTF-8 sequence with 400', async () => {
    // C0 80 is an overlong encoding of U+0000 (should be a single byte 0x00).
    const overlongBytes = new Uint8Array([0xc0, 0x80]);
    const result = await readBody(makeRequest(overlongBytes));
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects a misleading Content-Length (declared larger than actual) with 400', async () => {
    const body = 'email=test%40example.com';
    const request = new Request('https://api.example.com/api/subscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '5',
      },
      body,
    });
    const result = await readBody(request);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
    expect((result as { ok: false; error: string }).error).toBe('Content-Length mismatch');
  });

  it('rejects a misleading Content-Length (declared smaller than actual) with 400', async () => {
    const body = 'email=test%40example.com';
    const request = new Request('https://api.example.com/api/subscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '1',
      },
      body,
    });
    const result = await readBody(request);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
    expect((result as { ok: false; error: string }).error).toBe('Content-Length mismatch');
  });

  it('accepts a body when Content-Length matches actual size', async () => {
    const body = JSON.stringify({ email: 'test@example.com' });
    const request = new Request('https://api.example.com/api/subscribe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(body.length),
      },
      body,
    });
    const result = await readBody(request);
    expect(result.ok).toBe(true);
  });

  it('rejects malformed explicit JSON without interpreting it as a form', async () => {
    const result = await readBody(makeRequest('{not json', 'application/json'));
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects malformed Content-Length values', async () => {
    for (const value of ['5junk', '-1', '1, 1', '9007199254740992']) {
      const request = new Request('https://api.example.com/', {
        method: 'POST', headers: { 'Content-Length': value }, body: 'email=x',
      });
      const result = await readBody(request);
      expect(result.ok).toBe(false);
      expect((result as { ok: false; status: number }).status).toBe(400);
    }
  });

  it('limits UTF-8 bytes rather than JavaScript characters', async () => {
    const result = await readBody(makeRequest('é'.repeat(513), 'text/plain'));
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(413);
  });

  it('cancels an oversized stream rather than waiting for it to finish', async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(1025)); },
      cancel() { cancelled = true; },
    });
    const request = new Request('https://api.example.com/', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: stream, duplex: 'half',
    } as RequestInit & { duplex: 'half' });
    const result = await readBody(request);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(413);
    expect(cancelled).toBe(true);
  });

  it('rejects a non-string email field in JSON with 400', async () => {
    const result = await readBody(
      makeRequest(JSON.stringify({ email: 123 }), 'application/json'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects a non-string token field in JSON with 400', async () => {
    const result = await readBody(
      makeRequest(JSON.stringify({ token: true }), 'application/json'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects a non-string honeypot field in JSON with 400', async () => {
    const result = await readBody(
      makeRequest(JSON.stringify({ honeypot: 42 }), 'application/json'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects an unsupported content type with 415', async () => {
    const result = await readBody(
      makeRequest('raw body', 'application/xml'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(415);
  });

  it('rejects a request with no body stream with 400', async () => {
    const result = await readBody(
      new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('handles a stream error (cancellation) gracefully with 400', async () => {
    const errorStream = new ReadableStream({
      start(controller) {
        controller.error(new Error('Stream cancelled'));
      },
    });
    const result = await readBody(
      new Request('https://api.example.com/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: errorStream,
        duplex: 'half',
      } as RequestInit & { duplex: 'half' }),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('does not make any upstream calls during body parsing', async () => {
    let fetchCalled = false;
    const originalFetch = global.fetch;
    global.fetch = (() => {
      fetchCalled = true;
      return Promise.resolve(new Response('{}'));
    }) as unknown as typeof fetch;

    try {
      const result = await readBody(
        makeRequest(JSON.stringify({ email: 'test@example.com' }), 'application/json'),
      );
      expect(result.ok).toBe(true);
      expect(fetchCalled).toBe(false);
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('rejects an empty JSON body (not an object) with 400', async () => {
    const result = await readBody(
      makeRequest('"hello"', 'application/json'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('rejects null JSON body with 400', async () => {
    const result = await readBody(
      makeRequest('null', 'application/json'),
    );
    expect(result.ok).toBe(false);
    expect((result as { ok: false; status: number }).status).toBe(400);
  });

  it('accepts a URL-encoded form body with no Content-Type', async () => {
    const result = await readBody(
      makeRequest('email=form%40example.com'),
    );
    expect(result.ok).toBe(true);
    expect((result as { ok: true; body: { email?: string } }).body.email).toBe('form@example.com');
  });
});
