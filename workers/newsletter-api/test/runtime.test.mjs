// Runtime integration suite.
//
// The unit tests in src/*.test.ts run under Node with mocked KV, R2 and fetch.
// This suite runs the same Worker in the real workerd runtime through
// `unstable_startWorker`, so bindings, request/response objects and the body
// parser behave as they do in production. It complements the unit tests
// instead of replacing them.
//
// Two properties make it safe to run anywhere:
//
//   * `dev.persist: false` gives each run a fresh, throwaway KV and R2. Nothing
//     is written under `.wrangler/state`, and no real namespace is reachable.
//   * outbound networking is denied. `disableNetConnect()` makes every
//     non-intercepted connection throw, so a provider call cannot silently
//     reach the internet, and the Listmonk interceptor below asserts that the
//     unconfigured development Worker never attempts one at all.
//
// The Worker is started once per file; each test uses its own client IP so the
// per-IP rate limit cannot couple unrelated cases.

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from 'undici';
import { unstable_startWorker } from 'wrangler';

// A test-only value. The Worker reads UNSUBSCRIBE_HMAC_SECRET from its bindings;
// injecting it here lets the signed-token paths be exercised without secrets.
const HMAC_SECRET = 'runtime-suite-hmac-secret-not-a-production-value';
const ALLOWED_ORIGIN = 'http://localhost:1313';

// Mirrors MAX_REQUEST_SIZE in src/index.ts.
const MAX_BODY = 1024;

let worker;
let agent;
let previousDispatcher;
let listmonkCalls = 0;
let ipCounter = 0;

function nextIP() {
  ipCounter += 1;
  // TEST-NET-2, which never routes.
  return `198.51.100.${ipCounter}`;
}

function tokenFor(email) {
  return `v1:${createHmac('sha256', HMAC_SECRET).update(email).digest('hex')}`;
}

function send(path, init = {}) {
  const headers = new Headers(init.headers);
  headers.set('CF-Connecting-IP', init.ip ?? nextIP());
  return worker.fetch(`http://localhost${path}`, { ...init, headers });
}

function subscribe(email, extra = {}) {
  return send('/api/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, ...extra }),
  });
}

before(async () => {
  agent = new MockAgent();
  agent.disableNetConnect();
  // Records any attempt to reach the Listmonk host. The development
  // configuration has no provider URL, so this must stay at zero.
  agent
    .get('https://mail.philippdubach.com')
    .intercept({ path: () => true, method: () => true })
    .reply(200, () => {
      listmonkCalls += 1;
      return '{}';
    })
    .persist();

  previousDispatcher = getGlobalDispatcher();
  setGlobalDispatcher(agent);

  worker = await unstable_startWorker({
    config: 'wrangler.toml',
    logLevel: 'error',
    bindings: {
      UNSUBSCRIBE_HMAC_SECRET: { type: 'plain_text', value: HMAC_SECRET },
    },
    dev: {
      persist: false,
      mockFetch: agent,
      // The development Worker reports "Listmonk not configured" and
      // "PLUNK_SECRET_KEY not configured" for every accepted signup. Those are
      // the expected dev behaviour and not test failures, so they are dropped;
      // anything else still reaches the terminal.
      structuredLogsHandler: (log) => {
        const message = String(log?.message ?? JSON.stringify(log));
        if (/not configured/i.test(message)) return;
        console.error(message);
      },
    },
  });
});

after(async () => {
  if (worker) await worker.dispose();
  if (previousDispatcher) setGlobalDispatcher(previousDispatcher);
  if (agent) await agent.close();
});

describe('health', () => {
  it('serves a health response from the runtime', async () => {
    const response = await send('/api/health');
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /application\/json/);
    const body = await response.json();
    assert.equal(body.status, 'ok');
    assert.equal(typeof body.timestamp, 'string');
  });
});

describe('subscribe', () => {
  it('accepts a first subscription and records it in KV', async () => {
    const response = await subscribe('runtime-first@example.com');
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.success, true);
    assert.equal(body.message, 'Subscribed successfully');

    // A second request reads the record back through the real KV binding.
    const duplicate = await subscribe('runtime-first@example.com');
    assert.equal(duplicate.status, 200);
    assert.equal((await duplicate.json()).message, 'Already subscribed');
  });

  it('rejects a malformed JSON body as a client error', async () => {
    const response = await send('/api/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"email":',
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).success, false);
  });

  it('rejects a body larger than the accepted size', async () => {
    const response = await send('/api/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'runtime-large@example.com', padding: 'x'.repeat(4096) }),
    });
    assert.equal(response.status, 413);
    assert.equal((await response.json()).error, 'Request too large');
  });

  it('rejects a submission that fills the honeypot', async () => {
    const response = await subscribe('runtime-bot@example.com', { honeypot: 'filled' });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).success, false);
  });

  it('rejects an invalid address', async () => {
    const response = await subscribe('not-an-address');
    assert.equal(response.status, 400);
  });
});

describe('unsubscribe', () => {
  it('refuses an unauthenticated request and leaves KV untouched', async () => {
    const email = 'runtime-guard@example.com';
    assert.equal((await subscribe(email)).status, 200);

    const refused = await send('/api/unsubscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    assert.equal(refused.status, 403);
    assert.match((await refused.json()).error, /token/i);

    // The record still exists, which the duplicate path can only answer.
    const again = await subscribe(email);
    assert.equal((await again.json()).message, 'Already subscribed');
  });

  it('fails closed when the provider is not configured', async () => {
    const email = 'runtime-unconfigured@example.com';
    assert.equal((await subscribe(email)).status, 200);

    const response = await send('/api/unsubscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, token: tokenFor(email) }),
    });
    assert.equal(response.status, 502);
    const body = await response.json();
    assert.equal(body.success, false);
    assert.match(body.error, /unavailable/i);
  });

  it('does not mutate on a GET with a bad token', async () => {
    const email = 'runtime-get@example.com';
    assert.equal((await subscribe(email)).status, 200);

    const response = await send(`/api/unsubscribe?email=${encodeURIComponent(email)}&token=v1:deadbeef`);
    assert.equal(response.status, 403);
    assert.match(response.headers.get('content-security-policy') ?? '', /form-action 'self'/);

    const again = await subscribe(email);
    assert.equal((await again.json()).message, 'Already subscribed');
  });

  it('renders a confirmation form for a signed GET without removing anything', async () => {
    const email = 'runtime-confirm@example.com';
    assert.equal((await subscribe(email)).status, 200);

    const response = await send(
      `/api/unsubscribe?email=${encodeURIComponent(email)}&token=${encodeURIComponent(tokenFor(email))}`,
    );
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /action="\/api\/unsubscribe\/confirm"/);
    assert.match(html, /method="post"/);

    const again = await subscribe(email);
    assert.equal((await again.json()).message, 'Already subscribed');
  });

  it('accepts the form post that the confirmation page sends', async () => {
    const email = 'runtime-form@example.com';
    assert.equal((await subscribe(email)).status, 200);

    const response = await send('/api/unsubscribe/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email, token: tokenFor(email) }).toString(),
    });
    // The provider is unconfigured, so the request is refused rather than
    // reported as a completed removal.
    assert.equal(response.status, 502);
    assert.match(response.headers.get('content-type') ?? '', /text\/html/);
  });
});

describe('isolation', () => {
  it('answers a preflight for the configured origin only', async () => {
    const allowed = await send('/api/subscribe', {
      method: 'OPTIONS',
      headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'POST' },
    });
    assert.equal(allowed.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);

    const foreign = await send('/api/subscribe', {
      method: 'OPTIONS',
      headers: { Origin: 'https://attacker.example', 'Access-Control-Request-Method': 'POST' },
    });
    assert.notEqual(foreign.headers.get('access-control-allow-origin'), 'https://attacker.example');
  });

  it('never contacted the provider during the suite', () => {
    // Belt and braces: networking is disabled outright, and the interceptor
    // above would have recorded any attempt that somehow got through.
    assert.equal(listmonkCalls, 0);
  });
});
