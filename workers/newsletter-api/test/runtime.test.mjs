// Runtime integration suite.
//
// The unit tests in src/*.test.ts run under Node with mocked KV, R2 and fetch.
// This suite runs the same Worker in workerd through Miniflare, so bindings,
// request/response objects and the body parser behave as they do in production.
// It complements the unit tests instead of replacing them.
//
// Isolation is proven, not assumed:
//
//   * the deploy-configuration guard runs before workerd starts, so a
//     dangerous wrangler.toml aborts the suite even when it is invoked directly;
//   * bindings are supplied by the harness, so `.dev.vars` and `.env` are never
//     read — asserted behaviourally by the CORS test below;
//   * outbound traffic is wired through `outboundService`, and a positive
//     control makes the Worker fetch a URL and asserts the guard saw it, which
//     is what shows the guard is on the path at all;
//   * the provider-attempt assertion runs in the file-level `after` hook, once
//     every test has finished and ctx.waitUntil work has been drained through
//     a harness-only wrapper entry (see harness.mjs); dispose always runs.
//
// The Worker is started once per file; each test uses its own client IP so the
// per-IP rate limit cannot couple unrelated cases.

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkConfig, loadConfig } from '../scripts/check-deploy-config.mjs';
import { EGRESS_PROBE_HOST, TEST_BINDINGS, startRuntime } from './harness.mjs';

const workerDir = join(dirname(fileURLToPath(import.meta.url)), '..');

// A test-only value. The Worker reads UNSUBSCRIBE_HMAC_SECRET from its bindings;
// injecting it here lets the signed-token paths be exercised without secrets.
const HMAC_SECRET = TEST_BINDINGS.UNSUBSCRIBE_HMAC_SECRET;

// The origin the harness supplies, which is not the one in wrangler.toml.
const ALLOWED_ORIGIN = TEST_BINDINGS.ALLOWED_ORIGIN;

// Mirrors MAX_REQUEST_SIZE in src/index.ts.
const MAX_BODY = 1024;

let runtime;
let attempts;
let dispose;
let drain;
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
  return runtime.dispatchFetch(`http://localhost${path}`, { ...init, headers });
}

// With no provider configured the Worker declines to claim a subscription for
// an address it already holds, so `status: 'unverified'` is the signal that the
// KV record survived. It is a stronger presence proof than the old message,
// which asserted provider state the Worker had never checked.
function assertRecordPresent(body) {
  assert.equal(body.success, false);
  assert.equal(body.status, 'unverified');
}

function subscribe(email, extra = {}) {
  return send('/api/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, ...extra }),
  });
}

before(async () => {
  // Blocked here so a directly-invoked `npm run test:runtime` cannot initialise
  // workerd against an unsafe configuration. `verify` also runs it first.
  const errors = checkConfig(loadConfig(join(workerDir, 'wrangler.toml')));
  if (errors.length > 0) {
    throw new Error(`refusing to start workerd against an unsafe configuration:\n- ${errors.join('\n- ')}`);
  }

  ({ runtime, attempts, dispose, drain } = await startRuntime());
});

after(async () => {
  if (!dispose) return;
  try {
    // Background work (ctx.waitUntil) may still be running when the last test
    // returns, so settle it before judging what left the Worker.
    await drain();
    const providers = attempts.filter((host) => host !== EGRESS_PROBE_HOST);
    assert.deepEqual(providers, [], 'the Worker reached a provider host during the suite');
  } finally {
    await dispose();
  }
});

describe('egress guard', () => {
  it('intercepts a Worker-originated fetch and denies it', async () => {
    // `/api/subscriber-count` fetches the LinkedIn URLs from its bindings, so
    // this is a real outbound request from inside the Worker under test. If the
    // guard were not wired, the reserved-TLD host would fail to resolve and the
    // attempt would never be recorded.
    assert.equal(attempts.length, 0, 'the guard saw traffic before the control ran');

    const response = await send('/api/subscriber-count');
    assert.equal(response.status, 200);

    assert.ok(
      attempts.includes(EGRESS_PROBE_HOST),
      `expected the guard to see ${EGRESS_PROBE_HOST}, saw ${JSON.stringify(attempts)}`,
    );
  });
});

describe('background work drain', () => {
  it('catches delayed egress that happens after the response', async () => {
    const fixture = await startRuntime({ entry: join(workerDir, 'test/fixtures/delayed-egress-worker.mjs') });
    try {
      const response = await fixture.runtime.dispatchFetch('http://localhost/');
      assert.equal(response.status, 200);
      assert.equal(await fixture.drain(), 1);
      assert.deepEqual(fixture.attempts, ['delayed-provider.runtime-suite.invalid']);
    } finally {
      await fixture.dispose();
    }
  });

  it('settles with nothing to drain', async () => {
    assert.equal(typeof (await drain()), 'number');
  });
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
    assertRecordPresent(await duplicate.json());
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
      body: JSON.stringify({ email: 'runtime-large@example.com', padding: 'x'.repeat(MAX_BODY * 4) }),
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
    assertRecordPresent(await again.json());
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
    assertRecordPresent(await again.json());
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
    assertRecordPresent(await again.json());
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
  it('uses the bindings the harness supplies, not the configuration file', async () => {
    // wrangler.toml allows http://localhost:1313. Echoing the harness origin
    // proves no configuration file, and therefore no `.dev.vars`, was read.
    const allowed = await send('/api/subscribe', {
      method: 'OPTIONS',
      headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'POST' },
    });
    assert.equal(allowed.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);
  });

  it('does not answer a preflight for a foreign origin', async () => {
    const foreign = await send('/api/subscribe', {
      method: 'OPTIONS',
      headers: { Origin: 'https://attacker.example', 'Access-Control-Request-Method': 'POST' },
    });
    assert.notEqual(foreign.headers.get('access-control-allow-origin'), 'https://attacker.example');
  });
});
