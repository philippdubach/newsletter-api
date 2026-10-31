// Subscription invariants for item 35, expressed against the real Worker in
// workerd with a stand-in for Listmonk.
//
// These encode the constraints established before any behaviour change:
//
//   * A KV record is not evidence of provider membership. Answering "already
//     subscribed" from KV alone tells a subscriber something the Worker has not
//     checked, and the inventory found a live case where the two disagree.
//   * A blocklisted address must never be reactivated by any path.
//   * A native Listmonk unsubscribe is intent. Re-creating the subscriber from an
//     older KV row would silently undo it.
//   * An address in KV with no upstream record must still be recoverable, or the
//     only retry channel for a failed background write disappears.
//
// The stand-in records every request, so "did not mutate" is asserted by
// inspecting what the Worker actually sent rather than by trusting a status code.

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { startRuntime } from './harness.mjs';

const LIST_URL = 'https://listmonk.runtime-suite.invalid';
const LIST_ID = 3;

const PROVIDER_BINDINGS = {
  LISTMONK_API_URL: LIST_URL,
  LISTMONK_API_USER: 'runtime-suite',
  LISTMONK_API_TOKEN: 'runtime-suite-token',
  LISTMONK_LIST_ID: String(LIST_ID),
  LISTMONK_WELCOME_TEMPLATE_ID: '5',
};

/**
 * Minimal Listmonk stand-in. Subscriber state is a map the test controls, so a
 * case can put the provider in any status without touching a real account.
 */
function createProviderStub() {
  const calls = [];
  const subscribers = new Map();
  // Lets a case answer the lookup with a deliberately contradictory payload.
  let rawLookup = null;

  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const handler = async (request) => {
    const url = new URL(request.url);
    const method = request.method;
    let body = null;
    if (method !== 'GET' && method !== 'HEAD') {
      try {
        body = await request.clone().text();
      } catch {
        body = null;
      }
    }
    calls.push({ method, path: url.pathname, search: url.search, body });

    if (url.pathname === '/api/subscribers' && method === 'GET') {
      if (rawLookup) return rawLookup(request);
      const query = url.searchParams.get('query') ?? '';
      const match = /subscribers\.email\s*=\s*'([^']*)'/i.exec(query);
      const email = match?.[1]?.trim().toLowerCase();
      const record = email ? subscribers.get(email) : undefined;
      const results = record ? [record] : [];
      return json({ data: { results, total: results.length } });
    }
    if (url.pathname === '/api/subscribers' && method === 'POST') {
      return json({ data: {} });
    }
    return json({ data: {} });
  };

  return {
    calls,
    subscribers,
    handler,
    setRawLookup: (fn) => { rawLookup = fn; },
    clearRawLookup: () => { rawLookup = null; },
    /** Requests that would create or re-enable a subscriber. */
    mutations: () => calls.filter((call) => call.method === 'POST' && call.path === '/api/subscribers'),
    reset: () => { calls.length = 0; },
  };
}

let harness;
let provider;
let ipCounter = 0;

function nextIP() {
  ipCounter += 1;
  return `198.51.100.${ipCounter}`;
}

async function drain() {
  return harness.drain();
}

function subscribe(email) {
  return harness.runtime.dispatchFetch('http://localhost/api/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': nextIP() },
    body: JSON.stringify({ email }),
  });
}

/** Creates the KV record through the normal path, then clears the call log. */
async function seedSubscriber(email) {
  const first = await subscribe(email);
  assert.equal(first.status, 200);
  // Consume the body before draining, and never hand back an unread response.
  const body = await first.json();
  await drain();
  provider.reset();
  return body;
}

function setProviderStatus(email, { global = 'enabled', listStatus } = {}) {
  const lists = listStatus === undefined ? [] : [{ id: LIST_ID, subscription_status: listStatus }];
  provider.subscribers.set(email, { email, status: global, lists });
}

before(async () => {
  provider = createProviderStub();
  harness = await startRuntime({
    extraBindings: PROVIDER_BINDINGS,
    outboundService: provider.handler,
  });
});

after(async () => {
  if (harness) await harness.dispose();
});

describe('an existing KV record is not evidence of provider membership', () => {
  it('confirms an address that is genuinely subscribed', async () => {
    const email = 'invariant-confirmed@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'confirmed' });

    const response = await subscribe(email);
    // Read the body before any further runtime request: the response is a live
    // stream and a drain request can invalidate it.
    const body = await response.json();
    await drain();

    assert.equal(body.message, 'Already subscribed');
    // A confirmed subscriber needs no create, so the recovery path stays quiet.
    assert.equal(provider.mutations().length, 0);
  });

  it('does not claim an unsubscribed address is subscribed, and does not re-create it', async () => {
    const email = 'invariant-unsubscribed@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'unsubscribed' });

    const response = await subscribe(email);
    // Read the body before any further runtime request: the response is a live
    // stream and a drain request can invalidate it.
    const body = await response.json();
    await drain();

    // The inventory found a live instance of this: KV says present, Listmonk
    // says unsubscribed. Re-creating would undo a deliberate unsubscribe.
    assert.notEqual(body.message, 'Already subscribed');
    assert.notEqual(body.success, true);
    assert.equal(provider.mutations().length, 0, 'a native unsubscribe must not be overwritten');
  });

  it('never reactivates a blocklisted address', async () => {
    const email = 'invariant-blocklisted@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { global: 'blocklisted', listStatus: 'unsubscribed' });

    const response = await subscribe(email);
    // Read the body before any further runtime request: the response is a live
    // stream and a drain request can invalidate it.
    const body = await response.json();
    await drain();

    assert.notEqual(body.success, true);
    assert.equal(provider.mutations().length, 0, 'a blocklisted address must never be re-enabled');
  });

  it('still recovers an address that exists only in KV', async () => {
    const email = 'invariant-kv-only@example.com';
    await seedSubscriber(email);
    provider.subscribers.delete(email);

    await subscribe(email);
    await drain();

    // The two KV-only records from the inventory are exactly this shape. Without
    // this path a failed background write has no retry channel at all.
    assert.equal(provider.mutations().length, 1);
  });
});

describe('the answer is only sent once provider state is known', () => {
  it('does not answer "already subscribed" from KV when the provider cannot be read', async () => {
    const email = 'invariant-unreadable@example.com';
    await seedSubscriber(email);

    // Make the lookup fail while the rest of the stub keeps working.
    const failing = async (request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/subscribers' && request.method === 'GET') {
        provider.calls.push({ method: 'GET', path: url.pathname, search: url.search, body: null });
        return new Response('{"error":"boom"}', { status: 500 });
      }
      return provider.handler(request);
    };

    const failingRuntime = await startRuntime({
      extraBindings: PROVIDER_BINDINGS,
      outboundService: failing,
    });
    try {
      // Seed the record in this runtime so the existing-record path is hit.
      const seeded = await failingRuntime.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.200' },
        body: JSON.stringify({ email }),
      });
      assert.equal(seeded.status, 200);
      // Consume the seed body before its drain, for the same reason as below.
      await seeded.json();
      await failingRuntime.drain();

      const response = await failingRuntime.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.201' },
        body: JSON.stringify({ email }),
      });
      // Read the body before any further runtime request: the response is a live
      // stream and a drain request can invalidate it.
      const body = await response.json();
      await failingRuntime.drain();

      // Unreadable is not confirmed: the subscriber must not be told they are on
      // the list when the lookup did not succeed.
      assert.notEqual(body.message, 'Already subscribed');
    } finally {
      await failingRuntime.dispose();
    }
  });
});

describe('a contradictory lookup response establishes nothing', () => {
  const cases = [
    ['a missing global status', { global: undefined, listStatus: 'confirmed' }],
    ['a disabled global status', { global: 'disabled', listStatus: 'confirmed' }],
    ['an unrecognised global status', { global: 'archived', listStatus: 'confirmed' }],
  ];

  for (const [name, shape] of cases) {
    it(`does not claim confirmation with ${name}`, async () => {
      const email = `invariant-status-${String(shape.global)}@example.com`;
      await seedSubscriber(email);
      provider.setRawLookup(() => new Response(JSON.stringify({
        data: {
          results: [{ email, status: shape.global, lists: [{ id: LIST_ID, subscription_status: shape.listStatus }] }],
          total: 1,
        },
      }), { status: 200, headers: { 'content-type': 'application/json' } }));

      try {
        const response = await subscribe(email);
        const body = await response.json();
        await drain();
        assert.notEqual(body.message, 'Already subscribed');
        assert.equal(body.status, 'unverified');
        assert.equal(provider.mutations().length, 0);
      } finally {
        provider.clearRawLookup();
      }
    });
  }

  it('does not treat an empty result with a non-zero total as absence', async () => {
    const email = 'invariant-count-mismatch@example.com';
    await seedSubscriber(email);
    // The rows and the count disagree, so neither can be used to conclude that
    // the address is gone - and concluding that would issue a create.
    provider.setRawLookup(() => new Response(
      JSON.stringify({ data: { results: [], total: 1 } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));

    try {
      const response = await subscribe(email);
      // Read the body before any further runtime request: the response is a live
      // stream and a drain request can invalidate it.
      const body = await response.json();
      await drain();
      assert.equal(body.status, 'unverified');
      assert.equal(provider.mutations().length, 0, 'a contradictory count must not trigger a create');
    } finally {
      provider.clearRawLookup();
    }
  });

  it('treats more than one match for an exact address as ambiguous', async () => {
    const email = 'invariant-multi-match@example.com';
    await seedSubscriber(email);
    // One matching row, but the count says there are two. Which one is the
    // subscriber is not something the response can answer.
    provider.setRawLookup(() => new Response(JSON.stringify({
      data: {
        results: [{ email, status: 'enabled', lists: [{ id: LIST_ID, subscription_status: 'confirmed' }] }],
        total: 2,
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));

    try {
      const response = await subscribe(email);
      // Read the body before any further runtime request: the response is a live
      // stream and a drain request can invalidate it.
      const body = await response.json();
      await drain();
      assert.notEqual(body.message, 'Already subscribed');
      assert.equal(body.status, 'unverified');
    } finally {
      provider.clearRawLookup();
    }
  });

  for (const total of [-1, 0.5]) {
    it(`treats a ${total} count as uninterpretable rather than confirmed`, async () => {
      const email = `invariant-count-${String(total).replace('.', '_')}@example.com`;
      await seedSubscriber(email);
      // A matching, enabled, confirmed row with an impossible count. A `> 1`
      // bound would let these through to the length checks and report the
      // address as confirmed.
      provider.setRawLookup(() => new Response(JSON.stringify({
        data: {
          results: [{ email, status: 'enabled', lists: [{ id: LIST_ID, subscription_status: 'confirmed' }] }],
          total,
        },
      }), { status: 200, headers: { 'content-type': 'application/json' } }));

      try {
        const response = await subscribe(email);
        const body = await response.json();
        await drain();
        assert.notEqual(body.message, 'Already subscribed');
        assert.equal(body.status, 'unverified');
        assert.equal(provider.mutations().length, 0);
      } finally {
        provider.clearRawLookup();
      }
    });
  }

  it('does not accept a result for a different address', async () => {
    const email = 'invariant-wrong-identity@example.com';
    await seedSubscriber(email);
    provider.setRawLookup(() => new Response(JSON.stringify({
      data: {
        results: [{ email: 'someone-else@example.com', status: 'enabled', lists: [{ id: LIST_ID, subscription_status: 'confirmed' }] }],
        total: 1,
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));

    try {
      const response = await subscribe(email);
      // Read the body before any further runtime request: the response is a live
      // stream and a drain request can invalidate it.
      const body = await response.json();
      await drain();
      assert.notEqual(body.message, 'Already subscribed');
      assert.equal(body.status, 'unverified');
    } finally {
      provider.clearRawLookup();
    }
  });
});

describe('the browser can show the explanation', () => {
  it('returns an error string alongside the status for every non-confirmed state', async () => {
    const email = 'invariant-wording@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'unsubscribed' });

    const response = await subscribe(email);
    // Read the body before any further runtime request: the response is a live
    // stream and a drain request can invalidate it.
    const body = await response.json();
    await drain();

    // site.js reads data.error on failure, so message alone is invisible.
    assert.equal(typeof body.error, 'string');
    assert.ok(body.error.length > 0);
    assert.equal(body.status, 'unsubscribed');
    assert.equal(body.message, body.error);
  });

  it('does not assert the subscription state when the provider is unreadable', async () => {
    const email = 'invariant-unreadable-wording@example.com';
    await seedSubscriber(email);
    provider.setRawLookup(() => new Response('{"error":"boom"}', { status: 500 }));

    try {
      const response = await subscribe(email);
      // Read the body before any further runtime request: the response is a live
      // stream and a drain request can invalidate it.
      const body = await response.json();
      await drain();
      assert.equal(body.status, 'unverified');
      assert.doesNotMatch(body.error, /is not currently subscribed/i);
      assert.match(body.error, /verify/i);
    } finally {
      provider.clearRawLookup();
    }
  });
});
