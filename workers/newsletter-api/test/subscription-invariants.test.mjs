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
  await drain();
  provider.reset();
  return first;
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
    await drain();
    const body = await response.json();

    assert.equal(body.message, 'Already subscribed');
    // A confirmed subscriber needs no create, so the recovery path stays quiet.
    assert.equal(provider.mutations().length, 0);
  });

  it('does not claim an unsubscribed address is subscribed, and does not re-create it', async () => {
    const email = 'invariant-unsubscribed@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'unsubscribed' });

    const response = await subscribe(email);
    await drain();
    const body = await response.json();

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
    await drain();
    const body = await response.json();

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
      await failingRuntime.drain();

      const response = await failingRuntime.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.201' },
        body: JSON.stringify({ email }),
      });
      await failingRuntime.drain();
      const body = await response.json();

      // Unreadable is not confirmed: the subscriber must not be told they are on
      // the list when the lookup did not succeed.
      assert.notEqual(body.message, 'Already subscribed');
    } finally {
      await failingRuntime.dispose();
    }
  });
});
