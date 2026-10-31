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
import { createHmac } from 'node:crypto';

import { TEST_BINDINGS, startRuntime } from './harness.mjs';

const LIST_URL = 'https://listmonk.runtime-suite.invalid';
const HMAC_SECRET = TEST_BINDINGS.UNSUBSCRIBE_HMAC_SECRET;
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
function emailFrom(bodyText) {
  try {
    const parsed = JSON.parse(bodyText ?? '{}');
    return typeof parsed.email === 'string' ? parsed.email.trim().toLowerCase() : null;
  } catch {
    return null;
  }
}

function createProviderStub() {
  const calls = [];
  const subscribers = new Map();
  // Final membership, so a test can assert the *end state* rather than merely
  // that some removal request was sent.
  const membership = new Map();
  const events = [];
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
      // A create commits whatever the gate above decided to do.
      membership.set(emailFrom(body), true);
      events.push('create-commit');
      return json({ data: {} });
    }
    if (url.pathname === '/api/subscribers/query/lists' && method === 'PUT') {
      const parsed = body ? JSON.parse(body) : {};
      const target = /subscribers\.email = '([^']*)'/.exec(parsed.query ?? '')?.[1];
      if (target) membership.set(target.trim().toLowerCase(), false);
      events.push('remove-commit');
      return json({ data: {} });
    }
    if (url.pathname === '/api/tx') {
      events.push('welcome');
      return json({ data: {} });
    }
    return json({ data: {} });
  };

  return {
    calls,
    subscribers,
    handler,
    membership,
    events,
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

function tokenFor(email) {
  return `v1:${createHmac('sha256', HMAC_SECRET).update(email).digest('hex')}`;
}

function unsubscribe(email) {
  return harness.runtime.dispatchFetch('http://localhost/api/unsubscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': nextIP() },
    body: JSON.stringify({ email, token: tokenFor(email) }),
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
      // The seed is an accepted intent; with an unreadable provider it settles at
      // 202 rather than claiming completion.
      assert.ok([200, 202].includes(seeded.status), `unexpected seed status ${seeded.status}`);
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
      // the list, and a 5xx keeps the retry rather than being terminal.
      assert.notEqual(body.message, 'Already subscribed');
      assert.ok([200, 202].includes(response.status), `unexpected status ${response.status}`);
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
        assert.equal(body.status, 'accepted');
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
      assert.equal(body.status, 'accepted');
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
      assert.equal(body.status, 'accepted');
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
        assert.equal(body.status, 'accepted');
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
      assert.equal(body.status, 'accepted');
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
      // Accepted with a retry preserved; no claim about membership either way.
      assert.equal(body.status, 'accepted');
      const text = body.message ?? body.error ?? '';
      assert.doesNotMatch(text, /is not currently subscribed/i);
      assert.doesNotMatch(text, /already subscribed/i);
    } finally {
      provider.clearRawLookup();
    }
  });
});

describe('ordering is serialized per address', () => {
  async function coordinatorState(email) {
    const stub = await harness.coordinator(email);
    const response = await stub.fetch('https://coordinator/state');
    return response.json();
  }

  it('does not let a concurrent signup and unsubscribe both win', async () => {
    const email = 'invariant-race@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'confirmed' });

    // Both are issued without awaiting the first. Before the coordinator these
    // could interleave and leave the stores disagreeing.
    const [first, second] = await Promise.all([subscribe(email), unsubscribe(email)]);
    await drain();

    // Either request may report accepted instead of completed, because one of
    // them is superseded by the other. What must hold is that neither claims a
    // conflicting final state and the provider sees at most one write.
    assert.ok([200, 202].includes(first.status), `unexpected subscribe status ${first.status}`);
    assert.ok([200, 202].includes(second.status), `unexpected unsubscribe status ${second.status}`);

    const state = await coordinatorState(email);
    const desired = state.intent.desired;
    // Whichever arrived last owns the outcome; the point is that exactly one
    // intent survives and the provider is converged to it.
    assert.ok(['subscribed', 'unsubscribed'].includes(desired));

    const writes = provider.calls.filter((c) => c.method !== 'GET');
    assert.ok(writes.length <= 1, `expected at most one provider write, saw ${JSON.stringify(writes)}`);
  });

  it('keeps the later unsubscribe when a signup is already recorded', async () => {
    const email = 'invariant-sub-then-unsub@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'confirmed' });

    await unsubscribe(email);
    await drain();

    const state = await coordinatorState(email);
    assert.equal(state.intent.desired, 'unsubscribed');
    // The replacement intent is the tombstone: the KV shadow is gone but the
    // request to leave is still recorded.
    assert.ok(state.intent.seq >= 2);
  });

  it('does not resurrect an address after an unsubscribe', async () => {
    const email = 'invariant-no-resurrect@example.com';
    await seedSubscriber(email);
    setProviderStatus(email, { listStatus: 'unsubscribed' });

    await subscribe(email);
    await drain();
    const body = await (await subscribe(email)).json();

    // A fresh explicit signup is not silently turned into a re-subscription.
    assert.notEqual(body.message, 'Already subscribed');
    assert.equal(provider.mutations().length, 0);
  });
});

describe('failed provider work is durable', () => {
  it('accepts the intent, records a retry, and completes it later', async () => {
    const email = 'invariant-retry@example.com';
    // The address is absent upstream, so the coordinator will attempt a create —
    // and the provider refuses it.
    let failing = true;
    const store = createProviderStub();
    const base = store.handler;
    store.handler = async (request) => {
      const url = new URL(request.url);
      if (failing && url.pathname === '/api/subscribers' && request.method === 'POST') {
        store.calls.push({ method: 'POST', path: url.pathname, search: url.search, body: null });
        return new Response('{"error":"boom"}', { status: 500 });
      }
      return base(request);
    };

    const retryHarness = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    try {
      const response = await retryHarness.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.210' },
        body: JSON.stringify({ email }),
      });
      const body = await response.json();
      await retryHarness.drain();

      assert.equal(response.status, 202);
      assert.equal(body.status, 'accepted');

      const stub = await retryHarness.coordinator(email);
      let state = await (await stub.fetch('https://coordinator/state')).json();
      assert.equal(state.intent.desired, 'subscribed');
      assert.equal(state.pending.attempts, 1);
      assert.ok(state.alarm, 'a retry alarm must be armed');

      // The provider recovers; the stored retry converges without a new request.
      failing = false;
      const syncResponse = await stub.fetch('https://coordinator/sync', { method: 'POST' });
      const synced = await syncResponse.json();
      assert.equal(synced.outcome, 'completed');

      state = await (await stub.fetch('https://coordinator/state')).json();
      assert.equal(state.pending, null);
      assert.ok(store.calls.some((c) => c.method === 'POST' && c.path === '/api/subscribers'));
    } finally {
      await retryHarness.dispose();
    }
  });
});

describe('provider effects are serialized per address', () => {
  it('leaves the provider unsubscribed when an unsubscribe arrives mid-create', async () => {
    const email = 'invariant-supersede@example.com';
    let releaseCreate;
    const createGate = new Promise((resolve) => { releaseCreate = resolve; });

    const store = createProviderStub();
    const base = store.handler;
    store.handler = async (request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/subscribers' && request.method === 'POST') {
        store.calls.push({ method: 'POST', path: url.pathname, search: url.search, body: null });
        store.events.push('create-start');
        // Hold the create open so an unsubscribe arrives while it is in flight.
        await createGate;
      }
      return base(request);
    };

    const local = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    const post = (path, body, ip) => local.runtime.dispatchFetch(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
      body: JSON.stringify(body),
    });

    try {
      const signup = post('/api/subscribe', { email }, '198.51.100.220');
      await new Promise((resolve) => setTimeout(resolve, 50));
      const removal = post('/api/unsubscribe', { email, token: tokenFor(email) }, '198.51.100.221');
      await new Promise((resolve) => setTimeout(resolve, 50));
      releaseCreate();

      const signupBody = await (await signup).json();
      await (await removal).json();
      await local.drain();

      const stub = await local.coordinator(email);
      const state = await (await stub.fetch('https://coordinator/state')).json();

      // The serialized claim: the intent is unsubscribed AND the provider agrees,
      // with no pending work left behind.
      assert.equal(state.intent.desired, 'unsubscribed');
      assert.equal(store.membership.get(email), false, 'provider must end unsubscribed');
      assert.equal(state.pending, null, 'no work may be left unscheduled');

      // The removal must be the last membership effect, not merely present.
      const commits = store.events.filter((e) => e === 'create-commit' || e === 'remove-commit');
      assert.equal(commits.at(-1), 'remove-commit', `unexpected order ${commits.join(' > ')}`);
      // The signup's answer must match what actually happened for it.
      assert.ok(signupBody.status === 'accepted' || signupBody.message === 'Subscribed successfully');
    } finally {
      await local.dispose();
    }
  });
});

describe('welcome mail is sent once per intent', () => {
  it('does not resend the welcome when the same intent is synced again', async () => {
    const email = 'invariant-welcome-once@example.com';
    const store = createProviderStub();
    const local = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    try {
      const response = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.230' },
        body: JSON.stringify({ email }),
      });
      assert.equal(response.status, 200);
      await response.json();
      await local.drain();

      const welcomes = () => store.calls.filter((c) => c.method === 'POST' && c.path === '/api/tx').length;
      assert.equal(welcomes(), 1, 'the create should send exactly one welcome');

      // A second convergence of the same intent must not send another.
      const stub = await local.coordinator(email);
      await stub.fetch('https://coordinator/sync', { method: 'POST' });
      await stub.fetch('https://coordinator/sync', { method: 'POST' });

      assert.equal(welcomes(), 1, 'a re-sync must not duplicate the welcome');
    } finally {
      await local.dispose();
    }
  });
});

describe('durable state is recoverable', () => {
  it('records a recoverable operation when the KV shadow write fails', async () => {
    const email = 'invariant-kv-failure@example.com';
    const store = createProviderStub();
    // No KV binding at all: the rate limiter fails open, so the request reaches
    // the coordinator and its shadow write is what fails.
    const local = await startRuntime({
      extraBindings: PROVIDER_BINDINGS,
      outboundService: store.handler,
      withKv: false,
    });
    try {
      const response = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.240' },
        body: JSON.stringify({ email }),
      });
      const body = await response.json();
      await local.drain();

      assert.equal(response.status, 202);
      assert.equal(body.status, 'accepted');

      const stub = await local.coordinator(email);
      const state = await (await stub.fetch('https://coordinator/state')).json();

      // Intent survives the failed write, and work is scheduled to finish it.
      assert.equal(state.intent.desired, 'subscribed');
      assert.ok(state.pending, 'a failed KV write must leave a recoverable operation');
      assert.equal(state.pending.kind, 'shadow');
      assert.ok(state.alarm, 'the recovery must be scheduled, not merely recorded');
      assert.equal(store.membership.get(email), undefined, 'the provider must not be touched yet');
    } finally {
      await local.dispose();
    }
  });

  it('keeps the retry budget when the lookup fails transiently', async () => {
    const email = 'invariant-lookup-retry@example.com';
    const store = createProviderStub();
    const base = store.handler;
    let phase = 'create-fails';
    store.handler = async (request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/subscribers' && request.method === 'POST' && phase === 'create-fails') {
        store.calls.push({ method: 'POST', path: url.pathname, search: url.search, body: null });
        return new Response('{"error":"boom"}', { status: 500 });
      }
      if (url.pathname === '/api/subscribers' && request.method === 'GET' && phase === 'lookup-fails') {
        store.calls.push({ method: 'GET', path: url.pathname, search: url.search, body: null });
        return new Response('{"error":"unavailable"}', { status: 503 });
      }
      return base(request);
    };

    const local = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    try {
      const signup = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.241' },
        body: JSON.stringify({ email }),
      });
      await signup.json();
      await local.drain();

      const stub = await local.coordinator(email);
      let state = await (await stub.fetch('https://coordinator/state')).json();
      assert.equal(state.pending.attempts, 1);

      // The next attempt fails in the lookup instead of the create.
      phase = 'lookup-fails';
      const sync = await (await stub.fetch('https://coordinator/sync', { method: 'POST' })).json();
      assert.equal(sync.outcome, 'pending');

      state = await (await stub.fetch('https://coordinator/state')).json();
      // A transient lookup failure must not discard accepted work.
      assert.ok(state.pending, 'the pending operation must survive a 503 lookup');
      assert.equal(state.pending.attempts, 2);
      assert.ok(state.alarm, 'a retry must remain scheduled');
      assert.equal(store.membership.get(email), undefined, 'no create may happen on an unreadable lookup');
    } finally {
      await local.dispose();
    }
  });
});

describe('legacy work cannot undo a newer intent', () => {
  it('does not let a stale durable create override an unsubscribe served inline', async () => {
    const email = 'invariant-legacy-undo@example.com';
    const store = createProviderStub();
    const base = store.handler;
    let creating = false;
    store.handler = async (request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/subscribers' && request.method === 'POST') {
        if (creating) return new Response('{"error":"boom"}', { status: 500 });
      }
      return base(request);
    };

    const local = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    try {
      creating = true;
      const signup = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.250' },
        body: JSON.stringify({ email }),
      });
      await signup.json();
      await local.drain();

      const stub = await local.coordinator(email);
      let state = await (await stub.fetch('https://coordinator/state')).json();
      assert.ok(state.pending, 'the failed create must be pending');

      // The coordinator is now unavailable for provider work (legacy rollback). An
      // unsubscribe is served inline: the provider is changed directly and the
      // intent is published to the object without doing provider work.
      creating = false;
      await base(new Request(`https://mail.philippdubach.com/api/subscribers/query/lists`, {
        method: 'PUT',
        body: JSON.stringify({ query: `subscribers.email = '${email}'`, action: 'unsubscribe', target_list_ids: [3] }),
      }));
      assert.equal(store.membership.get(email), false);
      await stub.fetch('https://coordinator/intent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ desired: 'unsubscribed', email, recordOnly: true }),
      });

      // The old pending job must not resurrect the subscription.
      await stub.fetch('https://coordinator/sync', { method: 'POST' });
      await local.drain();

      state = await (await stub.fetch('https://coordinator/state')).json();
      assert.equal(store.membership.get(email), false, 'stale work must not re-subscribe');
      assert.equal(state.intent.desired, 'unsubscribed');
      assert.equal(state.pending, null);
      assert.ok(!store.events.slice(store.events.indexOf('remove-commit')).includes('create-commit'),
        `unexpected events ${store.events.join(' > ')}`);
    } finally {
      await local.dispose();
    }
  });
});

describe('the provider phase is bounded as a whole', () => {
  it('gives up on a slow sequence inside the budget, not at the 30-second reset', async () => {
    const email = 'invariant-stall@example.com';
    const store = createProviderStub();
    const base = store.handler;
    const slow = () => new Promise((resolve) => setTimeout(resolve, 6000));
    store.handler = async (request) => {
      const url = new URL(request.url);
      // Each call is inside its own 10-second timer, so only a combined budget
      // bounds the sequence: lookup, create and welcome together.
      if (url.pathname === '/api/subscribers' || url.pathname === '/api/tx') await slow();
      return base(request);
    };

    const local = await startRuntime({
      extraBindings: { ...PROVIDER_BINDINGS, PROVIDER_BUDGET_MS: '2000' },
      outboundService: store.handler,
    });
    try {
      const started = Date.now();
      const response = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.251' },
        body: JSON.stringify({ email }),
      });
      const body = await response.json();
      await local.drain();
      const elapsed = Date.now() - started;

      assert.ok(elapsed < 8000, `took ${elapsed}ms, which means the sequence outlived the budget`);
      assert.equal(body.status, 'accepted');

      const stub = await local.coordinator(email);
      const state = await (await stub.fetch('https://coordinator/state')).json();
      // The boundary the reset made observable: durable state survives and agrees.
      assert.equal(state.intent.desired, 'subscribed');
      assert.ok(state.pending, 'an over-budget sequence must leave recoverable work');
      assert.ok(state.alarm, 'the recovery must remain scheduled');
    } finally {
      await local.dispose();
    }
  });

  it('bounds a provider body that never finishes', async () => {
    const email = 'invariant-stall-body@example.com';
    const store = createProviderStub();
    const base = store.handler;
    store.handler = async (request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/subscribers' && request.method === 'GET') {
        // Headers arrive, the body never completes. This is the read the lookup
        // actually performs, unlike the create path which never reads a 200 body.
        return new Response(new ReadableStream({ start() {} }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return base(request);
    };

    const local = await startRuntime({
      extraBindings: { ...PROVIDER_BINDINGS, PROVIDER_BUDGET_MS: '1500' },
      outboundService: store.handler,
    });
    try {
      const started = Date.now();
      const response = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.252' },
        body: JSON.stringify({ email }),
      });
      const body = await response.json();
      await local.drain();
      const elapsed = Date.now() - started;

      // The budget, not the 10-second per-call timer, has to bound this.
      assert.ok(elapsed < 6000, `took ${elapsed}ms`);
      assert.equal(body.status, 'accepted');
      const stub = await local.coordinator(email);
      const state = await (await stub.fetch('https://coordinator/state')).json();
      assert.ok(state.pending);
      assert.ok(state.alarm);
    } finally {
      await local.dispose();
    }
  });
});

describe('the shadow fences work that contradicts it', () => {
  it('refuses to act on stored intent the shadow contradicts', async () => {
    const email = 'invariant-shadow-fence@example.com';
    const store = createProviderStub();
    const local = await startRuntime({ extraBindings: PROVIDER_BINDINGS, outboundService: store.handler });
    try {
      const stub = await local.coordinator(email);
      // Publishes intent without writing the shadow, which is what a legacy request
      // whose coordinator call failed leaves behind.
      await stub.fetch('https://coordinator/intent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ desired: 'subscribed', email, recordOnly: true }),
      });

      const sync = await (await stub.fetch('https://coordinator/sync', { method: 'POST' })).json();

      // The shadow says this address is not subscribed, so recreating it would
      // undo whatever removed it.
      assert.equal(sync.outcome, 'superseded');
      assert.equal(store.membership.get(email), undefined, 'the provider must not be touched');
    } finally {
      await local.dispose();
    }
  });
});
