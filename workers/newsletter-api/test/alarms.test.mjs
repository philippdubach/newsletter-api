import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { startRuntime } from './harness.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function json(stub, path) { return (await stub.fetch(`https://coordinator${path}`)).json(); }
async function fixture(stub, input) {
  return stub.fetch('https://coordinator/fixture', { method: 'POST', body: JSON.stringify(input) });
}
async function until(fn) {
  for (let i = 0; i < 200; i++) { if (await fn()) return; await sleep(25); }
  assert.fail('scheduler did not converge within 5 seconds');
}
const bindings = { LISTMONK_API_URL: 'https://provider.invalid', LISTMONK_API_USER: 'test', LISTMONK_API_TOKEN: 'test', LISTMONK_LIST_ID: '1' };
function seed(email, seq = 1) {
  return { intent: { email, desired: 'subscribed', seq: 1, updatedAt: new Date().toISOString() }, pending: { kind: 'create', seq, attempts: 0, nextAt: 0, lastError: null } };
}

describe('workerd scheduler delivers retries; /sync is used only to assert the paused guard', () => {
  for (const converge of [true, false]) it(converge ? 'retries converge' : 'eight total attempts and exact capped backoffs', async () => {
    let calls = 0;
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: () => {
      calls++;
      if (converge && calls > 2) return Response.json({ data: { total: 1, results: [{ email: 'alarm@example.com', status: 'enabled', lists: [{ id: 1, subscription_status: 'confirmed' }] }] } });
      return new Response('unavailable', { status: 503 });
    } });
    try {
      const stub = await local.coordinator('alarm@example.com');
      // Historical fence keys have no authority, regardless of their clock.
      await local.kv.put('intent:fence:alarm@example.com', { desired: 'unsubscribed', at: Date.now() + 999999999 });
      await fixture(stub, { seed: seed('alarm@example.com') });
      await until(async () => (await json(stub, '/state')).pending === null);
      const metrics = await json(stub, '/metrics');
      assert.equal(calls, converge ? 3 : 8);
      assert.equal(metrics.callbacks, calls);
      const expected = converge ? [60000, 240000] : [60000, 240000, 960000, 3600000, 3600000, 3600000, 3600000];
      assert.equal(metrics.delays.length, expected.length);
      metrics.delays.forEach((delay, i) => assert.ok(Math.abs(delay - expected[i]) < 100, `${delay} != ${expected[i]}`));
      await sleep(100);
      assert.equal((await json(stub, '/metrics')).callbacks, calls, 'terminal work must not spin');
    } finally { await local.dispose(); }
  });

  for (const exhausted of [true, false]) it(`protects an unsubscribe tombstone after ${exhausted ? 'scheduler exhaustion' : 'scheduler completion'}`, async () => {
    const calls = [];
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: request => {
      calls.push({ method: request.method, path: new URL(request.url).pathname });
      return new Response('{}', { status: exhausted ? 503 : 200 });
    } });
    try {
      const email = exhausted ? 'exhausted-removal@example.com' : 'completed-removal@example.com';
      const stub = await local.coordinator(email);
      const removal = seed(email);
      removal.intent.desired = 'unsubscribed';
      removal.intent.authenticated = true;
      removal.pending.kind = 'remove';
      await fixture(stub, { seed: removal });
      // Only workerd's scheduler drives removal; no direct alarm or /sync call.
      await until(async () => (await json(stub, '/state')).pending === null);
      const before = await json(stub, '/state');
      assert.equal(before.alarm, null);
      assert.equal(before.intent.desired, 'unsubscribed');
      assert.equal(before.intent.authenticated, true);
      // No pending work means both outcomes look alike without this record.
      if (exhausted) {
        const { at, ...rest } = before.exhausted;
        assert.deepEqual(rest, { seq: 1, kind: 'remove', desired: 'unsubscribed', lastError: 'Listmonk unsubscribe HTTP 503: {}' });
        assert.ok(Math.abs(Date.parse(at) - Date.now()) < 5000);
      } else {
        assert.equal(before.exhausted, null);
      }
      assert.equal(calls.length, exhausted ? 8 : 1);
      assert.ok(calls.every(call => call.method === 'PUT' && call.path === '/api/subscribers/query/lists'));
      const metrics = await json(stub, '/metrics');
      assert.equal(metrics.callbacks, exhausted ? 8 : 1);

      const signup = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.90' },
        body: JSON.stringify({ email }),
      });
      assert.equal(signup.status, 200);
      const body = await signup.json();
      assert.equal(body.success, false);
      assert.equal(body.status, 'unsubscribed');
      await local.drain();
      await sleep(100);
      const after = await json(stub, '/state');
      assert.deepEqual(after.intent, before.intent, 'anonymous signup must not change the tombstone or sequence');
      assert.deepEqual(after.exhausted, before.exhausted, 'a refused intent must not clear the failure record');
      assert.equal(after.pending, null);
      assert.equal(after.alarm, null);
      assert.equal(calls.length, exhausted ? 8 : 1, 'no lookup, create, or other provider call after refusal');
      assert.equal((await json(stub, '/metrics')).callbacks, metrics.callbacks);
      assert.equal(await local.kv.get(email), null);
    } finally { await local.dispose(); }
  });

  it('clears the exhausted record on the next accepted intent', async () => {
    let healthy = false;
    const email = 'exhausted-recovers@example.com';
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: request => {
      if (!healthy) return new Response('', { status: 503 });
      return request.method === 'GET'
        ? Response.json({ data: { total: 1, results: [{ email, status: 'enabled', lists: [{ id: 1, subscription_status: 'confirmed' }] }] } })
        : new Response('{}', { status: 200 });
    } });
    try {
      const stub = await local.coordinator(email);
      await fixture(stub, { seed: seed(email) });
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.equal((await json(stub, '/state')).exhausted.kind, 'create');
      assert.equal((await json(stub, '/state')).exhausted.lastError, 'http_503');
      healthy = true;
      const signup = await local.runtime.dispatchFetch('http://localhost/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.91' },
        body: JSON.stringify({ email }),
      });
      assert.equal((await signup.json()).message, 'Already subscribed');
      assert.equal((await json(stub, '/state')).exhausted, null);
    } finally { await local.dispose(); }
  });

  it('records an exhausted shadow repair as shadow work', async () => {
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: () => new Response('{}', { status: 200 }) });
    try {
      const email = 'exhausted-shadow@example.com';
      const stub = await local.coordinator(email);
      await fixture(stub, { failShadow: true, seed: removal(email) });
      await until(async () => (await json(stub, '/state')).pending === null);
      const { exhausted } = await json(stub, '/state');
      assert.equal(exhausted.kind, 'shadow');
      assert.match(exhausted.lastError, /kv unavailable/);
    } finally { await local.dispose(); }
  });

  function removal(email) {
    const seeded = seed(email);
    seeded.intent.desired = 'unsubscribed';
    seeded.intent.authenticated = true;
    seeded.pending.kind = 'remove';
    return seeded;
  }

  it('removes from the provider once while the shadow delete keeps failing', async () => {
    const calls = [];
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: request => {
      calls.push(`${request.method} ${new URL(request.url).pathname}`);
      return new Response('{}', { status: 200 });
    } });
    try {
      const email = 'shadow-down@example.com';
      const stub = await local.coordinator(email);
      await fixture(stub, { failShadow: true, seed: removal(email) });
      await until(async () => (await json(stub, '/metrics')).callbacks >= 2);
      const midway = await json(stub, '/state');
      assert.equal(midway.pending.kind, 'shadow');
      assert.match(midway.pending.lastError, /kv unavailable/);
      assert.ok(midway.alarm, 'the shadow repair must stay scheduled');
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.deepEqual(calls, ['PUT /api/subscribers/query/lists']);
      assert.equal((await json(stub, '/metrics')).callbacks, 8);
    } finally { await local.dispose(); }
  });

  it('finishes the shadow repair without repeating the removal once KV recovers', async () => {
    const calls = [];
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: request => {
      calls.push(new URL(request.url).pathname);
      return new Response('{}', { status: 200 });
    } });
    try {
      const email = 'shadow-recovers@example.com';
      await local.kv.put(email, { seq: 1 });
      const stub = await local.coordinator(email);
      await fixture(stub, { failShadow: true, seed: removal(email) });
      await until(async () => (await json(stub, '/metrics')).callbacks >= 2);
      await fixture(stub, { failShadow: false });
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.equal(calls.length, 1);
      assert.equal(await local.kv.get(email), null);
      assert.equal((await json(stub, '/state')).alarm, null);
    } finally { await local.dispose(); }
  });

  it('keeps retrying the removal itself when both stores fail', async () => {
    let calls = 0;
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: () => {
      calls++;
      return new Response('', { status: 503 });
    } });
    try {
      const email = 'both-down@example.com';
      const stub = await local.coordinator(email);
      await fixture(stub, { failShadow: true, seed: removal(email) });
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.equal(calls, 8);
    } finally { await local.dispose(); }
  });

  it('answers a real unsubscribe as accepted while the shadow is down', async () => {
    const calls = [];
    const local = await startRuntime({ scheduler: true, withKv: false, extraBindings: bindings, outboundService: request => {
      calls.push(new URL(request.url).pathname);
      return new Response('{}', { status: 200 });
    } });
    try {
      const email = 'no-kv@example.com';
      const token = `v1:${createHmac('sha256', 'runtime-suite-hmac-secret-not-a-production-value').update(email).digest('hex')}`;
      const response = await local.runtime.dispatchFetch('http://localhost/api/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token }),
      });
      assert.equal(response.status, 202);
      assert.equal((await response.json()).status, 'accepted');
      assert.deepEqual(calls, ['/api/subscribers/query/lists']);
    } finally { await local.dispose(); }
  });

  it('drops orphaned work without provider or shadow I/O', async () => {
    let calls = 0;
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: () => { calls++; return new Response('', { status: 503 }); } });
    try {
      const stub = await local.coordinator('orphan@example.com');
      await fixture(stub, { seed: seed('orphan@example.com', 2) });
      await until(async () => (await json(stub, '/metrics')).callbacks > 0);
      assert.equal((await json(stub, '/state')).pending, null);
      assert.equal(calls, 0);
      assert.equal(await local.kv.get('orphan@example.com'), null);
    } finally { await local.dispose(); }
  });

  it('preserves even orphaned pending work during maintenance until resume', async () => {
    const local = await startRuntime({ scheduler: true });
    try {
      const stub = await local.coordinator('paused-orphan@example.com');
      await fixture(stub, { mode: 'legacy', seed: seed('paused-orphan@example.com', 2) });
      await until(async () => (await json(stub, '/metrics')).callbacks >= 2);
      assert.equal((await json(stub, '/state')).pending.seq, 2);
      await fixture(stub, { mode: 'on' });
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.deepEqual(local.attempts, []);
    } finally { await local.dispose(); }
  });

  it('pauses alarms and sync without spending attempts, then resumes authoritative work', async () => {
    let calls = 0;
    const local = await startRuntime({ scheduler: true, extraBindings: bindings, outboundService: () => { calls++; return new Response('', { status: 503 }); } });
    try {
      const email = 'paused@example.com';
      const stub = await local.coordinator(email);
      await fixture(stub, { mode: 'legacy', seed: seed(email) });
      await until(async () => (await json(stub, '/metrics')).callbacks >= 2);
      await stub.fetch('https://coordinator/sync', { method: 'POST' });
      let state = await json(stub, '/state');
      assert.equal(state.pending.attempts, 0);
      assert.equal(calls, 0);
      assert.equal(await local.kv.get(email), null);
      assert.ok((await json(stub, '/metrics')).delays.every(d => Math.abs(d - 60000) < 100));
      const rejected = await stub.fetch('https://coordinator/intent', { method: 'POST', body: JSON.stringify({ email, desired: 'unsubscribed' }) });
      assert.equal(rejected.status, 503);
      assert.equal((await json(stub, '/state')).intent.desired, 'subscribed');
      await fixture(stub, { mode: 'on' });
      await until(async () => (await json(stub, '/state')).pending === null);
      assert.equal(calls, 8);
      assert.ok(await local.kv.get(email));
    } finally { await local.dispose(); }
  });
});

for (const config of [{ COORDINATOR_MODE: 'legacy' }, { ENVIRONMENT: 'production' }, { ENVIRONMENT: 'production', SUBSCRIPTION_COORDINATOR: 'malformed' }]) {
  it(`fails closed public writes: ${JSON.stringify(config)}`, async () => {
    const local = await startRuntime({ extraBindings: config, withCoordinator: false });
    try {
      for (const path of ['/api/subscribe', '/api/unsubscribe', '/api/unsubscribe/confirm']) {
        const response = await local.runtime.dispatchFetch(`http://localhost${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.8' }, body: JSON.stringify({ email: 'closed@example.com', token: `v1:${createHmac('sha256', 'runtime-suite-hmac-secret-not-a-production-value').update('closed@example.com').digest('hex')}` }) });
        assert.equal(response.status, 503, path);
        await response.text();
      }
      assert.equal(await local.kv.get('closed@example.com'), null);
      assert.equal(await local.kv.get('rate_limit:198.51.100.8'), null, 'reject before rate-limit mutations');
      assert.deepEqual(local.attempts, []);
    } finally { await local.dispose(); }
  });
}
