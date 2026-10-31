// Tests for the read-only subscriber inventory.
//
// Fixtures only: no network, no Cloudflare account, no Listmonk instance.
// The cases that matter are the ones where a naive implementation would state
// something it cannot know — a failed page read as absence, an absent status
// field as a status, or a pseudonym that is really a hash of the address.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BUCKETS,
  assertOutsideRepository,
  buildInventory,
  buildReport,
  classifyAddress,
  collectUpstream,
  createListmonkReader,
  createPseudonymizer,
  isNonSubscriberKey,
  readKvExport,
  readUpstream,
} from './inventory-subscribers.mjs';

const workerDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const execFileAsync = promisify(execFile);

// Runs the CLI without blocking the event loop: the fixture server lives in this
// process, so a synchronous spawn would deadlock waiting on itself.
async function runCli(args, env) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['scripts/inventory-subscribers.mjs', ...args], {
      cwd: workerDir,
      encoding: 'utf8',
      env: { ...process.env, ...env },
    });
    return { status: 0, stdout, stderr };
  } catch (error) {
    return { status: error.code ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
}

function page(results, { total = results.length, perPage = 100 } = {}) {
  return { data: { results, total, page: 1, per_page: perPage } };
}

function subscriber(email, status = 'enabled', lists) {
  return lists === undefined ? { email, status } : { email, status, lists };
}

/** A reader double that records every method it is asked to use. */
function recordingReader(pagesByPath) {
  const methods = [];
  const paths = [];
  return {
    methods,
    paths,
    reader: {
      async get(path) {
        methods.push('GET');
        paths.push(path);
        const handler = pagesByPath(path);
        if (handler instanceof Error) throw handler;
        return handler;
      },
      refuseMutation(method) {
        throw new Error(`read-only client: refusing ${method}`);
      },
    },
  };
}

describe('key space', () => {
  it('excludes rate-limit and cache keys', () => {
    assert.equal(isNonSubscriberKey('rate_limit:198.51.100.1'), true);
    assert.equal(isNonSubscriberKey('cache:subscriber_count'), true);
    assert.equal(isNonSubscriberKey('cache:linkedin_last_known:abc'), true);
    assert.equal(isNonSubscriberKey('someone@example.com'), false);
  });
});

describe('KV export normalisation', () => {
  it('accepts the three export shapes and drops non-membership keys', () => {
    const arrayShape = readKvExport([
      { key: 'a@example.com', value: '{"timestamp":"2026-01-01T00:00:00Z"}' },
      { key: 'rate_limit:198.51.100.1', value: '{"count":1}' },
      { key: 'cache:subscriber_count', value: '{"count":10}' },
    ]);
    assert.deepEqual(arrayShape.subscribers.map((entry) => entry.email), ['a@example.com']);
    assert.deepEqual(arrayShape.unreadable, []);

    const pairShape = readKvExport([['b@example.com', { timestamp: 'x' }]]);
    assert.equal(pairShape.subscribers.length, 1);

    const objectShape = readKvExport({ 'c@example.com': '{"timestamp":"y"}' });
    assert.equal(objectShape.subscribers.length, 1);
  });

  it('reports an unreadable record instead of dropping it', () => {
    const result = readKvExport([
      { key: 'broken@example.com', value: '{not json' },
      { key: 'not-an-address', value: '{}' },
      { key: 'array@example.com', value: '[]' },
    ]);
    assert.equal(result.subscribers.length, 0);
    assert.equal(result.unreadable.length, 3);
  });
});

describe('classification', () => {
  const cases = [
    ['subscribed in both', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }, true, 'both_active'],
    ['missing upstream', { found: false, readable: true }, true, 'kv_only_missing_upstream'],
    ['upstream unsubscribed', { found: true, globalStatus: 'enabled', listStatus: 'unsubscribed' }, true, 'upstream_unsubscribed'],
    ['globally blocklisted', { found: true, globalStatus: 'blocklisted', listStatus: 'unsubscribed' }, true, 'blocklisted'],
    ['listmonk only', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }, false, 'listmonk_only'],
    ['unreadable upstream record', { found: true, readable: false }, true, 'needs_investigation'],
  ];

  for (const [name, upstream, hasKv, expected] of cases) {
    it(`classifies ${name}`, () => {
      assert.equal(classifyAddress(upstream, hasKv), expected);
    });
  }

  it('does not guess when the list status is unknown', () => {
    // Present upstream, no list information and no unsubscribed marker:
    // "never added" and "removed without a status" are indistinguishable.
    assert.equal(
      classifyAddress({ found: true, globalStatus: 'enabled', listStatus: 'unknown' }, true),
      'needs_investigation',
    );
  });

  it('does not guess when a status value is unrecognised', () => {
    assert.equal(
      classifyAddress({ found: true, globalStatus: 'enabled', listStatus: 'paused' }, true),
      'needs_investigation',
    );
  });

  it('keeps blocklisted ahead of the KV/upstream split', () => {
    assert.equal(classifyAddress({ found: true, globalStatus: 'blocklisted', listStatus: 'confirmed' }, false), 'blocklisted');
  });
});

describe('upstream collection', () => {
  it('uses list membership for the list status when the payload carries it', () => {
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', 'enabled', [{ subscription_status: 'unsubscribed' }])])],
      listedEmails: new Set(),
      complete: true,
      failures: [],
    });
    assert.equal(collected.upstreamByEmail.get('a@example.com').listStatus, 'unsubscribed');
  });

  it('prefers confirmed membership for addresses in the list query', () => {
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', 'enabled', [{ subscription_status: 'unsubscribed' }])])],
      listedEmails: new Set(['a@example.com']),
      complete: true,
      failures: [],
    });
    assert.equal(collected.upstreamByEmail.get('a@example.com').listStatus, 'confirmed');
  });

  it('records an address seen only in the list query', () => {
    const collected = collectUpstream({ pages: [], listedEmails: new Set(['b@example.com']), complete: true, failures: [] });
    assert.equal(collected.upstreamByEmail.get('b@example.com').listStatus, 'confirmed');
  });
});

describe('pagination', () => {
  const first = page([subscriber('a@example.com')], { total: 2 });
  const second = page([subscriber('b@example.com')], { total: 2 });

  it('walks subscriber pages until the total is reached', async () => {
    const { reader, paths } = recordingReader((path) => {
      if (path.startsWith('/api/subscribers?per_page') && path.endsWith('page=1')) return first;
      if (path.startsWith('/api/subscribers?per_page') && path.endsWith('page=2')) return second;
      return page([subscriber('a@example.com')], { total: 1 });
    });

    const result = await readUpstream(reader, { listId: 3, perPage: 100 });
    assert.equal(result.complete, true);
    assert.equal(result.pages.length, 2);
    assert.ok(paths.some((path) => path.includes('list_id=3')));
  });

  it('stops on an empty page rather than trusting a total', async () => {
    const { reader, paths } = recordingReader((path) => {
      if (path.startsWith('/api/subscribers?per_page') && path.endsWith('page=1')) {
        return page([subscriber('a@example.com')], { total: 999 });
      }
      return page([], { total: 999 });
    });

    const result = await readUpstream(reader, { listId: 3 });
    assert.equal(result.pages.length, 2);
    assert.equal(result.complete, true);
    assert.equal(paths.filter((path) => path.includes('list_id=3')).length, 1);
  });
});

describe('partial failures', () => {
  it('reports an incomplete read instead of missing subscribers', async () => {
    let call = 0;
    const reader = {
      async get() {
        call += 1;
        if (call === 1) return page([subscriber('a@example.com', 'enabled', [{ subscription_status: 'unsubscribed' }])], { total: 200 });
        throw new Error('HTTP 500');
      },
      refuseMutation() { throw new Error('nope'); },
    };

    const upstream = await readUpstream(reader, { listId: 3 });
    assert.equal(upstream.complete, false);
    assert.ok(upstream.failures.some((failure) => failure.phase === 'subscribers'));

    const collected = collectUpstream(upstream);
    const inventory = buildInventory({ kv: readKvExport([{ key: 'a@example.com', value: '{}' }]), upstreamByEmail: collected.upstreamByEmail });
    const report = buildReport({
      inventory,
      window: { startedAt: 'start', finishedAt: 'end' },
      source: { complete: false, failures: upstream.failures },
      includeIdentifiers: false,
      pseudonymize: () => 'unused',
    });

    assert.equal(report.complete, false);
    assert.match(report.incompleteReason, /could not be read/);
    assert.deepEqual(report.failures, upstream.failures);
    // The one address that was read is still classified on its merits.
    assert.equal(inventory.counts.upstream_unsubscribed, 1);
  });

  it('marks the list phase as failed without discarding the subscriber pages', async () => {
    const reader = {
      async get(path) {
        if (path.includes('list_id')) throw new Error('HTTP 403');
        return page([subscriber('a@example.com', 'enabled', [{ subscription_status: 'confirmed' }])]);
      },
      refuseMutation() { throw new Error('nope'); },
    };

    const upstream = await readUpstream(reader, { listId: 3 });
    assert.equal(upstream.complete, false);
    assert.equal(upstream.pages.length, 1);
    assert.ok(upstream.failures.some((failure) => failure.phase === 'list'));
  });
});

describe('no-write guarantee', () => {
  it('issues only GET requests', async () => {
    const methods = [];
    const reader = createListmonkReader({
      apiUrl: 'https://mail.invalid',
      user: 'u',
      token: 't',
      fetchImpl: async (_url, init) => {
        methods.push(init.method);
        return { ok: true, status: 200, json: async () => page([]) };
      },
    });

    await readUpstream(reader, { listId: 3 });
    assert.ok(methods.length > 0);
    assert.deepEqual([...new Set(methods)], ['GET']);
  });

  it('refuses a mutation method before building a request', () => {
    let called = false;
    const reader = createListmonkReader({
      apiUrl: 'https://mail.invalid',
      user: 'u',
      token: 't',
      fetchImpl: async () => { called = true; return { ok: true, status: 200, json: async () => ({}) }; },
    });

    assert.throws(() => reader.refuseMutation('PUT'), /refusing PUT/);
    assert.throws(() => reader.refuseMutation('POST'), /refusing POST/);
    assert.throws(() => reader.refuseMutation('DELETE'), /refusing DELETE/);
    assert.equal(called, false);
  });

  it('retries a rate-limited page and still only reads', async () => {
    let attempts = 0;
    const methods = [];
    const reader = createListmonkReader({
      apiUrl: 'https://mail.invalid',
      user: 'u',
      token: 't',
      delayMs: 1,
      fetchImpl: async (_url, init) => {
        attempts += 1;
        methods.push(init.method);
        if (attempts === 1) return { ok: false, status: 429, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => page([]) };
      },
    });

    await readUpstream(reader, { listId: 3 });
    assert.ok(attempts >= 2);
    assert.deepEqual([...new Set(methods)], ['GET']);
  });
});

describe('pseudonymisation and report shape', () => {
  it('refuses a missing or short secret', () => {
    assert.throws(() => createPseudonymizer(undefined), /at least 16/);
    assert.throws(() => createPseudonymizer('short'), /at least 16/);
  });

  it('is keyed, deterministic and not an unsalted hash', () => {
    const one = createPseudonymizer('a'.repeat(32));
    const two = createPseudonymizer('b'.repeat(32));
    const email = 'someone@example.com';

    assert.equal(one(email), one(email));
    assert.notEqual(one(email), two(email));
    assert.notEqual(one(email), createHash('sha256').update(email).digest('hex').slice(0, 32));
    assert.equal(one('Someone@Example.com '), one(email));
  });

  it('reports aggregate counts only by default', () => {
    const inventory = buildInventory({
      kv: readKvExport([{ key: 'a@example.com', value: '{}' }]),
      upstreamByEmail: new Map([['a@example.com', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }]]),
    });
    const report = buildReport({
      inventory,
      window: { startedAt: 'start', finishedAt: 'end' },
      source: { complete: true },
      includeIdentifiers: false,
      pseudonymize: createPseudonymizer('c'.repeat(32)),
    });

    assert.equal(report.identifiers, undefined);
    assert.equal(report.complete, true);
    assert.equal(report.counts.both_active, 1);
    assert.equal(report.unreadable, 0);
    assert.deepEqual(Object.keys(report.counts).sort(), [...BUCKETS].sort());
    assert.match(report.caveats.join(' '), /No bucket implies an action/);
    assert.match(report.caveats.join(' '), /must not be overwritten from KV/);
  });

  it('emits pseudonyms, never addresses, when identifiers are requested', () => {
    const pseudonymize = createPseudonymizer('d'.repeat(32));
    const inventory = buildInventory({
      kv: readKvExport([{ key: 'a@example.com', value: '{}' }, { key: 'b@example.com', value: '{}' }]),
      upstreamByEmail: new Map([['a@example.com', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }]]),
    });
    const report = buildReport({
      inventory,
      window: { startedAt: 'start', finishedAt: 'end' },
      source: { complete: true },
      includeIdentifiers: true,
      pseudonymize,
    });

    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes('a@example.com'));
    assert.ok(!serialized.includes('b@example.com'));
    assert.deepEqual(report.identifiers.both_active, [pseudonymize('a@example.com')]);
    assert.deepEqual(report.identifiers.kv_only_missing_upstream, [pseudonymize('b@example.com')]);
  });
});

describe('report destination', () => {
  it('refuses to write inside the Git working tree', () => {
    assert.throws(
      () => assertOutsideRepository(join(workerDir, 'inventory.json')),
      /refusing to write a report inside the Git working tree/,
    );
  });
});

describe('command line', () => {
  it('produces a report end to end while issuing only GET requests', async () => {
    const methods = [];
    const server = createServer((request, response) => {
      methods.push(request.method);
      const url = new URL(request.url, 'http://localhost');
      const listed = url.searchParams.get('list_id') !== null;
      const results = listed
        ? [{ email: 'both@example.com', status: 'enabled' }]
        : [
            { email: 'both@example.com', status: 'enabled', lists: [{ subscription_status: 'confirmed' }] },
            { email: 'gone@example.com', status: 'enabled', lists: [{ subscription_status: 'unsubscribed' }] },
          ];
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { results, total: results.length, page: 1, per_page: 100 } }));
    });

    await new Promise((done) => server.listen(0, '127.0.0.1', done));
    const { port } = server.address();

    try {
      const dir = mkdtempSync(join(tmpdir(), 'inventory-'));
      const kvPath = join(dir, 'kv.json');
      const outPath = join(dir, 'report.json');
      writeFileSync(kvPath, JSON.stringify([
        { key: 'both@example.com', value: '{"timestamp":"2026-01-01T00:00:00Z"}' },
        { key: 'gone@example.com', value: '{"timestamp":"2026-01-01T00:00:00Z"}' },
        { key: 'absent@example.com', value: '{"timestamp":"2026-01-01T00:00:00Z"}' },
        { key: 'cache:subscriber_count', value: '{"count":10}' },
      ]));

      const run = await runCli(['--kv', kvPath, '--out', outPath], {
        LISTMONK_API_URL: `http://127.0.0.1:${port}`,
        LISTMONK_API_USER: 'fixture',
        LISTMONK_API_TOKEN: 'fixture',
        LISTMONK_LIST_ID: '3',
        INVENTORY_HMAC_SECRET: 'e'.repeat(32),
      });

      assert.equal(run.status, 0, run.stderr);
      const report = JSON.parse(readFileSync(outPath, 'utf8'));
      assert.equal(report.complete, true);
      assert.equal(report.counts.both_active, 1);
      assert.equal(report.counts.upstream_unsubscribed, 1);
      assert.equal(report.counts.kv_only_missing_upstream, 1);
      assert.equal(report.identifiers, undefined);
      assert.ok(!JSON.stringify(report).includes('@example.com'));
      assert.deepEqual([...new Set(methods)], ['GET']);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });

  it('exits non-zero when a store cannot be read in full', async () => {
    const server = createServer((request, response) => {
      response.writeHead(500, { 'Content-Type': 'application/json' });
      response.end('{"error":"boom"}');
    });
    await new Promise((done) => server.listen(0, '127.0.0.1', done));
    const { port } = server.address();

    try {
      const dir = mkdtempSync(join(tmpdir(), 'inventory-'));
      const kvPath = join(dir, 'kv.json');
      writeFileSync(kvPath, JSON.stringify([{ key: 'a@example.com', value: '{}' }]));

      const run = await runCli(['--kv', kvPath], {
        LISTMONK_API_URL: `http://127.0.0.1:${port}`,
        LISTMONK_API_USER: 'fixture',
        LISTMONK_API_TOKEN: 'fixture',
        LISTMONK_LIST_ID: '3',
        INVENTORY_HMAC_SECRET: 'e'.repeat(32),
      });

      // Exit 2 is "read completed partially"; the report on stdout is marked
      // incomplete rather than asserting that subscribers are missing.
      assert.equal(run.status, 2, run.stderr);
      const report = JSON.parse(run.stdout);
      assert.equal(report.complete, false);
      assert.match(report.incompleteReason, /could not be read/);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });
});
