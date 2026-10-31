// Tests for the read-only subscriber inventory.
//
// Fixtures only: no network, no Cloudflare account, no Listmonk instance.
// The cases that matter are the ones where a naive implementation would state
// something it cannot know — list membership read as subscription status, a
// failed page read as absence, an unreadable record read as absence, or a
// pseudonym that is really a hash of the address.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

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
  writeReport,
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

function page(results, { total = results.length } = {}) {
  return { data: { results, total, page: 1, per_page: 100 } };
}

function subscriber(email, { global = 'enabled', listStatus, listId = 3, otherLists = [] } = {}) {
  const lists = [...otherLists];
  if (listStatus !== undefined) lists.push({ id: listId, subscription_status: listStatus });
  return { email, status: global, lists };
}

function recordingReader(handler) {
  const methods = [];
  const paths = [];
  return {
    methods,
    paths,
    reader: {
      async get(path) {
        methods.push('GET');
        paths.push(path);
        const result = handler(path);
        if (result instanceof Error) throw result;
        return result;
      },
      refuseMutation(method) {
        throw new Error(`read-only client: refusing ${method}`);
      },
    },
  };
}

const COMPLETE = { subscribersComplete: true };

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
    const result = readKvExport([
      { key: 'a@example.com', value: '{"timestamp":"2026-01-01T00:00:00Z"}' },
      { key: 'rate_limit:198.51.100.1', value: '{"count":1}' },
      { key: 'cache:subscriber_count', value: '{"count":10}' },
    ]);
    assert.deepEqual([...result.presentEmails], ['a@example.com']);
    assert.equal(result.excludedKeys, 2);
    assert.deepEqual(result.unreadable, []);

    assert.equal(readKvExport([['b@example.com', { timestamp: 'x' }]]).presentEmails.size, 1);
    assert.equal(readKvExport({ 'c@example.com': '{"timestamp":"y"}' }).presentEmails.size, 1);
  });

  it('keeps an unreadable record present while reporting it', () => {
    const result = readKvExport([
      { key: 'broken@example.com', value: '{not json' },
      { key: 'not-an-address', value: '{}' },
      { key: 'array@example.com', value: '[]' },
    ]);
    // Presence survives a parse failure: the key proves the address is there.
    assert.ok(result.presentEmails.has('broken@example.com'));
    assert.ok(result.presentEmails.has('array@example.com'));
    assert.equal(result.byEmail.get('broken@example.com').readable, false);
    assert.equal(result.unreadable.filter((entry) => entry.email).length, 2);
    assert.ok(result.unreadable.some((entry) => entry.key === 'not-an-address'));
  });

  it('normalizes and deduplicates keys, preferring a readable duplicate', () => {
    const result = readKvExport([
      { key: ' Dup@Example.com ', value: '{broken' },
      { key: 'dup@example.com', value: '{"timestamp":"z"}' },
    ]);
    assert.equal(result.presentEmails.size, 1);
    assert.equal(result.byEmail.get('dup@example.com').readable, true);
    // The failed first copy is still reported rather than silently dropped.
    assert.ok(result.unreadable.some((entry) => entry.email === 'dup@example.com'));
  });
});

describe('list membership is not subscription status', () => {
  it('does not read presence in the list query as confirmed', () => {
    // The installed Listmonk returns every status for ?list_id= unless filtered,
    // so appearance proves nothing.
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', { listStatus: undefined })])],
      queriedEmails: new Set(['a@example.com']),
      complete: true,
      failures: [],
      listId: 3,
    });
    const entry = collected.upstreamByEmail.get('a@example.com');
    assert.equal(entry.listStatus, 'unknown');
    assert.equal(entry.listEvidence, 'list-query-only');
    assert.equal(classifyAddress(entry, { inKv: true, readable: true }, COMPLETE), 'needs_investigation');
  });

  it('reports a target-list unsubscribe as unsubscribed, not active', () => {
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', { listStatus: 'unsubscribed' })])],
      // The real query returns unsubscribed rows too, which is what made the
      // previous version report them as both_active.
      queriedEmails: new Set(['a@example.com']),
      complete: true,
      failures: [],
      listId: 3,
    });
    const entry = collected.upstreamByEmail.get('a@example.com');
    assert.equal(entry.listStatus, 'unsubscribed');
    assert.equal(classifyAddress(entry, { inKv: true, readable: true }, COMPLETE), 'upstream_unsubscribed');
  });

  it('ignores an unsubscribed marker belonging to another list', () => {
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', { otherLists: [{ id: 9, subscription_status: 'unsubscribed' }] })])],
      queriedEmails: new Set(),
      complete: true,
      failures: [],
      listId: 3,
    });
    const entry = collected.upstreamByEmail.get('a@example.com');
    assert.equal(entry.listStatus, 'unknown');
    assert.equal(entry.listEvidence, 'no-list-entry');
    assert.equal(classifyAddress(entry, { inKv: true, readable: true }, COMPLETE), 'needs_investigation');
  });

  it('does not promote missing global status to active', () => {
    const collected = collectUpstream({
      pages: [page([{ email: 'a@example.com', lists: [{ id: 3, subscription_status: 'confirmed' }] }])],
      queriedEmails: new Set(['a@example.com']),
      complete: true,
      failures: [],
      listId: 3,
    });
    const entry = collected.upstreamByEmail.get('a@example.com');
    assert.equal(entry.globalStatus, 'unknown');
    assert.equal(entry.listStatus, 'confirmed');
    assert.equal(classifyAddress(entry, { inKv: true, readable: true }, COMPLETE), 'needs_investigation');
  });

  it('reports an unrecognised status instead of interpreting it', () => {
    const collected = collectUpstream({
      pages: [page([subscriber('a@example.com', { listStatus: 'paused' })])],
      queriedEmails: new Set(),
      complete: true,
      failures: [],
      listId: 3,
    });
    const entry = collected.upstreamByEmail.get('a@example.com');
    assert.equal(entry.listEvidence, 'unrecognized-list-status');
    assert.equal(classifyAddress(entry, { inKv: true, readable: true }, COMPLETE), 'needs_investigation');
  });

  it('treats a confirmed list next to a disabled subscriber as contradictory', () => {
    assert.equal(
      classifyAddress({ found: true, globalStatus: 'disabled', listStatus: 'confirmed' }, { inKv: true, readable: true }, COMPLETE),
      'needs_investigation',
    );
  });
});

describe('classification', () => {
  const cases = [
    ['subscribed in both', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }, true, 'both_active'],
    ['missing upstream', { found: false, readable: true }, true, 'kv_only_missing_upstream'],
    ['upstream unsubscribed', { found: true, globalStatus: 'enabled', listStatus: 'unsubscribed' }, true, 'upstream_unsubscribed'],
    ['globally blocklisted', { found: true, globalStatus: 'blocklisted', listStatus: 'unsubscribed' }, true, 'blocklisted'],
    ['blocklisted without KV', { found: true, globalStatus: 'blocklisted', listStatus: 'confirmed' }, false, 'blocklisted'],
    ['listmonk only', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }, false, 'listmonk_only'],
    ['unsubscribed and no KV record', { found: true, globalStatus: 'enabled', listStatus: 'unsubscribed' }, false, 'neither_active'],
    ['unconfirmed opt-in', { found: true, globalStatus: 'enabled', listStatus: 'unconfirmed' }, true, 'needs_investigation'],
    ['unreadable upstream record', { found: true, readable: false }, true, 'needs_investigation'],
  ];

  for (const [name, upstream, hasKv, expected] of cases) {
    it(`classifies ${name}`, () => {
      assert.equal(classifyAddress(upstream, { inKv: hasKv, readable: true }, COMPLETE), expected);
    });
  }

  it('does not treat an unreadable KV record as absent', () => {
    // Before this fix the address dropped out of the presence index and came
    // back as listmonk_only.
    assert.equal(
      classifyAddress({ found: true, globalStatus: 'enabled', listStatus: 'confirmed' }, { inKv: true, readable: false }, COMPLETE),
      'needs_investigation',
    );
  });

  it('does not assert absence upstream when coverage is incomplete', () => {
    assert.equal(
      classifyAddress({ found: false, readable: true }, { inKv: true, readable: true }, { subscribersComplete: false }),
      'needs_investigation',
    );
  });
});

describe('pagination and coverage', () => {
  it('walks subscriber pages until the reported total is reached', async () => {
    const { reader, paths } = recordingReader((path) => {
      if (path.includes('list_id')) return page([]);
      if (path.endsWith('page=1')) return page([subscriber('a@example.com', { listStatus: 'confirmed' })], { total: 2 });
      return page([subscriber('b@example.com', { listStatus: 'confirmed' })], { total: 2 });
    });

    const result = await readUpstream(reader, { listId: 3, perPage: 100 });
    assert.equal(result.complete, true);
    assert.equal(result.pages.length, 2);
    assert.equal(result.coverage.subscribersRead, 2);
    assert.ok(paths.some((path) => path.includes('list_id=3')));
  });

  it('treats an empty page before the reported total as incomplete', async () => {
    const { reader } = recordingReader((path) => {
      if (path.includes('list_id')) return page([]);
      if (path.endsWith('page=1')) return page([subscriber('a@example.com')], { total: 200 });
      return page([], { total: 200 });
    });

    const result = await readUpstream(reader, { listId: 3 });
    assert.equal(result.complete, false);
    assert.ok(result.failures.some((f) => /empty page/.test(f.error)));
  });

  it('treats a page-limit stop as incomplete', async () => {
    const { reader } = recordingReader((path) => {
      if (path.includes('list_id')) return page([]);
      return page([subscriber(`a${Math.random()}@example.com`)], { total: 100000 });
    });

    const result = await readUpstream(reader, { listId: 3, maxPages: 3 });
    assert.equal(result.complete, false);
    assert.ok(result.failures.some((f) => /page limit/.test(f.error)));
  });

  it('treats a non-array payload as incomplete', async () => {
    const { reader } = recordingReader((path) => (path.includes('list_id') ? page([]) : { data: { total: 5 } }));
    const result = await readUpstream(reader, { listId: 3 });
    assert.equal(result.complete, false);
  });

  it('keeps an incomplete subscriber read out of the absence bucket', async () => {
    let call = 0;
    const reader = {
      async get() {
        call += 1;
        if (call === 1) return page([subscriber('seen@example.com', { listStatus: 'confirmed' })], { total: 200 });
        throw new Error('HTTP 500');
      },
      refuseMutation() { throw new Error('nope'); },
    };

    const upstream = await readUpstream(reader, { listId: 3 });
    assert.equal(upstream.complete, false);

    const kv = readKvExport([{ key: 'seen@example.com', value: '{}' }, { key: 'unseen@example.com', value: '{}' }]);
    const collected = collectUpstream({ ...upstream, listId: 3 });
    const inventory = buildInventory({ kv, upstreamByEmail: collected.upstreamByEmail, coverage: upstream.coverage });

    assert.equal(inventory.counts.both_active, 1);
    // The address that was never reached must not be reported as missing.
    assert.equal(inventory.counts.kv_only_missing_upstream, 0);
    assert.equal(inventory.counts.needs_investigation, 1);
  });

  it('records a failed list phase without discarding the subscriber pages', async () => {
    const reader = {
      async get(path) {
        if (path.includes('list_id')) throw new Error('HTTP 403');
        return page([subscriber('a@example.com', { listStatus: 'confirmed' })]);
      },
      refuseMutation() { throw new Error('nope'); },
    };

    const upstream = await readUpstream(reader, { listId: 3 });
    assert.equal(upstream.pages.length, 1);
    assert.equal(upstream.coverage.subscribersComplete, true);
    assert.equal(upstream.coverage.listQueryComplete, false);
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

    for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
      assert.throws(() => reader.refuseMutation(method), new RegExp(`refusing ${method}`));
    }
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
      coverage: COMPLETE,
    });
    const report = buildReport({
      inventory,
      window: { startedAt: 'start', finishedAt: 'end' },
      source: { complete: true, coverage: COMPLETE },
      includeIdentifiers: false,
      pseudonymize: createPseudonymizer('c'.repeat(32)),
    });

    assert.equal(report.identifiers, undefined);
    assert.equal(report.counts.both_active, 1);
    assert.equal(report.unreadable, 0);
    assert.deepEqual(Object.keys(report.counts).sort(), [...BUCKETS].sort());
    assert.match(report.caveats.join(' '), /No bucket implies an action/);
    assert.match(report.caveats.join(' '), /must not be overwritten from KV/);
    assert.match(report.caveats.join(' '), /List membership is not subscription status/);
    assert.match(report.caveats.join(' '), /unproven absence/);
  });

  it('emits pseudonyms, never addresses, when identifiers are requested', () => {
    const pseudonymize = createPseudonymizer('d'.repeat(32));
    const inventory = buildInventory({
      kv: readKvExport([{ key: 'a@example.com', value: '{}' }, { key: 'b@example.com', value: '{}' }]),
      upstreamByEmail: new Map([['a@example.com', { found: true, globalStatus: 'enabled', listStatus: 'confirmed' }]]),
      coverage: COMPLETE,
    });
    const report = buildReport({
      inventory,
      window: { startedAt: 'start', finishedAt: 'end' },
      source: { complete: true, coverage: COMPLETE },
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
  it('refuses a plain path inside the Git working tree', () => {
    assert.throws(
      () => assertOutsideRepository(join(workerDir, 'inventory.json')),
      /refusing to write a report inside the Git working tree/,
    );
  });

  it('refuses a file symlink that points into the Git working tree', () => {
    const dir = mkdtempSync(join(tmpdir(), 'inventory-'));
    const target = join(workerDir, 'scripts', 'inventory-subscribers.mjs');
    const link = join(dir, 'report.json');
    symlinkSync(target, link);

    // The link itself lives outside the repository, so a path-only check passes;
    // the resolved destination does not.
    assert.throws(() => assertOutsideRepository(link), /symbolic link/);
  });

  it('refuses a directory symlink that resolves into the Git working tree', () => {
    const dir = mkdtempSync(join(tmpdir(), 'inventory-'));
    const link = join(dir, 'reports');
    symlinkSync(join(workerDir, 'scripts'), link);

    assert.throws(
      () => assertOutsideRepository(join(link, 'inventory.json')),
      /refusing to write a report inside the Git working tree/,
    );
  });

  it('publishes with private permissions and refuses to follow a symlink', () => {
    const dir = mkdtempSync(join(tmpdir(), 'inventory-'));
    const target = join(dir, 'report.json');
    writeReport(target, '{"ok":true}\n');

    const mode = statSync(target).mode & 0o777;
    assert.equal(mode, 0o600);
    assert.equal(readFileSync(target, 'utf8'), '{"ok":true}\n');

    const link = join(dir, 'link.json');
    symlinkSync(target, link);
    assert.throws(() => writeReport(link, '{"nope":true}\n'), /symbolic link/);
  });
});

describe('command line', () => {
  it('produces a report end to end while issuing only GET requests', async () => {
    const methods = [];
    const server = createServer((request, response) => {
      methods.push(request.method);
      const url = new URL(request.url, 'http://localhost');
      const listed = url.searchParams.get('list_id') !== null;
      // Mirrors the installed Listmonk: ?list_id= includes unsubscribed rows.
      const results = [
        subscriber('both@example.com', { listStatus: 'confirmed' }),
        subscriber('gone@example.com', { listStatus: 'unsubscribed' }),
      ];
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { results: listed ? results : results, total: results.length, page: 1, per_page: 100 } }));
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
      assert.equal(report.counts.needs_investigation, 0);
      assert.equal(report.identifiers, undefined);
      assert.ok(!JSON.stringify(report).includes('@example.com'));
      assert.deepEqual([...new Set(methods)], ['GET']);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });

  it('exits non-zero and withholds the absence bucket when a store fails', async () => {
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

      assert.equal(run.status, 2, run.stderr);
      const report = JSON.parse(run.stdout);
      assert.equal(report.complete, false);
      assert.equal(report.coverage.subscribersComplete, false);
      assert.match(report.incompleteReason, /did not cover its full space/);
      // The KV address was never proven absent upstream.
      assert.equal(report.counts.kv_only_missing_upstream, 0);
      assert.equal(report.counts.needs_investigation, 1);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });
});
