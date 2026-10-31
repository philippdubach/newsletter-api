#!/usr/bin/env node
// Read-only inventory of subscriber drift between KV and Listmonk.
//
// This tool answers one question: what differs between the two stores, and
// which differences can be explained without guessing a subscriber's latest
// intent? It is an inventory, not a migration. No bucket in the output implies
// an action, and a KV-only record must never be treated as a queued
// re-subscription.
//
// Why that matters: Listmonk's own unsubscribe links (`{{ UnsubscribeURL }}`,
// and the `List-Unsubscribe` header targeting
// /subscription/<campaign>/<subscriber>) mutate subscription state without the
// Worker being involved. A native unsubscribe is an expression of user intent.
// Converging Listmonk toward an older KV "subscribed" record would silently
// undo it, so this tool reports and never resolves.
//
// Three rules keep the report from stating things it cannot know:
//
//   1. List membership is not subscription status. In the installed Listmonk,
//      GET /api/subscribers?list_id=N returns every subscription status for
//      that list unless separately filtered, so a row's presence in that query
//      is evidence of nothing. Only `lists[].subscription_status` for the
//      target list id is read as a status.
//   2. Absence is a claim. An address is reported as missing upstream only when
//      the subscriber read provably covered the whole space. Otherwise the
//      absence is unproven and the address needs investigation.
//   3. Unreadable is not absent. A KV value that does not parse still proves
//      the address is present, so presence and readability are tracked
//      separately.
//
// Plus:
//   * Only GET requests are issued to Listmonk. Any other method throws.
//   * No writes to KV, no subscription changes, no welcome mail, no
//     unsubscribe requests.
//   * Identifiers are keyed HMAC-SHA256 under a secret you supply. There is no
//     unsalted fallback, and aggregate counts are the default.
//   * Reports are written through a private temporary file and renamed into
//     place; a symlinked destination or a destination inside a Git working tree
//     is refused.
//
// Usage:
//   LISTMONK_API_URL=... LISTMONK_API_USER=... LISTMONK_API_TOKEN=... \
//   LISTMONK_LIST_ID=3 INVENTORY_HMAC_SECRET=... \
//   node scripts/inventory-subscribers.mjs --kv kv-export.json --out /tmp/inventory.json
//
// The KV export is a JSON file holding either an array of
// `{ key, value }` objects, an array of `[key, value]` pairs, or an object
// mapping key to value. Values may be raw strings or already-parsed records.

import { createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, lstatSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Keys the Worker writes that are not subscriber records. Anything else in the
// namespace is expected to be keyed by normalized address.
const NON_SUBSCRIBER_PREFIXES = ['rate_limit:', 'cache:'];

const EXPECTED_EMAIL = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

const GLOBAL_STATUSES = new Set(['enabled', 'disabled', 'blocklisted', 'unknown']);
const LIST_STATUSES = new Set(['confirmed', 'unconfirmed', 'unsubscribed', 'unknown']);

export const BUCKETS = [
  'both_active',
  'kv_only_missing_upstream',
  'upstream_unsubscribed',
  'blocklisted',
  'listmonk_only',
  'neither_active',
  'needs_investigation',
];

/** True for keys the Worker uses for rate limiting and caching, not membership. */
export function isNonSubscriberKey(key) {
  return NON_SUBSCRIBER_PREFIXES.some((prefix) => key.startsWith(prefix));
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : null;
}

/**
 * Normalizes a raw KV export into a presence index plus the records that could
 * be read.
 *
 * Presence and readability are deliberately separate: an entry whose value does
 * not parse still proves that the address exists in KV, so treating it as
 * absent would let it surface later as "Listmonk-only". Keys are normalized and
 * deduplicated, and a readable duplicate wins over an unreadable one.
 */
export function readKvExport(raw) {
  const byEmail = new Map();
  const unreadable = [];
  let scannedKeys = 0;
  let excludedKeys = 0;

  const push = (key, value) => {
    if (typeof key !== 'string' || key.length === 0) {
      unreadable.push({ reason: 'key is not a non-empty string' });
      return;
    }
    scannedKeys += 1;
    if (isNonSubscriberKey(key)) {
      excludedKeys += 1;
      return;
    }
    const email = normalizeEmail(key);
    if (!email || !EXPECTED_EMAIL.test(email)) {
      unreadable.push({ key, reason: 'key is not a valid address' });
      return;
    }

    let record = value;
    let readable = true;
    let reason;
    if (typeof record === 'string') {
      try {
        record = JSON.parse(record);
      } catch {
        readable = false;
        reason = 'record is not valid JSON';
      }
    }
    if (readable && (!record || typeof record !== 'object' || Array.isArray(record))) {
      readable = false;
      reason = 'record is not an object';
    }

    const existing = byEmail.get(email);
    if (!existing || (!existing.readable && readable)) {
      byEmail.set(email, readable ? { email, readable: true, record } : { email, readable: false, reason });
    }
    if (!readable) unreadable.push({ email, reason });
  };

  if (Array.isArray(raw)) {
    for (const item of raw) {
      if (Array.isArray(item) && item.length === 2) push(item[0], item[1]);
      else if (item && typeof item === 'object' && 'key' in item) push(item.key, item.value);
      else unreadable.push({ reason: 'unrecognized export entry' });
    }
  } else if (raw && typeof raw === 'object') {
    for (const [key, value] of Object.entries(raw)) push(key, value);
  } else {
    unreadable.push({ reason: 'export is neither an array nor an object' });
  }

  const records = [...byEmail.values()];
  return {
    byEmail,
    records,
    presentEmails: new Set(byEmail.keys()),
    unreadable,
    scannedKeys,
    excludedKeys,
  };
}

/**
 * Classifies one address.
 *
 * `upstream` is `{ found, readable, globalStatus, listStatus }` where
 * `listStatus` is the status recorded for the target list only.
 * `presence` is `{ inKv, readable }`.
 * `coverage` is `{ subscribersComplete }` — absence is only asserted when the
 * subscriber read covered the whole space.
 */
export function classifyAddress(upstream, presence, coverage = { subscribersComplete: false }) {
  // An unreadable KV record is present but not understood: it is not absence,
  // and it must not be resolved by looking at the other store.
  if (presence.inKv && !presence.readable) return 'needs_investigation';

  // An observation conflict means the two reads disagree, so neither status can
  // be asserted.
  if (upstream.conflicting) return 'needs_investigation';

  if (upstream?.found) {
    const globalStatus = upstream.globalStatus ?? 'unknown';
    const listStatus = upstream.listStatus ?? 'unknown';

    if (globalStatus === 'blocklisted') return 'blocklisted';
    // A status the tool cannot interpret must not be bucketed as a fact.
    if (!GLOBAL_STATUSES.has(globalStatus) || !LIST_STATUSES.has(listStatus)) return 'needs_investigation';
    if (globalStatus === 'unknown' || listStatus === 'unknown') return 'needs_investigation';

    if (listStatus === 'confirmed') {
      // A confirmed list membership next to a globally disabled subscriber is
      // contradictory, and slicing it either way would invent a fact.
      if (globalStatus !== 'enabled') return 'needs_investigation';
      return presence.inKv ? 'both_active' : 'listmonk_only';
    }
    if (listStatus === 'unsubscribed') {
      return presence.inKv ? 'upstream_unsubscribed' : 'neither_active';
    }
    // 'unconfirmed' is an opt-in that has not completed: not active, and not a
    // drift the tool can interpret.
    return 'needs_investigation';
  }

  if (!presence.inKv) return 'needs_investigation';
  // Absence upstream is only a fact when the read provably covered everything.
  return coverage.subscribersComplete ? 'kv_only_missing_upstream' : 'needs_investigation';
}

/**
 * Normalizes Listmonk's read model.
 *
 * `pages` are `{ data: { results, total } }` payloads from GET /api/subscribers.
 * `queriedEmails` is the set returned by GET /api/subscribers?list_id=<id>; it
 * is kept as evidence of appearance only, because that endpoint returns every
 * subscription status for the list unless separately filtered.
 */
export function collectUpstream({ pages, queriedEmails, complete, failures, listId }) {
  const upstreamByEmail = new Map();
  const queried = queriedEmails instanceof Set ? queriedEmails : new Set(queriedEmails ?? []);
  const targetListId = Number(listId);
  const conflicts = [];

  for (const page of pages) {
    const results = page?.data?.results;
    if (!Array.isArray(results)) continue;
    for (const subscriber of results) {
      const email = normalizeEmail(subscriber?.email);
      if (!email || !EXPECTED_EMAIL.test(email)) continue;

      const rawGlobal = typeof subscriber?.status === 'string' ? subscriber.status.trim().toLowerCase() : null;
      const globalStatus = rawGlobal && GLOBAL_STATUSES.has(rawGlobal) ? rawGlobal : 'unknown';

      // Only the entry for the target list carries a status this report can
      // attribute to the target list. A marker on any other list is ignored.
      let listStatus = 'unknown';
      let listEvidence = 'no-list-entry';
      if (Array.isArray(subscriber?.lists)) {
        const entry = subscriber.lists.find((candidate) => Number(candidate?.id) === targetListId);
        if (entry) {
          const raw = typeof entry.subscription_status === 'string' ? entry.subscription_status.trim().toLowerCase() : null;
          if (raw && LIST_STATUSES.has(raw)) {
            listStatus = raw;
            listEvidence = 'target-list-entry';
          } else {
            listEvidence = 'unrecognized-list-status';
          }
        }
      }
      // Appearance in the list query is recorded but never promoted to a status.
      if (listStatus === 'unknown' && queried.has(email)) listEvidence = 'list-query-only';

      const previous = upstreamByEmail.get(email);
      // The same address observed twice with different statuses cannot be
      // resolved by picking one.
      const conflicting = Boolean(previous) &&
        (previous.globalStatus !== globalStatus || previous.listStatus !== listStatus);
      if (conflicting) conflicts.push(email);

      upstreamByEmail.set(email, {
        found: true,
        readable: true,
        globalStatus: previous && !conflicting ? previous.globalStatus : globalStatus,
        listStatus: previous && !conflicting ? previous.listStatus : listStatus,
        listEvidence,
        conflicting: conflicting || Boolean(previous?.conflicting),
      });
    }
  }

  // An address can be observed upstream only by the list query — for instance
  // when it is added between the two reads. Reporting it as absent because the
  // subscriber pages predate it would turn a positive observation into a
  // missing-subscriber claim.
  for (const email of queried) {
    if (upstreamByEmail.has(email)) continue;
    upstreamByEmail.set(email, {
      found: true,
      readable: true,
      globalStatus: 'unknown',
      listStatus: 'unknown',
      listEvidence: 'list-query-only',
      conflicting: false,
    });
  }

  return { upstreamByEmail, complete, failures, conflicts };
}

/** Buckets every address. Coverage gates the one bucket that asserts absence. */
export function buildInventory({ kv, upstreamByEmail, coverage }) {
  const buckets = Object.fromEntries(BUCKETS.map((name) => [name, []]));
  const seen = new Set();

  for (const email of kv.presentEmails) {
    seen.add(email);
    const record = kv.byEmail.get(email);
    const upstream = upstreamByEmail.get(email) ?? { found: false, readable: true };
    buckets[classifyAddress(upstream, { inKv: true, readable: record.readable }, coverage)].push(email);
  }

  for (const [email, upstream] of upstreamByEmail) {
    if (seen.has(email)) continue;
    buckets[classifyAddress(upstream, { inKv: false, readable: true }, coverage)].push(email);
  }

  return {
    counts: Object.fromEntries(BUCKETS.map((name) => [name, buckets[name].length])),
    buckets,
    unreadable: kv.unreadable,
    kvRecords: kv.presentEmails.size,
    kvReadable: kv.records.filter((entry) => entry.readable).length,
    kvExcludedKeys: kv.excludedKeys,
    upstreamRecords: upstreamByEmail.size,
  };
}

/** Keyed pseudonym. Refuses to run without a secret; there is no sha256 fallback. */
export function createPseudonymizer(secret) {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new Error('INVENTORY_HMAC_SECRET must be set to at least 16 characters');
  }
  return (email) => createHmac('sha256', secret).update(email.trim().toLowerCase()).digest('hex').slice(0, 32);
}

/**
 * Builds the report. Aggregate counts are always present; identifiers are
 * included only when asked for, and always pseudonymous.
 */
export function buildReport({ inventory, window, source, includeIdentifiers, pseudonymize }) {
  const report = {
    generatedAt: new Date().toISOString(),
    observationWindow: window,
    source,
    complete: source.complete !== false,
    coverage: source.coverage,
    // Stated in the artefact itself so a reader cannot mistake it for a
    // consistent snapshot or an action plan.
    caveats: [
      'Two live stores were read separately; differences are candidates for investigation, not a transactionally consistent snapshot.',
      'No bucket implies an action. A KV-only record is not a queued re-subscription.',
      'A native Listmonk unsubscribe expresses user intent and must not be overwritten from KV.',
      'List membership is not subscription status: only the target list entry is read as a status.',
      'needs_investigation includes unproven absence and unreadable records, which are not evidence of a missing subscriber.',
    ],
    counts: inventory.counts,
    unreadable: inventory.unreadable.length,
    kvRecords: inventory.kvRecords,
    kvReadable: inventory.kvReadable,
    kvExcludedKeys: inventory.kvExcludedKeys,
    upstreamRecords: inventory.upstreamRecords,
  };

  if (!report.complete) {
    report.incompleteReason = 'at least one phase did not cover its full space; absence is not asserted from it';
    report.failures = source.failures ?? [];
  }

  if (includeIdentifiers) {
    report.identifiers = Object.fromEntries(
      BUCKETS.map((name) => [name, inventory.buckets[name].sort().map(pseudonymize)]),
    );
  }

  return report;
}

/** GET-only client. Every other method throws before a request is built. */
export function createListmonkReader({ apiUrl, user, token, fetchImpl = fetch, retries = 3, delayMs = 250, log = () => {} }) {
  const auth = Buffer.from(`${user}:${token}`).toString('base64');

  async function get(path) {
    let lastError;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      if (attempt > 0) await new Promise((done) => setTimeout(done, delayMs * attempt));
      const response = await fetchImpl(`${apiUrl}${path}`, {
        method: 'GET',
        headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' },
      });
      if (response.status === 429 || response.status >= 500) {
        lastError = new Error(`HTTP ${response.status} for ${path}`);
        log(`retrying ${path}: ${lastError.message}`);
        continue;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status} for ${path}`);
      return response.json();
    }
    throw lastError ?? new Error(`unreadable response for ${path}`);
  }

  function refuseMutation(method) {
    throw new Error(`read-only client: refusing ${method}`);
  }

  return { get, refuseMutation };
}

/**
 * Walks a paginated endpoint and reports whether the walk covered everything.
 *
 * Complete means: no exception, a non-empty final page, the reported total was
 * reached (when one was given), and maxPages was not exhausted. An empty page
 * before the reported total is a contradiction and is treated as incomplete,
 * because the missing rows are exactly the ones the report would otherwise call
 * absent.
 */
async function walkPages(fetchPage, { perPage, maxPages, identify }) {
  const pages = [];
  const distinct = new Set();
  let rows = 0;
  let invalidRows = 0;
  let total = null;

  const finish = (complete, reason) => ({
    pages,
    rows,
    validRows: rows - invalidRows,
    invalidRows,
    distinct: distinct.size,
    total,
    complete,
    reason,
  });

  for (let page = 1; page <= maxPages; page += 1) {
    let payload;
    try {
      payload = await fetchPage(page);
    } catch (error) {
      // Pages already read stay in the result: a failure on page 3 does not
      // make pages 1 and 2 unread, and discarding them would throw away the
      // only evidence the run produced.
      return finish(false, String(error?.message ?? error));
    }
    const results = payload?.data?.results;
    if (!Array.isArray(results)) {
      return finish(false, 'response has no results array');
    }
    pages.push(payload);
    const reported = Number(payload?.data?.total ?? 0);
    if (Number.isFinite(reported) && reported > 0) total = reported;

    for (const row of results) {
      rows += 1;
      const identity = identify(row);
      if (identity) distinct.add(identity);
      else invalidRows += 1;
    }

    // Every early return below is a judgement about coverage, and coverage is
    // counted in distinct usable identities. A row with no identity, or a
    // repeated identity, means the reported total cannot be reconciled with
    // what was actually observed, so completeness is not established.
    const unreconciled = invalidRows > 0 || (total !== null && distinct.size < total);

    if (results.length === 0) {
      if (total !== null && distinct.size < total) {
        return finish(false, `empty page after ${distinct.size} distinct of ${total} reported records`);
      }
      if (invalidRows > 0) {
        return finish(false, `${invalidRows} rows had no usable identity`);
      }
      return finish(true);
    }

    if (!unreconciled && total !== null && distinct.size >= total) return finish(true);
  }

  return finish(false, `stopped after the ${maxPages}-page limit with ${distinct.size} of ${total ?? '?'} distinct records`);
}

function subscriberIdentity(row) {
  const email = normalizeEmail(row?.email);
  return email && EXPECTED_EMAIL.test(email) ? email : null;
}

/** Reads every subscriber page and the list membership pages, with coverage. */
export async function readUpstream(reader, { listId, perPage = 100, maxPages = 500 }) {
  const failures = [];

  let subscribers;
  try {
    subscribers = await walkPages(
      (page) => reader.get(`/api/subscribers?per_page=${perPage}&page=${page}`),
      { perPage, maxPages, identify: subscriberIdentity },
    );
  } catch (error) {
    subscribers = { pages: [], distinct: 0, total: null, complete: false, reason: String(error?.message ?? error), invalidRows: 0, rows: 0 };
  }
  if (!subscribers.complete) failures.push({ phase: 'subscribers', error: subscribers.reason });

  const queriedEmails = new Set();
  let listWalk;
  try {
    listWalk = await walkPages(
      (page) => reader.get(`/api/subscribers?list_id=${listId}&per_page=${perPage}&page=${page}`),
      { perPage, maxPages, identify: subscriberIdentity },
    );
    for (const payload of listWalk.pages) {
      const results = payload?.data?.results;
      if (!Array.isArray(results)) continue;
      for (const row of results) {
        const email = subscriberIdentity(row);
        if (email) queriedEmails.add(email);
      }
    }
  } catch (error) {
    listWalk = { complete: false, reason: String(error?.message ?? error), distinct: 0, invalidRows: 0 };
  }
  if (!listWalk.complete) failures.push({ phase: 'list', error: listWalk.reason });

  // Both phases are required. Status observations from the subscriber pages stay
  // valid on their own, but the run is not complete and must not exit 0.
  const complete = Boolean(subscribers.complete && listWalk.complete);

  return {
    pages: subscribers.pages,
    queriedEmails,
    complete,
    failures,
    coverage: {
      subscribersComplete: Boolean(subscribers.complete),
      subscribersDistinct: subscribers.distinct ?? 0,
      subscribersReportedTotal: subscribers.total ?? null,
      subscribersInvalidRows: subscribers.invalidRows ?? 0,
      listQueryComplete: Boolean(listWalk.complete),
      listQueryDistinct: listWalk.distinct ?? 0,
      listQueryInvalidRows: listWalk.invalidRows ?? 0,
    },
  };
}

/**
 * Determines whether `target` is inside a Git working tree.
 *
 * Returns `true`/`false` only when Git answered definitively. Anything else — a
 * missing binary, a permission error, an unreadable configuration, an
 * unexpected exit status — throws, because treating "could not check" as "not a
 * repository" is exactly how a report ends up committed.
 */
function insideRepository(target) {
  let stdout;
  try {
    stdout = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: dirname(target),
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
    });
  } catch (error) {
    const stderr = String(error?.stderr ?? '');
    const status = error?.status;
    // Git's own refusal: this directory is definitively not in a work tree.
    if (status === 128 && /not a git repository|not a git work tree/i.test(stderr)) {
      return false;
    }
    throw new Error(
      `could not determine whether ${dirname(target)} is inside a Git working tree` +
      ` (${String(error?.code ?? error?.message ?? 'unknown failure').split('\n')[0]}); refusing to write a report`,
    );
  }

  const root = stdout.trim();
  if (!root) {
    throw new Error(`git reported no working-tree root for ${dirname(target)}; refusing to write a report`);
  }
  return target === root || target.startsWith(`${root}/`);
}

/**
 * Validates a report destination and returns the resolved, safe path.
 *
 * The parent directory is resolved through `realpath`, so a symlinked directory
 * cannot smuggle the write into a repository. An existing destination that is a
 * symlink is refused outright: following it would write wherever it points, and
 * replacing it would silently discard the link.
 */
export function assertOutsideRepository(target) {
  const requested = isAbsolute(target) ? target : resolve(target);
  let realDir;
  try {
    realDir = realpathSync(dirname(requested));
  } catch {
    throw new Error(`report directory does not exist: ${dirname(requested)}`);
  }
  const effective = join(realDir, basename(requested));

  let stats = null;
  try {
    stats = lstatSync(effective);
  } catch {
    // Destination does not exist yet, which is the normal case.
  }
  if (stats?.isSymbolicLink()) {
    throw new Error('refusing to write a report to a symbolic link');
  }
  if (stats && !stats.isFile()) {
    throw new Error('refusing to write a report to a path that is not a regular file');
  }

  if (insideRepository(effective)) {
    throw new Error(`refusing to write a report inside the Git working tree at ${realDir}`);
  }
  return effective;
}

/** Publishes through a private temporary file, then renames into place. */
export function writeReport(target, contents) {
  const effective = assertOutsideRepository(target);
  const temporary = join(dirname(effective), `.${basename(effective)}.${process.pid}.tmp`);
  try {
    writeFileSync(temporary, contents, { mode: 0o600, flag: 'wx' });
    chmodSync(temporary, 0o600);
    renameSync(temporary, effective);
  } catch (error) {
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created.
    }
    throw error;
  }
  return effective;
}

function parseArgs(argv) {
  const options = { includeIdentifiers: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--kv') options.kv = argv[++index];
    else if (arg === '--out') options.out = argv[++index];
    else if (arg === '--include-identifiers') options.includeIdentifiers = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node scripts/inventory-subscribers.mjs --kv <export.json> [--out <path>] [--include-identifiers]');
    console.log('Reads KV and Listmonk, writes a read-only drift inventory. No writes are performed.');
    return 0;
  }
  if (!options.kv) throw new Error('--kv <export.json> is required');

  const { LISTMONK_API_URL, LISTMONK_API_USER, LISTMONK_API_TOKEN, LISTMONK_LIST_ID, INVENTORY_HMAC_SECRET } = process.env;
  for (const [name, value] of Object.entries({ LISTMONK_API_URL, LISTMONK_API_USER, LISTMONK_API_TOKEN, LISTMONK_LIST_ID, INVENTORY_HMAC_SECRET })) {
    if (!value) throw new Error(`${name} must be set`);
  }

  const startedAt = new Date().toISOString();
  const kv = readKvExport(JSON.parse(readFileSync(options.kv, 'utf8')));

  const reader = createListmonkReader({ apiUrl: LISTMONK_API_URL, user: LISTMONK_API_USER, token: LISTMONK_API_TOKEN });
  const listId = Number(LISTMONK_LIST_ID);
  const upstream = await readUpstream(reader, { listId });
  const collected = collectUpstream({
    pages: upstream.pages,
    queriedEmails: upstream.queriedEmails,
    complete: upstream.complete,
    failures: upstream.failures,
    listId,
  });

  const inventory = buildInventory({ kv, upstreamByEmail: collected.upstreamByEmail, coverage: upstream.coverage });
  const report = buildReport({
    inventory,
    window: { startedAt, finishedAt: new Date().toISOString() },
    source: { complete: upstream.complete, failures: upstream.failures, listId, coverage: upstream.coverage },
    includeIdentifiers: options.includeIdentifiers,
    pseudonymize: createPseudonymizer(INVENTORY_HMAC_SECRET),
  });

  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    writeReport(options.out, output);
    console.error(`wrote ${options.out}`);
  }
  console.log(output);
  return report.complete ? 0 : 2;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => { process.exitCode = code; },
    (error) => {
      console.error(`inventory failed: ${error?.message ?? error}`);
      process.exitCode = 1;
    },
  );
}
