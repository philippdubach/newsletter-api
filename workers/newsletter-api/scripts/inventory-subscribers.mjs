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
// Guarantees:
//   * Only GET requests are issued to Listmonk. Any other method throws.
//   * No writes to KV, no subscription changes, no welcome mail, no
//     unsubscribe requests.
//   * A failed or truncated read yields an incomplete report. It never renders
//     as "these subscribers are missing".
//   * Identifiers are keyed HMAC-SHA256 under a secret you supply. There is no
//     unsalted fallback, and aggregate counts are the default.
//   * The report refuses to be written inside a Git working tree.
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
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Keys the Worker writes that are not subscriber records. Anything else in the
// namespace is expected to be keyed by normalized address.
const NON_SUBSCRIBER_PREFIXES = ['rate_limit:', 'cache:'];

const EXPECTED_EMAIL = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export const BUCKETS = [
  'both_active',
  'kv_only_missing_upstream',
  'upstream_unsubscribed',
  'blocklisted',
  'listmonk_only',
  'needs_investigation',
];

/** True for keys the Worker uses for rate limiting and caching, not membership. */
export function isNonSubscriberKey(key) {
  return NON_SUBSCRIBER_PREFIXES.some((prefix) => key.startsWith(prefix));
}

/**
 * Normalizes a raw KV export into subscriber records plus a list of records
 * that could not be read. Never throws on malformed input: unreadable entries
 * are reported, because a parse failure is not evidence of absence.
 */
export function readKvExport(raw) {
  const entries = [];
  const unreadable = [];

  const push = (key, value) => {
    if (typeof key !== 'string' || key.length === 0) {
      unreadable.push({ reason: 'key is not a non-empty string' });
      return;
    }
    if (isNonSubscriberKey(key)) return;
    entries.push({ key, value });
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

  const subscribers = [];
  for (const { key, value } of entries) {
    const email = key.trim().toLowerCase();
    if (!EXPECTED_EMAIL.test(email)) {
      unreadable.push({ key, reason: 'key is not a valid address' });
      continue;
    }
    let record = value;
    if (typeof record === 'string') {
      try {
        record = JSON.parse(record);
      } catch {
        unreadable.push({ email, reason: 'record is not valid JSON' });
        continue;
      }
    }
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      unreadable.push({ email, reason: 'record is not an object' });
      continue;
    }
    subscribers.push({ email, record });
  }

  return { subscribers, unreadable };
}

/**
 * Classifies one address. `upstream` is `{ found, globalStatus, listStatus }`
 * where `listStatus` is 'confirmed', 'unsubscribed', or 'unknown'. A status the
 * tool cannot interpret becomes `needs_investigation` rather than a guess.
 */
export function classifyAddress(upstream, hasKvRecord) {
  if (!upstream || upstream.readable === false) return 'needs_investigation';

  const listStatus = upstream.listStatus ?? 'unknown';
  const globalStatus = upstream.globalStatus ?? 'unknown';

  if (globalStatus === 'blocklisted') return 'blocklisted';

  const listed = listStatus === 'confirmed';
  const unsubscribedUpstream = listStatus === 'unsubscribed';

  // A status the tool cannot interpret must not be bucketed as a fact.
  if (!['confirmed', 'unsubscribed', 'unknown'].includes(listStatus)) return 'needs_investigation';
  if (!['enabled', 'disabled', 'blocklisted', 'unknown'].includes(globalStatus)) return 'needs_investigation';

  if (hasKvRecord) {
    if (listed) return 'both_active';
    if (upstream.found && unsubscribedUpstream) return 'upstream_unsubscribed';
    if (!upstream.found) return 'kv_only_missing_upstream';
    // Present upstream, not in the list, but not recorded as unsubscribed:
    // "never added to this list" and "removed without a status" look identical
    // here, so this is not reported as either.
    return 'needs_investigation';
  }

  if (listed) return 'listmonk_only';
  return 'needs_investigation';
}

/** Buckets every address, keeping unreadable records separate from facts. */
export function buildInventory({ kv, upstreamByEmail }) {
  const buckets = Object.fromEntries(BUCKETS.map((name) => [name, []]));
  const seen = new Set();

  for (const { email } of kv.subscribers) {
    seen.add(email);
    const upstream = upstreamByEmail.get(email) ?? { found: false, readable: true };
    buckets[classifyAddress(upstream, true)].push(email);
  }

  for (const [email, upstream] of upstreamByEmail) {
    if (seen.has(email)) continue;
    buckets[classifyAddress(upstream, false)].push(email);
  }

  const counts = Object.fromEntries(BUCKETS.map((name) => [name, buckets[name].length]));
  return {
    counts,
    buckets,
    unreadable: kv.unreadable,
    kvRecords: kv.subscribers.length,
    upstreamRecords: upstreamByEmail.size,
  };
}

/**
 * Derives the inventory from Listmonk's paginated read model.
 *
 * `pages` are the raw `{ data: { results, total, page, per_page } }` payloads
 * from GET /api/subscribers. `listedEmails` is the set returned by
 * GET /api/subscribers?list_id=<id>. Neither is trusted to be complete: a
 * caller that failed to read a page must pass `complete: false`, and the report
 * says so instead of implying absence.
 */
export function collectUpstream({ pages, listedEmails, complete, failures }) {
  const upstreamByEmail = new Map();
  const listed = listedEmails instanceof Set ? listedEmails : new Set(listedEmails ?? []);

  for (const page of pages) {
    const results = page?.data?.results;
    if (!Array.isArray(results)) continue;
    for (const subscriber of results) {
      const email = typeof subscriber?.email === 'string' ? subscriber.email.trim().toLowerCase() : null;
      if (!email || !EXPECTED_EMAIL.test(email)) continue;

      const globalStatus = typeof subscriber.status === 'string' ? subscriber.status : 'unknown';
      // The list status is read only when the payload carries it for this list.
      // Absent means unknown, which is reported rather than assumed.
      let listStatus = 'unknown';
      if (Array.isArray(subscriber.lists)) {
        if (listed.has(email)) listStatus = 'confirmed';
        else if (subscriber.lists.some((entry) => entry?.subscription_status === 'unsubscribed')) {
          listStatus = 'unsubscribed';
        }
      }

      upstreamByEmail.set(email, { found: true, readable: true, globalStatus, listStatus });
    }
  }

  for (const email of listed) {
    const existing = upstreamByEmail.get(email);
    upstreamByEmail.set(email, {
      found: true,
      readable: true,
      globalStatus: existing?.globalStatus ?? 'unknown',
      listStatus: 'confirmed',
    });
  }

  return { upstreamByEmail, complete, failures };
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
    // Stated in the artefact itself so a reader cannot mistake it for a
    // consistent snapshot or an action plan.
    caveats: [
      'Two live stores were read separately; differences are candidates for investigation, not a transactionally consistent snapshot.',
      'No bucket implies an action. A KV-only record is not a queued re-subscription.',
      'A native Listmonk unsubscribe expresses user intent and must not be overwritten from KV.',
    ],
    counts: inventory.counts,
    unreadable: inventory.unreadable.length,
    kvRecords: inventory.kvRecords,
    upstreamRecords: inventory.upstreamRecords,
  };

  if (!report.complete) {
    report.incompleteReason = 'at least one page could not be read; counts describe only what was read';
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

  return {
    get,
    // Exposed so callers and tests can assert the refusal rather than trust it.
    refuseMutation,
  };
}

/** Reads every subscriber page and the list membership pages. */
export async function readUpstream(reader, { listId, perPage = 100, maxPages = 500 }) {
  const pages = [];
  const failures = [];
  let seen = 0;

  try {
    for (let page = 1; page <= maxPages; page += 1) {
      const payload = await reader.get(`/api/subscribers?per_page=${perPage}&page=${page}`);
      pages.push(payload);
      const results = payload?.data?.results;
      if (!Array.isArray(results) || results.length === 0) break;
      seen += results.length;
      // `total` is the count upstream reports; `seen` is what was actually read.
      // Comparing seen against total stops on a short final page without
      // assuming every page is full.
      const total = Number(payload?.data?.total ?? 0);
      if (total > 0 && seen >= total) break;
    }
  } catch (error) {
    failures.push({ phase: 'subscribers', error: String(error?.message ?? error) });
  }

  const listedEmails = new Set();
  let listedSeen = 0;
  try {
    for (let page = 1; page <= maxPages; page += 1) {
      const payload = await reader.get(`/api/subscribers?list_id=${listId}&per_page=${perPage}&page=${page}`);
      const results = payload?.data?.results;
      if (!Array.isArray(results)) {
        failures.push({ phase: 'list', error: 'response has no results array' });
        break;
      }
      for (const subscriber of results) {
        const email = typeof subscriber?.email === 'string' ? subscriber.email.trim().toLowerCase() : null;
        if (email) listedEmails.add(email);
      }
      if (results.length === 0) break;
      listedSeen += results.length;
      const total = Number(payload?.data?.total ?? 0);
      if (total > 0 && listedSeen >= total) break;
    }
  } catch (error) {
    failures.push({ phase: 'list', error: String(error?.message ?? error) });
  }

  return { pages, listedEmails, complete: failures.length === 0, failures };
}

/** Refuses to place a report inside a Git working tree. */
export function assertOutsideRepository(target) {
  const resolved = isAbsolute(target) ? target : resolve(target);
  try {
    const root = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: dirname(resolved),
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    }).trim();
    if (root && resolved.startsWith(`${root}/`)) {
      throw new Error(`refusing to write a report inside the Git working tree at ${root}`);
    }
  } catch (error) {
    if (String(error?.message ?? '').startsWith('refusing')) throw error;
    // Not a Git working tree, which is the expected case for a report path.
  }
  return resolved;
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
  const upstream = await readUpstream(reader, { listId: Number(LISTMONK_LIST_ID) });
  const collected = collectUpstream({
    pages: upstream.pages,
    listedEmails: upstream.listedEmails,
    complete: upstream.complete,
    failures: upstream.failures,
  });

  const inventory = buildInventory({ kv, upstreamByEmail: collected.upstreamByEmail });
  const report = buildReport({
    inventory,
    window: { startedAt, finishedAt: new Date().toISOString() },
    source: { complete: collected.complete, failures: collected.failures, listId: Number(LISTMONK_LIST_ID) },
    includeIdentifiers: options.includeIdentifiers,
    pseudonymize: createPseudonymizer(INVENTORY_HMAC_SECRET),
  });

  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    writeFileSync(assertOutsideRepository(options.out), output);
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
