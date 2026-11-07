# Newsletter API reference

This file holds the detailed design notes and test records. `README.md` describes the system. Entries with a date were true on that date.

## Rolling this back

Rolling back to a version that predates the Durable Object class is not supported
by Cloudflare: a rollback cannot cross a class creation. The supported path is a
forward deploy retaining the same `SubscriptionCoordinator` class, binding and
migration history. The pre-migration `6963` version cannot be a direct rollback target:

```bash
# 1. Set the lever in wrangler.toml:  COORDINATOR_MODE = "legacy"
npm run deploy:production
```

`COORDINATOR_MODE = "legacy"` is **read-only subscriber maintenance**, not a
fallback writer. It keeps the binding, class and pending operations. New public
subscriber writes (including signed unsubscribe and confirmation POSTs) return
503 before mutations; direct internal `/intent` requests also return 503.
Alarms and `/sync` pause without provider or shadow I/O or spending attempts,
rescheduling pending work for one minute later. Switch back to `"on"` with another
forward deploy to resume the authoritative stored intent at its next alarm.
The guard accepts only `on` or `legacy`. A missing or malformed production
coordinator binding fails closed; only nonproduction unit environments retain an
inline fallback in `on` mode.

There is no independent legacy writer or KV clock/fence authority. Historical
`intent:` keys remain excluded from subscriber inventory and counts. The KV
shadow is not evidence of supersession.

Retries allow eight total attempts (the initial attempt plus seven retries).
Requested delays after failures are 1, 4, 16, 60, 60, 60 and 60 minutes. Exhausted
work requires operator investigation; maintenance does not reset this budget.
Maintenance cannot recall a provider request already in flight or prevent native
Listmonk actions. Deploy propagation is not a globally instantaneous pause.

`test/alarms.test.mjs` uses actual workerd scheduler callbacks; a test-only storage
proxy accelerates alarm delivery while recording original requested delays and
callback counts. It covers convergence, exhaustion, orphan cleanup and pause/
resume. This in-process mode-switch proof does not prove restart persistence or
Cloudflare migration/control-plane behavior. A disposable remote migration and
rollback-forward canary still requires separate upload authorization; neither
local tests nor the production dry run establish that proof.

A separately authorized live lifecycle drill passed on 2026-10-31 for PR #6:
class creation with `v1`, redeployment with `v1` already applied, preservation of
synthetic durable intent, rollback-forward into maintenance, an actual alarm
pausing without spending attempts, and alarm-driven resumption after returning
to `on`. The disposable Worker used the candidate coordinator class without
production KV/R2 bindings or application credentials. Its namespace and Worker
were deleted afterward; production deployment metadata remained unchanged. This
validates the tested lifecycle, not an instantaneous global pause or a production
migration. Future live drills still require separate authorization.

An accepted unsubscribe is a durable recipient tombstone: an unauthenticated
signup cannot cancel it, even after retry exhaustion or completed removal. The
address keeps reporting as unsubscribed until the caller proves control through
the supported authenticated path; provider lookup policy still governs whether
that signup may proceed.

## Runtime suite

The suite in `test/runtime.test.mjs` runs the Worker in workerd through Miniflare
(the runtime `wrangler` drives itself) and exercises it over HTTP, so KV, R2,
`Request`/`Response` and the streamed body parser behave as they do in
production. It is not a live-provider test.

Isolation is enforced rather than described:

- `test/harness.mjs` supplies every binding, so `wrangler.toml`, `.dev.vars` and
  `.env` are never read — Miniflare has no configuration-file awareness. A test
  asserts the Worker echoes the harness origin rather than the configured one.
- KV and R2 are in memory, so nothing is written to `.wrangler/state` or to a
  namespace that exists in the account.
- Outbound traffic is wired through Miniflare's `outboundService` to a guard
  that records each requested host and answers 403. A positive control makes the
  Worker perform a real outbound request and asserts the guard saw it, which is
  what shows the guard is on the path at all. After all tests finish, a test-only
  wrapper entry drains all `ctx.waitUntil` background work, and only then does
  the suite assert that no provider host was contacted; a fixture test proves
  the drain catches delayed egress. Production source is not modified.
- The deploy-configuration guard runs before workerd starts, so an unsafe
  `wrangler.toml` aborts the suite even when it is invoked on its own. `npm run
  verify` also runs it first.

The expected `Listmonk not configured` / `PLUNK_SECRET_KEY not configured`
warnings appear in the runtime logs; they are the intended development
behaviour and are not filtered.

## Subscriber Drift Inventory

`scripts/inventory-subscribers.mjs` compares subscriber records in KV with list
membership in Listmonk and reports what differs. It is a **read-only inventory,
not a migration**: no bucket implies an action, and a KV-only record must never
be treated as a queued re-subscription.

That distinction is deliberate. Listmonk's own unsubscribe links —
`{{ UnsubscribeURL }}` and the `List-Unsubscribe` header, which targets
`/subscription/<campaign>/<subscriber>` — change subscription state without the
Worker being involved. A native unsubscribe is an expression of user intent, so
converging Listmonk toward an older KV "subscribed" record would silently undo
it. The inventory reports; a human decides.

```bash
LISTMONK_API_URL=... LISTMONK_API_USER=... LISTMONK_API_TOKEN=... \
LISTMONK_LIST_ID=3 INVENTORY_HMAC_SECRET=... \
node scripts/inventory-subscribers.mjs --kv kv-export.json --out /tmp/inventory.json
```

| Guarantee | How |
|---|---|
| Read-only | The client issues only `GET` and refuses any other method; no KV writes, no welcome mail, no unsubscribe requests |
| No policy by accident | Recipients needing investigation are reported as such; nothing re-subscribes, re-adds or removes |
| Membership is not status | Only the target list's own `subscription_status` is read as a status. Appearance in `?list_id=` is recorded as evidence of nothing, because that query returns every status for the list |
| Absence is a claim | `kv_only_missing_upstream` is used only when the subscriber read proved full coverage. Otherwise the address needs investigation |
| Unreadable is not absent | Presence and readability are tracked separately, so a malformed value cannot resurface as Listmonk-only |
| Incomplete reads stay incomplete | A failed page, an early empty page, or a page-limit stop marks the report incomplete and exits `2` |
| Pseudonymous identifiers | Keyed HMAC-SHA256 under `INVENTORY_HMAC_SECRET`; there is no unsalted fallback, and aggregate counts are the default |
| No secrets in Git | The destination's real path is checked, symlinked destinations are refused, and reports are published from a private temporary file with mode `0600` |

The KV export is a JSON file of `{ key, value }` objects, `[key, value]` pairs,
or a key-to-value object. Keys are normalized and deduplicated, and
`rate_limit:` / `cache:` keys are excluded, since they are Worker bookkeeping
rather than membership.

Buckets: `both_active`, `kv_only_missing_upstream`, `upstream_unsubscribed`,
`blocklisted`, `listmonk_only`, `neither_active`, `needs_investigation`.

`needs_investigation` is the honest bucket and the one to read first. It holds
records where the tool will not state a fact: an unrecognised or absent status,
membership in the list query without a status for the target list, a malformed KV
value, and an absence that was never proven because a read fell short.

A target-list unsubscribe is reported as `upstream_unsubscribed` even though the
address still appears in the `?list_id=` query, and an `unsubscribed` marker
recorded against a *different* list is ignored entirely.

The two stores are read separately, so differences are candidates for
investigation rather than a transactionally consistent snapshot. The report
records its own observation window, per-phase coverage, and these caveats.
