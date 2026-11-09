# Newsletter API reference

This file holds the detailed design notes and test records. `README.md` describes the system. Entries with a date were true on that date.

## Signup challenge (Turnstile)

Added on 2026-11-09 after a bot posted 124 signups straight to `/api/subscribe`
on 3 to 7 November. It used six hosting-provider IP addresses, one user agent and
about one request every 20 minutes. The honeypot, the per-IP rate limit and the
exact-match `BLOCKED_IPS` list do not stop that pattern. Double opt-in kept the
addresses off campaigns, but each request still mailed a stranger.

### What the Worker does

`checkChallenge()` runs in `handleSubscribe` after the blocklist, the rate limit,
the honeypot and the address check, and before `submitIntent`. The token is the
`cf-turnstile-response` field of the JSON or form body. The Worker posts it to
`https://challenges.cloudflare.com/turnstile/v0/siteverify` with `TURNSTILE_SECRET`
and the caller's IP address, with a 5-second limit.

A token passes only if the siteverify answer meets all three checks that
Cloudflare's integration guide requires:

1. `success` is `true`.
2. `action` is exactly `signup`, the action the site's widget is rendered with.
   A different, empty or missing action fails.
3. `hostname` is in `TURNSTILE_HOSTNAMES`, a comma-separated list. The match is
   exact and ignores case. A subdomain passes only if it is listed.

Checks 2 and 3 refuse a token that is valid for the sitekey but was solved
somewhere else. Each such refusal logs
`Turnstile token refused: action "...", hostname "..."`.

| Caller | `TURNSTILE = "on"` | `TURNSTILE = "off"` |
|---|---|---|
| Operator bearer token | Accepted, verified | Accepted, verified |
| Token that passes all three checks | Accepted, verified | Accepted, verified (needs the secret and the hostname list) |
| No token | 400 `challenge_required` | Accepted, unverified |
| Token that siteverify rejects, or longer than 2048 characters | 400 `challenge_failed` | Accepted, unverified |
| Token with another or no action, or from a hostname not in the list | 400 `challenge_failed` | Accepted, unverified |
| Siteverify unreachable, or it reports a bad secret or an internal error | 503 `challenge_unavailable` | Accepted, unverified |
| `TURNSTILE_SECRET` not set | 503 `challenge_unavailable` | Accepted, unverified, no siteverify call |
| `TURNSTILE_HOSTNAMES` missing or empty | 503 `challenge_unavailable`, no siteverify call | Accepted, unverified, no siteverify call |

A refusal carries `success: false`, `status`, `error` and `message`, like the other
signup answers, so the site form shows the text without a change. A refused request
records no intent, writes no KV record and reaches Listmonk at no point.

Only the exact value `on` enforces. `npm run check:config` rejects any value other
than `on` or `off`, because a typo would leave the endpoint open. It also rejects
`on` without `TURNSTILE_HOSTNAMES`, and a production list that names `localhost`,
`127.0.0.1` or another loopback host. A token solved on a developer's machine must
never count in production.

`TURNSTILE_HOSTNAMES` is `philippdubach.com` in production. If the form is ever
served from another hostname, such as `www.philippdubach.com` or `phil-dubach.com`,
add that hostname to the list and to the widget in the dashboard. Until then its
tokens fail check 3.

`verified` is true for a passed token or the operator token. It is stored on the
coordinator intent and on the KV record. An intent that is not verified gets one
mail at most:

- The Listmonk create sends the opt-in mail. This is the one mail.
- `optin-reminder-at` is not stored, so there is no 48-hour reminder. A reminder
  that an earlier signup armed for the same address is deleted.
- A repeat request for an unclicked address does not call `resendOptin`. The caller
  still gets `confirmation_required`, so the answer tells an attacker nothing.

A reminder that a verified signup armed still fires after a later unverified
request for the same address.

### Evidence, not a filter

A one-hour tail of production on 2026-11-09 (11:34 to 12:34 UTC) showed the bot's
request: `Origin: https://philippdubach.com` and
`Referer: https://philippdubach.com/subscribe/`, both spoofed; a URL-encoded form
body; `Accept-Language: ru,en;q=0.8`; a Chrome 124 on Windows user agent; no
`Sec-CH-UA` header; HTTP/1.1. A real Chrome sends `Sec-CH-UA` and uses HTTP/2 or
HTTP/3.

Two things follow:

- Enforcing the `Origin` header would not stop this client, so the branch does
  not add that check. The challenge is the control.
- The KV record keeps `asn`, `asOrganization`, `secChUa` (whether the header was
  present) and `httpProtocol` (`request.cf.httpProtocol`). `/api/signup-stats`
  shows them for each recent signup.

These fields are for alerting and cleanup only. Do not use them to refuse a
request. In the same hour an unrelated scraper used the same user-agent string,
and about 20 real subscribers arrive through VPNs or relays. The unit tests pin
this: a request with the bot's exact shape is accepted once its challenge passes.

### The IP blocklist stays for now

`BLOCKED_IPS` and its check are unchanged in this branch. The owner's instruction
on 2026-11-09 was: "Keep the IP list until Turnstile is live." At 12:25 UTC that
day `95.182.114.251`, one of the six listed addresses, posted to `/api/subscribe`
and got the 429. The blocklist runs before the challenge, so a listed address is
refused without a siteverify call.

Remove the list only after `TURNSTILE` is `on` in production and the signup
report has stayed quiet. Until then it is the only control that stops those
addresses.

### Rollout

Each step that changes production needs the owner's approval.

State on 2026-11-09: steps 1 to 5 are done, and `TURNSTILE` is `on` in
production. The secret was stored after the deploy of step 3, not before it:
`wrangler secret put` refuses while the newest uploaded version of the Worker is
not the deployed one, and a leftover test version was the newest. A signup made
through the live form was recorded with `"verified":true`. Steps 6 and 7 are open.

1. Create a Turnstile widget in the Cloudflare dashboard, in Managed mode. Allow
   the hostnames that serve the form. Done on 2026-11-09 for `philippdubach.com`.
   Keep `TURNSTILE_HOSTNAMES` in `wrangler.toml` equal to the hostnames of the
   widget that show the form. Note the sitekey, which is public, and the secret key.
2. Store the secret. Run this from `workers/newsletter-api/`:

   ```bash
   npx wrangler secret put TURNSTILE_SECRET --env production
   ```

3. Deploy this code with `TURNSTILE = "off"`, as committed:

   ```bash
   npm run deploy:production
   ```

   From this deploy on, the report endpoint works and new records carry the ASN.
   Also from this deploy on, a signup without a token is unverified. Until the site
   sends tokens, that is every signup, so no reader gets the 48-hour reminder or a
   resend. Keep the time between this step and the next one short.
4. Ship the site change below. Then sign up through the form with an address you
   own that has no KV record yet, because the first record is kept. Its record
   must show `"verified":true`:

   ```bash
   npx wrangler kv key get "<address>" --binding NEWSLETTER_SUBSCRIBERS --remote --env production
   ```
5. Wait for cached copies of the site to expire. A page cached before the site
   release renders the widget without an action, or has no widget. Its token fails
   the action check or is missing, so with the challenge on that reader gets a 400.
   While the challenge is off, watch `npx wrangler tail --env production` for
   `Turnstile token refused: action "undefined"`. Go on when it has stopped.
   Then set `TURNSTILE = "on"` in `[env.production.vars]` of `wrangler.toml` and
   deploy again. A request without a passing token now gets 400.
6. Start the hourly poll of `/api/signup-stats`. See `README.md`.
7. Leave `BLOCKED_IPS` set through all of the steps above. It may be removed only
   after step 5 is live in production. See "The IP blocklist stays for now".

To go back, set `TURNSTILE = "off"` and deploy. The secret can stay. Keep
`BLOCKED_IPS` while the challenge is off.

### The site form change

The form is in the site repository, `philippdubach.github.io`. It posts to
`/api/subscribe` from `assets/js/site.js`. Four files change.

1. `hugo.toml`, under `[params.newsletter]`: add the public sitekey.

   ```toml
   turnstile_sitekey = '<sitekey from the dashboard>'
   ```

2. `layouts/partials/newsletter-form.html`: give the production form the sitekey
   and a container for the widget. Put the container before the message paragraph.

   ```html
   <form ... data-newsletter-endpoint="..." data-turnstile-sitekey="{{ site.Params.newsletter.turnstile_sitekey }}" ...>
     ...
     <div data-newsletter-challenge></div>
     <p class="newsletter-preview__message" data-newsletter-message role="status" aria-live="polite"></p>
   </form>
   ```

   The preview form stays inert and gets no widget.

3. `assets/js/site.js`, in the `[data-newsletter-endpoint]` loop: load the Turnstile
   script on the first focus of the email field, render one widget for each form,
   and send its token with the address. The Worker's contract has three parts:
   the field name `cf-turnstile-response`, the widget action `signup`, and a page
   hostname that is in `TURNSTILE_HOSTNAMES`. The code below is one way to meet it.

   ```js
   // One script load for the page. Cloudflare requires this exact URL: do not bundle or proxy it.
   let turnstileScript;
   const loadTurnstile = () => turnstileScript ??= new Promise((resolve, reject) => {
     const script = document.createElement("script");
     script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
     script.async = true;
     script.onload = () => resolve(window.turnstile);
     script.onerror = reject;
     document.head.append(script);
   });

   // For each form:
   const challenge = form.querySelector("[data-newsletter-challenge]");
   let widgetId;
   const showChallenge = () => loadTurnstile().then((turnstile) => {
     widgetId ??= turnstile.render(challenge, {
       sitekey: form.dataset.turnstileSitekey,
       action: "signup", // The Worker refuses a token with any other action.
       appearance: "interaction-only",
       size: "flexible",
     });
   });
   input.addEventListener("focus", () => showChallenge().catch(() => {}), { once: true });
   ```

   In the submit handler, after the address check and before the `fetch`:

   ```js
   const token = widgetId === undefined ? "" : window.turnstile.getResponse(widgetId);
   if (!token) {
     showChallenge().catch(() => {});
     message.textContent = "Checking your browser. Please press Subscribe again in a moment.";
     return;
   }
   ```

   Change the request body:

   ```js
   body: JSON.stringify({ email: input.value.trim(), "cf-turnstile-response": token }),
   ```

   A token works once and for 300 seconds. So in the `else` branch and in `.catch`,
   where the button is enabled again, ask for a new one:

   ```js
   if (widgetId !== undefined) window.turnstile.reset(widgetId);
   ```

   The Worker's answers need no other change. `challenge_required`,
   `challenge_failed` and `challenge_unavailable` arrive with `status` and
   `message`, which the handler already displays.

4. The Content Security Policy, in both places that set it:
   `layouts/partials/head.html` (the `<meta>` tag) and
   `workers/security-headers/src/index.js`.

   - Add `https://challenges.cloudflare.com` to `script-src`.
   - Add the directive `frame-src https://challenges.cloudflare.com;`. The policy
     has no `frame-src` now, so `default-src 'self'` blocks the widget's iframe.
   - `connect-src` needs no change.

   `workers/security-headers/test/csp.test.js` reads the policy, so run that
   Worker's tests.

Three consequences for the site owner to decide on:

- The form keeps `method="post" action="..."` for readers without JavaScript.
  Turnstile needs JavaScript, so with `TURNSTILE = "on"` that path gets a raw 400
  answer. Remove the two attributes and add a `<noscript>` note, or accept it.
- The form says "No tracking". The widget loads a script and an iframe from
  `challenges.cloudflare.com`. Loading it on focus limits that to readers who start
  a signup. Check the privacy notice.
- `layouts/partials/structured-data.html` advertises the endpoint as a
  `urlTemplate`. A client that follows it has no token.

### Local testing

Cloudflare publishes dummy keys that work on any hostname, listed at
`developers.cloudflare.com/turnstile/troubleshooting/testing/`. They cannot produce
a verified signup here. The dummy secret `1x0000000000000000000000000000000AA`
answers `success: true` with the hostname `example.com` and no action, so the
Worker refuses the token on the action check. That makes the dummy keys useful for
the refusal paths only: put that secret in `.dev.vars` with `TURNSTILE = "on"` and
`TURNSTILE_HOSTNAMES = "example.com"`, and expect 400 `challenge_failed`. Secret
`2x0000000000000000000000000000000AA` always answers a failure.

To see a signup pass locally, use a real widget whose hostnames include
`localhost`, with its secret and `TURNSTILE_HOSTNAMES = "localhost"` in `.dev.vars`.
Use a widget made for development, not the production one, and never add a local
hostname to the production list.

The unit tests stub siteverify through `fetch`. The workerd suite answers it from
the provider stand-in in `test/subscription-invariants.test.mjs`, which accepts one
fixed token.

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
