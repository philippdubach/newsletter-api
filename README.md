# Newsletter API

This repository holds the signup system for the newsletter on [philippdubach.com](https://philippdubach.com). It has two parts:

- `workers/newsletter-api/`: a Cloudflare Worker with a Durable Object.
- `listmonk/`: template overrides for Listmonk, which runs on the Hetzner host `pd-prod`.

The website is in a separate repository. Its `OPERATIONS.md` describes the production host.

| Read this | For |
|---|---|
| `README.md` | What the system does and how to run it |
| `CLAUDE.md` | Rules for coding agents |
| `listmonk/README.md` | The Listmonk template overrides |
| `docs/REFERENCE.md` | Signup challenge rollout, the site form change, coordinator rollback, test design and the subscriber inventory tool |

## How signup works

```text
Site form -> POST /api/subscribe -> SubscriptionCoordinator -> Listmonk -> confirmation email
Email button -> philippdubach.com/?confirm#<id> -> POST /api/confirm -> Listmonk
```

1. The form posts the address and a Turnstile token to `/api/subscribe`.
2. The Worker checks the blocklist, the rate limit and the honeypot field. With `TURNSTILE = "on"`, it then verifies the token with Cloudflare and answers 400 if the token is missing or fails. Nothing is recorded and no mail is sent for a refused request.
3. `SubscriptionCoordinator` is one Durable Object for each address. It records the intent, so a signup and an unsubscribe cannot overlap.
4. The coordinator reads the current state from Listmonk. It creates the subscriber if the address is absent. It does not overwrite a blocklisted or unsubscribed address.
5. Listmonk sends the confirmation email, because list 3 is a double opt-in list. If the link is unclicked after 48 hours, the coordinator asks Listmonk to send it once more. This reminder is armed only for a verified signup: one that passed the challenge or carried the operator token.
6. The email button opens the site. The site posts the subscriber id to `/api/confirm`, and the Worker confirms in Listmonk.

The Worker sends no welcome email while `DOUBLE_OPTIN` is `on`.

Listmonk is the source of truth. KV keeps a shadow record of each signup: the time, IP address, user agent, ASN, ASN organization, whether a `Sec-CH-UA` header was present, the HTTP protocol and whether the signup was verified. The first record for an address is kept. The ASN, the header and the protocol are evidence for the report and for cleanup. The Worker never refuses a request because of them. KV also holds the rate limit counters and caches. A KV record does not prove that an address is subscribed.

A failed provider call retries by Durable Object alarm. There are eight attempts in total. After that, the coordinator stores an `exhausted` record, and an operator must investigate. The next accepted intent clears the record. A 4xx answer to a create, other than 409 and 429, is final and does not retry.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/subscribe` | Subscribe an address |
| POST | `/api/confirm` | Confirm a double opt-in. The body is `{"token": "<subscriber uuid>"}` |
| GET | `/api/unsubscribe` | Show the signed unsubscribe form. This changes nothing |
| POST | `/api/unsubscribe` | Request removal, with a signed token or operator authorization |
| POST | `/api/unsubscribe/confirm` | Submit the signed form |
| GET | `/api/newsletters` | List newsletter issues |
| GET | `/api/subscriber-count` | Get the combined count, cached for 10 minutes |
| GET | `/api/signup-stats` | Report recent signups. Operator authorization is required |
| GET | `/api/health` | Health check |
| POST | `/api/test-email` | Send a test email. Operator authorization is required |

`/api/subscriber-count` counts confirmed subscribers on the list and adds LinkedIn followers.

## Security

- With `TURNSTILE = "on"`, `/api/subscribe` requires a Turnstile token in the `cf-turnstile-response` field. A missing or rejected token gets 400. A missing secret, a missing hostname list or an unreachable siteverify gets 503, so the check never fails open. The operator bearer token passes without a challenge.
- A token passes on three checks of the siteverify answer: `success` is true, `action` is `signup`, and `hostname` is in `TURNSTILE_HOSTNAMES`. The last two refuse a token that was solved on another page.
- With `TURNSTILE = "off"`, no request is refused. A token that arrives is still verified, and the record stores the result.
- A signup that is not verified causes one email at most: the opt-in mail from Listmonk. It gets no 48-hour reminder, and a repeat of the request does not resend the link.
- `BLOCKED_IPS` refuses listed clients at `/api/subscribe` and `/api/confirm`. It is in the Worker because zone WAF rules do not cover the `workers.dev` hostname. The check runs before the challenge. The secret is optional and is not set in production: the list of six addresses was removed on 2026-11-09, after `TURNSTILE` went `on`. `docs/REFERENCE.md` records the addresses.
- Both endpoints allow five requests a minute for each IP address. The limit fails open on KV errors and is not atomic.
- `/api/confirm` accepts only a UUID. It reports a provider failure as a failure.
- A plain fetch of the confirmation link confirms nothing, because the site must run JavaScript. A scanner that runs JavaScript can still confirm.
- Unsubscribing requires a signed token or the operator bearer token. A signed GET link only shows a form.
- An accepted unsubscribe is a durable tombstone. An anonymous signup cannot undo it.
- Removal returns HTTP 202 with `status: "unverified"`, because a provider 2xx does not prove removal.
- Request bodies are limited to 4 KB for signup, 2 KB for unsubscribe and 1 KB elsewhere. A Turnstile token is up to 2048 characters.
- `/api/test-email` is refused when `ENVIRONMENT` is missing or unknown.

Do not render provider values as HTML in a client. This code has no HTML sanitizer.

## Watching for a signup spike

`GET /api/signup-stats` reads the KV signup records and counts those of the last 24 hours and the last 7 days. It needs the operator bearer token. The 7-day numbers include the last 24 hours.

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://newsletter-api.philippd.workers.dev/api/signup-stats
```

```json
{
  "generatedAt": "2026-11-09T12:00:00.000Z",
  "records": 148,
  "undated": 0,
  "windows": {
    "24h": {
      "signups": 4,
      "unverified": 3,
      "withoutSecChUa": 3,
      "byIp": [{ "ip": "203.0.113.5", "count": 3 }, { "ip": "198.51.100.7", "count": 1 }],
      "byAsn": [{ "asn": 64500, "asOrganization": "Example Hosting", "count": 3 }, { "asn": null, "asOrganization": null, "count": 1 }],
      "byUserAgent": [{ "userAgent": "Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36", "count": 3 }, { "userAgent": "...", "count": 1 }],
      "byHttpProtocol": [{ "httpProtocol": "HTTP/1.1", "count": 3 }, { "httpProtocol": "HTTP/2", "count": 1 }]
    },
    "7d": { "signups": 9, "unverified": 5, "withoutSecChUa": 4, "byIp": [], "byAsn": [], "byUserAgent": [], "byHttpProtocol": [] }
  },
  "recent": [
    {
      "timestamp": "2026-11-09T11:40:00.000Z",
      "ip": "203.0.113.5",
      "asn": 64500,
      "asOrganization": "Example Hosting",
      "userAgent": "Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36",
      "secChUa": false,
      "httpProtocol": "HTTP/1.1",
      "verified": false
    }
  ],
  "recentTruncated": false,
  "alert": {
    "triggered": true,
    "reasons": [
      { "rule": "ip_24h", "ip": "203.0.113.5", "count": 3 },
      { "rule": "user_agent_24h", "userAgent": "Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36", "count": 3 }
    ],
    "thresholds": { "signups24h": 10, "repeat24h": 3 }
  }
}
```

Poll it every hour. `alert.triggered` is true when one of these holds for the last 24 hours:

| Rule | Condition |
|---|---|
| `signups_24h` | More than 10 signups |
| `ip_24h` | 3 or more signups from one IP address |
| `user_agent_24h` | 3 or more signups with one identical user-agent string |

Treat any answer other than HTTP 200 as a failed check, not as a quiet day. A KV error returns 500.

`recent` lists each signup of the last 7 days, newest first, 200 at most. `recentTruncated` is true when there were more. Use it to read a cluster across fields. The bot of November 2026 claimed Chrome 124 on Windows, sent no `Sec-CH-UA` header and used HTTP/1.1. A real Chrome sends the header and uses HTTP/2 or HTTP/3. Firefox and Safari send no such header, so `secChUa: false` means something only next to a Chrome user agent.

No alert rule reads `secChUa` or `httpProtocol`, and the Worker never refuses a request because of them. Another scraper used the same user-agent string in the same hour, and about 20 real subscribers arrive through VPNs or relays. Decide on a cluster, not on one row.

Limits of the report:

- It counts addresses, not requests. A record is the first signup of an address, and an unsubscribe deletes it.
- A request that the challenge refuses leaves no record. Use `npx wrangler tail --env production` to see refused requests.
- Records made before this endpoint existed have no ASN and count as unverified. Their `secChUa` and `httpProtocol` are `null`, and `withoutSecChUa` does not count them.
- Each breakdown lists the 50 largest groups. The alert uses all groups.
- The report contains IP addresses and no email address.

## Local development

Run all commands from `workers/newsletter-api/`.

```bash
npm install
npm run dev      # http://localhost:8787
npm run verify   # Typecheck, configuration guard and all test suites
```

Put local values in `.dev.vars`, which Git ignores. Use dummy addresses and non-production providers only.

The default environment is the development Worker `newsletter-api-dev`. It has placeholder KV and R2 bindings and no provider settings. It cannot reach production storage. `npm run check:config` enforces this.

| Command | Runs |
|---|---|
| `npm test` | Unit tests in Node with mocked KV, R2 and providers |
| `npm run test:runtime` | Integration tests in workerd |
| `npm run test:invariants` | Subscription rules and alarm tests in workerd |
| `npm run test:inventory` | Subscriber inventory tests |
| `npm run test:config` | Configuration and deploy wrapper tests |
| `npm run typecheck` | `tsc --noEmit` |

## Deployment

```bash
npm run deploy:production              # Verify, then deploy
npm run deploy:production -- --dry-run # Verify and bundle only
```

The wrapper accepts only `--dry-run`. Do not use a bare `wrangler deploy`, because it uploads the development Worker. `npm run deploy` refuses on purpose.

There is no CI. A Worker deploy does not change Listmonk. See `listmonk/README.md` for the template installation.

To roll back, use a forward deploy that keeps the `SubscriptionCoordinator` class. See `docs/REFERENCE.md`. To pause subscriber writes, deploy with `COORDINATOR_MODE = "legacy"`.

To return to single opt-in, set `DOUBLE_OPTIN` to `off` and set list 3 to single opt-in together.

## Configuration

Production variables are in `wrangler.toml`:

| Variable | Purpose |
|---|---|
| `ALLOWED_ORIGIN` | Allowed CORS origins |
| `ENVIRONMENT` | `development` or `production` |
| `COORDINATOR_MODE` | `on`, or `legacy` to pause subscriber writes |
| `DOUBLE_OPTIN` | `on` requires confirmation |
| `TURNSTILE` | `on` refuses a signup without a passed Turnstile challenge. `off` verifies a token only if one arrives |
| `TURNSTILE_HOSTNAMES` | Hostnames whose widget may issue a token, separated by commas. Required when `TURNSTILE` is `on`. Never list `localhost` or `127.0.0.1` in production |
| `PROVIDER_BUDGET_MS` | Time limit for one provider phase |
| `LINKEDIN_NEWSLETTER_URLS` | LinkedIn pages for the follower count |
| `LISTMONK_API_URL`, `LISTMONK_LIST_ID` | Listmonk location and list |
| `LISTMONK_WELCOME_TEMPLATE_ID` | Welcome template, used only when `DOUBLE_OPTIN` is off |

Production secrets are set with `npx wrangler secret put <NAME> --env production`:

| Secret | Purpose |
|---|---|
| `LISTMONK_API_USER`, `LISTMONK_API_TOKEN` | Listmonk API access |
| `PLUNK_SECRET_KEY` | Fallback welcome email |
| `ADMIN_TOKEN` | Operator bearer token |
| `UNSUBSCRIBE_HMAC_SECRET` | Signs unsubscribe tokens |
| `BLOCKED_IPS` | Client IPs to refuse, separated by commas |
| `TURNSTILE_SECRET` | Turnstile secret key for siteverify. Set it before `TURNSTILE` is `on` |
| `UNSUBSCRIBE_BASE_URL` | Optional origin for unsubscribe links |

## Local-only files

Git ignores `*.csv` in the Worker directory. `dashboard.sh`, `dashboard.html`, `export-subscribers.sh`, `signup-growth.html` and `experiments/` are untracked. CSV exports hold subscriber addresses, so do not commit or publish them.

## License

MIT
