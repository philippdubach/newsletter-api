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
| `docs/REFERENCE.md` | Coordinator rollback, test design and the subscriber inventory tool |

## How signup works

```text
Site form -> POST /api/subscribe -> SubscriptionCoordinator -> Listmonk -> confirmation email
Email button -> philippdubach.com/?confirm#<id> -> POST /api/confirm -> Listmonk
```

1. The form posts the address to `/api/subscribe`.
2. The Worker checks the blocklist, the rate limit and the honeypot field.
3. `SubscriptionCoordinator` is one Durable Object for each address. It records the intent, so a signup and an unsubscribe cannot overlap.
4. The coordinator reads the current state from Listmonk. It creates the subscriber if the address is absent. It does not overwrite a blocklisted or unsubscribed address.
5. Listmonk sends the confirmation email, because list 3 is a double opt-in list.
6. The email button opens the site. The site posts the subscriber id to `/api/confirm`, and the Worker confirms in Listmonk.

The Worker sends no welcome email while `DOUBLE_OPTIN` is `on`.

Listmonk is the source of truth. KV keeps a shadow record with the time, IP address and user agent of each signup. KV also holds the rate limit counters and caches. A KV record does not prove that an address is subscribed.

A failed provider call retries by Durable Object alarm. There are eight attempts in total. After that, an operator must investigate.

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
| GET | `/api/health` | Health check |
| POST | `/api/test-email` | Send a test email. Operator authorization is required |

`/api/subscriber-count` counts confirmed subscribers on the list and adds LinkedIn followers.

## Security

- `BLOCKED_IPS` refuses listed clients at `/api/subscribe` and `/api/confirm`. It is in the Worker because zone WAF rules do not cover the `workers.dev` hostname.
- Both endpoints allow five requests a minute for each IP address. The limit fails open on KV errors and is not atomic.
- `/api/confirm` accepts only a UUID. It reports a provider failure as a failure.
- A plain fetch of the confirmation link confirms nothing, because the site must run JavaScript. A scanner that runs JavaScript can still confirm.
- Unsubscribing requires a signed token or the operator bearer token. A signed GET link only shows a form.
- An accepted unsubscribe is a durable tombstone. An anonymous signup cannot undo it.
- Removal returns HTTP 202 with `status: "unverified"`, because a provider 2xx does not prove removal.
- Request bodies are limited to 1 KB for signup and 2 KB for unsubscribe.
- `/api/test-email` is refused when `ENVIRONMENT` is missing or unknown.

Do not render provider values as HTML in a client. This code has no HTML sanitizer.

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
| `UNSUBSCRIBE_BASE_URL` | Optional origin for unsubscribe links |

## Local-only files

Git ignores `*.csv` in the Worker directory. `dashboard.sh`, `dashboard.html`, `export-subscribers.sh`, `signup-growth.html` and `experiments/` are untracked. CSV exports hold subscriber addresses, so do not commit or publish them.

## License

MIT
