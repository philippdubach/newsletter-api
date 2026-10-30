# Newsletter API

A Cloudflare Workers API for managing newsletter subscriptions. Handles email subscription, unsubscription, and newsletter listing with rate limiting and security best practices.

## Features

- Email subscription with validation and rate limiting
- Unsubscribe functionality
- Newsletter archive listing from R2 storage
- Welcome email via **Listmonk** (self-hosted), with Plunk (direct API) as an automatic fallback if Listmonk is unreachable
- Subscriber count endpoint sourced from Listmonk (with KV fallback) and augmented with LinkedIn follower counts
- Health check endpoint
- CORS with origin validation
- Honeypot spam protection

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/subscribe` | Subscribe an email address |
| GET | `/api/unsubscribe` | Display the signed unsubscribe form without changing the subscription |
| POST | `/api/unsubscribe` | Request removal with a signed token or operator authorization; completion is unverified |
| POST | `/api/unsubscribe/confirm` | Submit the signed browser form and display the result |
| GET | `/api/newsletters` | List available newsletters |
| GET | `/api/subscriber-count` | Get combined subscriber count (Listmonk + LinkedIn followers), 10-min cached |
| GET | `/api/health` | Health check |
| POST | `/api/test-email` | Send a test email (operator authorization required in every environment) |

## Requirements

- Node.js 18+
- Cloudflare account with Workers, KV, and R2 enabled
- Plunk project (secret key) for the fallback welcome email (optional)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/philippdubach/newsletter-api.git
cd newsletter-api/workers/newsletter-api
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.dev.vars` file for local development:
```
PLUNK_SECRET_KEY=your_plunk_secret_key
ADMIN_TOKEN=your_admin_token
UNSUBSCRIBE_HMAC_SECRET=your_dev_hmac_secret
LISTMONK_API_URL=https://mail.example.com
LISTMONK_API_USER=user
LISTMONK_API_TOKEN=token
LISTMONK_LIST_ID=0
```

Point `LISTMONK_*` at dummy/non-production values; the dev worker shares
production KV/R2 storage, so never exercise it with real subscriber addresses.

4. Update `wrangler.toml` with your KV namespace IDs and R2 bucket name.

## Development

Start the local development server:
```bash
npm run dev
```

The API will be available at `http://localhost:8787`.

## Deployment

Deploy to production:
```bash
npm run deploy:production
# or equivalently:
npx wrangler deploy --env production
```

> ⚠️ **Always pass `--env production` for production.** The default (dev) Worker is
> named `newsletter-api-dev` so a plain `wrangler deploy` (or `npm run deploy`)
> uploads a development worker and can no longer overwrite the production
> Worker. Even so, deploy production with `npm run deploy:production` and do not
> ignore wrangler's no-env warning. Dev and production still share KV/R2
> resources, so only use dev with dummy data.

## Configuration

Environment variables are configured in `wrangler.toml`:

| Variable | Description |
|----------|-------------|
| `ALLOWED_ORIGIN` | Comma-separated list of allowed CORS origins |
| `ENVIRONMENT` | `development` or `production` |
| `LINKEDIN_NEWSLETTER_URLS` | Comma-separated list of LinkedIn newsletter URLs to scrape follower counts from |
| `LISTMONK_API_URL` | Base URL of the Listmonk instance (e.g. `https://mail.example.com`) |
| `LISTMONK_LIST_ID` | Numeric Listmonk list ID for the newsletter |
| `LISTMONK_WELCOME_TEMPLATE_ID` | Numeric Listmonk transactional template ID for the welcome email |

Secrets (set via `wrangler secret put ... --env production`):

| Secret | Description |
|--------|-------------|
| `LISTMONK_API_USER` | Listmonk API user (Basic auth username) |
| `LISTMONK_API_TOKEN` | Listmonk API token (Basic auth password) |
| `PLUNK_SECRET_KEY` | Plunk project secret key — used by the welcome-email fallback path |
| `ADMIN_TOKEN` | Operator bearer token required for `/api/test-email` and for admin-initiated unsubscribes |
| `UNSUBSCRIBE_HMAC_SECRET` | Signs subscriber-bound unsubscribe tokens (required for email unsubscribe links) |
| `UNSUBSCRIBE_BASE_URL` | Optional; origin used in unsubscribe links (defaults to the workers.dev hostname) |

```bash
wrangler secret put LISTMONK_API_USER --env production
wrangler secret put LISTMONK_API_TOKEN --env production
wrangler secret put PLUNK_SECRET_KEY --env production
wrangler secret put ADMIN_TOKEN --env production
wrangler secret put UNSUBSCRIBE_HMAC_SECRET --env production
```

Set the same secrets (with distinct values) for the dev worker if you exercise
the protected routes locally.

If `LISTMONK_*` secrets are removed, welcome email can fall through to Plunk.
Unsubscribe requests fail closed with 502 when Listmonk is not configured,
because missing configuration does not prove that existing Listmonk
subscriptions are absent. Restore the configuration or remove affected
subscriptions manually; this fallback is not a complete replacement.

## Testing

Run the test suite:
```bash
npm test
```
These tests run in Node with mocked bindings and provider responses; they are
not a Worker-runtime or live-provider integration test.

## Scripts

### Export Subscribers

Export all subscriber emails to a CSV file:
```bash
./export-subscribers.sh
```

This creates a `subscribers.csv` file with all current subscribers. The script:
- Fetches emails directly from Cloudflare KV (requires wrangler authentication)
- Excludes rate limit keys
- Outputs a CSV with an `email` header column

**Note:** Make sure you're authenticated with wrangler (`npx wrangler whoami`) before running.

## Security

Controls are endpoint-specific:

- **`POST /api/subscribe`** — rate limited (5 requests/minute/IP, fail-open on
  KV errors), honeypot field, bounded request body. The rate limiter is not
  atomic under concurrency.
- **`POST /api/subscribe` and `POST /api/unsubscribe`** — streamed request
  bodies are bounded to 1 KB and 2 KB respectively, not just by the declared
  Content-Length; JSON and URL-encoded forms are accepted. Invalid JSON, raw
  UTF-8, body shape or declared length produces a client error (4xx); the form
  decoder follows URLSearchParams' tolerant percent-decoding behavior.
- **`POST /api/unsubscribe`** — requires proof of control: a subscriber-bound
  HMAC token signed over the email address, or an operator bearer
  (`ADMIN_TOKEN`). Email-only requests are rejected. The Listmonk removal uses
  the documented plural API route and a failed or unconfigured removal is
  reported as a failure. A provider 2xx returns HTTP 202 with `success: false`
  and `status: "unverified"`: it reports receiving an upstream 2xx, not
  confirmed removal or a durable queue. There is no automatic retry; if another
  newsletter arrives, contact the operator. This changes the earlier 200/success
  response and clients must handle it explicitly. Signed GET links show a form
  and do not remove subscribers on prefetch; the form submits a POST.
- **Subscription ordering limitation** — KV intent checks cannot prevent an
  already in-flight Listmonk signup from completing after an unsubscribe. A
  successful response alone does not establish cross-system ordering; this
  requires a durable coordination and recovery design.
- **`POST /api/test-email`** — fail closed: refused when `ENVIRONMENT` is
  missing or unknown, and requires the operator bearer token in every
  environment.
- Email validation with an RFC 5322-compliant regex; CORS origin validation;
  timing-safe comparisons; security headers (X-Content-Type-Options,
  X-Frame-Options, X-XSS-Protection).

There is no HTML sanitizer in this codebase; do not render arbitrary values
from provider responses as HTML client-side.

## License

MIT
