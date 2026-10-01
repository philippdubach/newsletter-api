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
| POST | `/api/unsubscribe` | Remove a subscription |
| GET | `/api/newsletters` | List available newsletters |
| GET | `/api/subscriber-count` | Get combined subscriber count (Listmonk + LinkedIn followers), 10-min cached |
| GET | `/api/health` | Health check |
| POST | `/api/test-email` | Test email sending (dev only or auth required) |

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
```

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

> ⚠️ **Always pass `--env production`.** The top-level and `[env.production]` blocks in `wrangler.toml` share the same Worker name, so `wrangler deploy` (or `npm run deploy`) without an env flag uploads the dev env vars to the production Worker and breaks CORS for the live origin. Wrangler emits a warning when no env is specified — do not ignore it.

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
| `ADMIN_TOKEN` | Token for `/api/test-email` in production |

```bash
wrangler secret put LISTMONK_API_USER --env production
wrangler secret put LISTMONK_API_TOKEN --env production
wrangler secret put PLUNK_SECRET_KEY --env production
wrangler secret put ADMIN_TOKEN --env production
```

To bypass Listmonk for welcome emails, delete the `LISTMONK_*` secrets — the Worker will fall through to the Plunk code path automatically.

## Testing

Run the test suite:
```bash
npm test
```

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

The API implements several security measures:

- Rate limiting (5 requests per minute per IP)
- Request size limits (1KB max)
- Email validation with RFC 5322 compliant regex
- XSS protection via HTML sanitization
- CORS origin validation
- Timing-safe token comparison
- Security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)
- Honeypot field for bot detection

## License

MIT
