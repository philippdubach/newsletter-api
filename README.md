# Newsletter API

A Cloudflare Workers API for managing newsletter subscriptions. Handles email subscription, unsubscription, and newsletter listing with rate limiting and security best practices.

## Features

- Email subscription with validation and rate limiting
- Unsubscribe functionality
- Newsletter archive listing from R2 storage
- Welcome email via Resend
- Subscriber count endpoint
- Health check endpoint
- CORS with origin validation
- Honeypot spam protection

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/subscribe` | Subscribe an email address |
| POST | `/api/unsubscribe` | Remove a subscription |
| GET | `/api/newsletters` | List available newsletters |
| GET | `/api/subscriber-count` | Get subscriber count |
| GET | `/api/health` | Health check |
| POST | `/api/test-email` | Test email sending (dev only or auth required) |

## Requirements

- Node.js 18+
- Cloudflare account with Workers, KV, and R2 enabled
- Resend account for email sending (optional)

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
RESEND_API_KEY=your_resend_api_key
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

Deploy to Cloudflare Workers:
```bash
npm run deploy
```

For production deployment:
```bash
wrangler deploy --env production
```

## Configuration

Environment variables are configured in `wrangler.toml`:

| Variable | Description |
|----------|-------------|
| `ALLOWED_ORIGIN` | Comma-separated list of allowed CORS origins |
| `ENVIRONMENT` | `development` or `production` |
| `RESEND_API_KEY` | API key for Resend email service (set as secret) |
| `ADMIN_TOKEN` | Token for protected endpoints (set as secret) |

Set secrets using wrangler:
```bash
wrangler secret put RESEND_API_KEY
wrangler secret put ADMIN_TOKEN
```

## Testing

Run the test suite:
```bash
npm test
```

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
