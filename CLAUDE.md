# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Newsletter subscription management API built on Cloudflare Workers. Single-file application (`workers/newsletter-api/src/index.ts`) using **Listmonk** (self-hosted on Hetzner) as the email-sending source of truth, **KV** as a dual-write durable shadow + rate-limit + cache store, **R2** for newsletter archives (EU jurisdiction), and **Plunk** (direct `/v1/send` API) as an automatic fallback when Listmonk is unreachable. Listmonk itself relays all mail through Plunk SMTP (`next-smtp.useplunk.com:2587`) since 2026-10-01; Resend is no longer used.

## Commands

All commands run from `workers/newsletter-api/`:

```bash
npm run dev                 # Local dev server on http://localhost:8787
npm test                    # Run tests once (Vitest + Miniflare)
npm run test:watch          # Run tests in watch mode
npm run typecheck           # TypeScript type checking
npm run deploy:production   # Deploy to production — USE THIS
# npm run deploy            # DO NOT USE — see "Deployment" section below
```

## Architecture

**Single handler pattern:** `src/index.ts` exports a default Workers `fetch` handler that routes requests by method + pathname to handler functions (`handleSubscribe`, `handleUnsubscribe`, `handleGetNewsletters`, etc.).

**Subscribe flow** (`handleSubscribe`):
1. Sync KV write for the email (rate-limit + durable shadow).
2. `ctx.waitUntil` → `createListmonkSubscriber` (POST `/api/subscribers`) → `sendListmonkWelcome` (POST `/api/tx` with template id from `LISTMONK_WELCOME_TEMPLATE_ID`, pre-fetching the latest newsletter URL from R2).
3. On any Listmonk failure, falls back to `sendPlunkWelcomeFallback` with a legacy hardcoded welcome. Note: `/api/tx` is asynchronous, so an SMTP failure *inside* Listmonk does not trigger this fallback; it only shows in `journalctl -u listmonk` on the server.

To bypass Listmonk: delete `LISTMONK_API_USER` and `LISTMONK_API_TOKEN` secrets — `isListmonkConfigured()` will return false and the Worker will send the welcome via Plunk directly.

**Subscriber-count** (`/api/subscriber-count`): Listmonk is the source of truth. Calls `GET /api/subscribers?list_id={LISTMONK_LIST_ID}&per_page=1` and reads `data.total`. This avoids the JOIN double-count bug in `/api/lists/{id}.subscriber_count`. Falls back to counting KV keys (excluding `rate_limit:*` and `cache:*`) if Listmonk is unreachable. Adds LinkedIn follower counts (cached, scraped from `LINKEDIN_NEWSLETTER_URLS`) and rounds the total up to the nearest 10. The combined response is cached in KV under `cache:subscriber_count` for 10 minutes.

**Bindings (defined in `wrangler.toml`):**
- `NEWSLETTER_SUBSCRIBERS` — KV namespace (subscriber shadow + rate limits + caches)
- `R2_BUCKET` — R2 bucket `static-eu` (EU jurisdiction) for newsletter archive files
- Vars: `ALLOWED_ORIGIN`, `ENVIRONMENT`, `LINKEDIN_NEWSLETTER_URLS`, `LISTMONK_API_URL`, `LISTMONK_LIST_ID`, `LISTMONK_WELCOME_TEMPLATE_ID`
- Secrets (set via `wrangler secret put ... --env production`): `LISTMONK_API_USER`, `LISTMONK_API_TOKEN`, `PLUNK_SECRET_KEY`, `ADMIN_TOKEN` (not set in production, so `/api/test-email` returns 401 there)

**KV key conventions:**
- Subscriber emails stored directly as keys (lowercased) with subscription metadata as the value
- `rate_limit:{ip}` — short-TTL rate-limit counter
- `cache:subscriber_count` — 10-min cached combined count payload
- `cache:linkedin_last_known:{hash}` — last successful LinkedIn follower count per URL

**Env interface:** The `Env` type in `index.ts` defines all bindings and environment variables.

## Testing

Worker tests in `src/**/*.test.ts` run under Node with mocked KV, R2 and fetch, not workerd. Configuration and deploy-wrapper tests run through `node:test` in `scripts/`. `npm run verify` runs typechecking, both suites and the config guard. Local dev secrets go in ignored `.dev.vars`; use only non-production provider credentials and dummy addresses.

## Deployment

The top-level development Worker is `newsletter-api-dev`, with local placeholder KV/R2 bindings and no provider vars. `[env.production]` retains `newsletter-api` and its production bindings. The config guard rejects shared resources, provider vars in development and unknown named environments. Development defaults do not prevent explicit `.dev.vars` overrides from reaching real providers.

```bash
npm run deploy:production
npm run deploy:production -- --dry-run  # verify and bundle only
```

The deployment wrapper runs `npm run verify`, then `npx --no-install wrangler deploy` with a fixed absolute config path and `--env production`. It accepts only the optional `--dry-run`; target overrides are refused. Do not bypass the wrapper with raw deployment commands. `npm run deploy` refuses outright. Secrets are environment-specific; never copy production secrets into development.

Operational reads (always pass `--env production`):

```bash
npx wrangler tail --env production --format pretty
npx wrangler kv key list --binding NEWSLETTER_SUBSCRIBERS --remote --env production
npx wrangler secret list --env production
```

No CI/CD — deployment is manual via Wrangler CLI.
