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

Tests are in `src/index.test.ts` using Vitest with Miniflare environment (configured in `vitest.config.ts`). Tests mock KV and R2 bindings with `vi.fn()` and invoke the worker's `fetch` handler directly. Local dev secrets go in `.dev.vars` (not committed). Note: the suite currently has a config issue (`vitest-environment-miniflare` not installed) — fix before relying on CI.

## Deployment

Two environments in `wrangler.toml`: top-level (development) and `[env.production]`. Both define the same Worker name (`newsletter-api`), which makes `wrangler deploy` without an env flag dangerous — see warning below.

```bash
npm run deploy:production
# or equivalently:
npx wrangler deploy --env production
```

**⚠️ Do not run `wrangler deploy` (no env flag) or `npm run deploy`.** Because both the top-level and `[env.production]` blocks point at the same Worker name, a bare deploy uploads the **top-level dev env vars** (`ENVIRONMENT="development"`, `ALLOWED_ORIGIN="http://localhost:1313,..."`) to the production Worker. Result: prod CORS instantly breaks for `philippdubach.com`. Wrangler warns about the missing `--env` flag; do not ignore it. Secrets (`LISTMONK_*`, `PLUNK_SECRET_KEY`) are not per-env so they survive, but env vars get clobbered.

Operational reads (always pass `--env production`):

```bash
npx wrangler tail --env production --format pretty
npx wrangler kv key list --binding NEWSLETTER_SUBSCRIBERS --remote --env production
npx wrangler secret list --env production
```

No CI/CD — deployment is manual via Wrangler CLI.
