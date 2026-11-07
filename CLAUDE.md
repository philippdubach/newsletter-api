# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Newsletter signup system: a Cloudflare Worker and Listmonk template overrides. `README.md` describes the system, and `docs/REFERENCE.md` holds design notes.

Built on Cloudflare Workers. Single-file application (`workers/newsletter-api/src/index.ts`) using **Listmonk** (self-hosted on Hetzner) as the email-sending source of truth, **KV** as a dual-write durable shadow + rate-limit + cache store, **R2** for newsletter archives (EU jurisdiction), and **Plunk** (direct `/v1/send` API) as an automatic fallback when Listmonk is unreachable. Listmonk itself relays all mail through Plunk SMTP (`next-smtp.useplunk.com:2587`) since 2026-10-01; Resend is no longer used.

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
1. Refuse `BLOCKED_IPS`, apply the rate limit, and reject the honeypot field.
2. Send the intent to `SubscriptionCoordinator`, one Durable Object for each address. It serializes signups and unsubscribes.
3. The coordinator reads Listmonk, then creates the subscriber if the address is absent. It writes the KV shadow record. A failed call retries by alarm, with eight attempts in total.
4. With `DOUBLE_OPTIN = "on"` (production), the create uses `preconfirm_subscriptions: false`, and the Worker sends no welcome. Listmonk mails the opt-in link because list 3 is a double opt-in list. The response carries `status: "confirmation_required"`. Change the Worker var and the list's opt-in type together.

**Confirm flow** (`handleConfirm`): the email links to `philippdubach.com/?confirm#<subscriber uuid>`. The site posts the id to `/api/confirm`, and the Worker posts to Listmonk's public `/subscription/optin/<uuid>`. Do not change the link format. The query avoids a stale cached homepage, and the fragment keeps the id out of logs. See `OPERATIONS.md` in the site repository.

`BLOCKED_IPS` is an optional comma-separated secret. It lives in the Worker because zone WAF rules do not cover the `workers.dev` hostname.

The welcome and Plunk fallback paths run only when `DOUBLE_OPTIN` is off.

**Subscriber-count** (`/api/subscriber-count`): Listmonk is the source of truth. Calls `GET /api/subscribers?list_id={LISTMONK_LIST_ID}&subscription_status=confirmed&per_page=1` and reads `data.total`. The status filter excludes blocklisted, unsubscribed and unconfirmed rows. This avoids the JOIN double-count bug in `/api/lists/{id}.subscriber_count`. Falls back to counting KV keys (excluding `rate_limit:*` and `cache:*`) if Listmonk is unreachable. Adds LinkedIn follower counts (cached, scraped from `LINKEDIN_NEWSLETTER_URLS`) and rounds the total up to the nearest 10. The combined response is cached in KV under `cache:subscriber_count` for 10 minutes.

**Bindings (defined in `wrangler.toml`):**
- `NEWSLETTER_SUBSCRIBERS` — KV namespace (subscriber shadow + rate limits + caches)
- `R2_BUCKET` — R2 bucket `static-eu` (EU jurisdiction) for newsletter archive files
- `SUBSCRIPTION_COORDINATOR` — Durable Object namespace, one object for each address
- Vars: `ALLOWED_ORIGIN`, `ENVIRONMENT`, `COORDINATOR_MODE`, `DOUBLE_OPTIN`, `PROVIDER_BUDGET_MS`, `LINKEDIN_NEWSLETTER_URLS`, `LISTMONK_API_URL`, `LISTMONK_LIST_ID`, `LISTMONK_WELCOME_TEMPLATE_ID`
- Secrets (set via `wrangler secret put ... --env production`): `LISTMONK_API_USER`, `LISTMONK_API_TOKEN`, `PLUNK_SECRET_KEY`, `ADMIN_TOKEN`, `UNSUBSCRIBE_HMAC_SECRET`, `BLOCKED_IPS`

**KV key conventions:**
- Subscriber emails stored directly as keys (lowercased) with subscription metadata as the value
- `rate_limit:{ip}` — short-TTL rate-limit counter
- `cache:subscriber_count` — 10-min cached combined count payload
- `cache:linkedin_last_known:{hash}` — last successful LinkedIn follower count per URL

**Env interface:** The `Env` type in `index.ts` defines all bindings and environment variables.

## Testing

Unit tests in `src/**/*.test.ts` run under Node with mocked KV, R2 and fetch. Tests in `test/` run the Worker in workerd. Configuration and deploy-wrapper tests run through `node:test` in `scripts/`. `npm run verify` runs typechecking, both suites and the config guard. Local dev secrets go in ignored `.dev.vars`; use only non-production provider credentials and dummy addresses.

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

## Listmonk templates

`listmonk/static/` overlays the Listmonk templates at `/etc/listmonk/static` on `pd-prod`. See `listmonk/README.md`. Render a template offline before you install it. Do not send test signups without authorization.

## Subscriber data

CSV exports in `workers/newsletter-api/` hold addresses. Git ignores them. Never commit, publish or delete them without the owner's request.
