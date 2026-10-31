// Shared harness for the runtime integration suite.
//
// The Worker is executed by Miniflare — the same runtime wrangler drives — with
// three properties the tests depend on:
//
//   * Bindings come from `TEST_BINDINGS` and nowhere else. Miniflare has no
//     configuration-file awareness, so `wrangler.toml`, `.dev.vars` and `.env`
//     are never read. Ambient credentials cannot reach the test Worker because
//     there is no code path that would look for them.
//   * Workerd state is in memory. Nothing is written to `.wrangler/state` or to
//     a namespace that exists in the account.
//   * Outbound traffic is wired to `outboundService`, not left to the runtime's
//     default egress. `createEgressGuard()` returns the handler and the list of
//     hosts it was asked for, so a test can assert both that the guard is
//     working (positive control) and that the provider was never contacted.
//
// `convertV4MiniflareOptions` is Miniflare's own compatibility bridge for the
// options shape used here; the current schema nests these under `workers`.

import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const workerDir = join(dirname(fileURLToPath(import.meta.url)), '..');

// Deliberately different from the values in wrangler.toml. A test asserts that
// the Worker echoes *this* origin, which proves the configuration file was not
// loaded behind the harness's back.
export const TEST_BINDINGS = Object.freeze({
  ENVIRONMENT: 'development',
  ALLOWED_ORIGIN: 'http://runtime-suite.invalid',
  // A reserved TLD, so an un-intercepted request cannot resolve. If the guard
  // is ever unwired, the control fails instead of reaching a real host.
  LINKEDIN_NEWSLETTER_URLS: 'https://egress-probe.runtime-suite.invalid/pulse/example',
  UNSUBSCRIBE_HMAC_SECRET: 'runtime-suite-hmac-secret-not-a-production-value',
});

export const EGRESS_PROBE_HOST = 'egress-probe.runtime-suite.invalid';

/**
 * Builds an outbound handler that records the requested host and denies it.
 * The same handler is passed to the runtime as `outboundService`, so a request
 * reaching `attempts` is proof that workerd's egress went through the guard.
 */
export function createEgressGuard() {
  const attempts = [];
  const guard = (request) => {
    attempts.push(new URL(request.url).host);
    return new Response('denied by the runtime test harness', { status: 403 });
  };
  return { guard, attempts };
}

async function bundleWorker() {
  const result = await build({
    entryPoints: [join(workerDir, 'src/index.ts')],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    target: 'es2021',
    write: false,
    logLevel: 'silent',
  });
  if (!result.outputFiles?.length) throw new Error('the Worker bundle was not produced');
  return result.outputFiles[0].text;
}

/**
 * Starts the Worker in workerd. Returns the runtime, the egress record, and a
 * dispose function.
 */
export async function startRuntime() {
  const script = await bundleWorker();
  const { guard, attempts } = createEgressGuard();

  const runtime = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script,
      // Matches wrangler.toml, so request and response semantics are the same.
      compatibilityDate: '2024-01-01',
      bindings: { ...TEST_BINDINGS },
      kvNamespaces: ['NEWSLETTER_SUBSCRIBERS'],
      r2Buckets: ['R2_BUCKET'],
      outboundService: guard,
    }),
  );

  return {
    runtime,
    attempts,
    dispose: () => runtime.dispose(),
  };
}
