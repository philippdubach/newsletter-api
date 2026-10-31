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

export const DRAIN_PATH = '/__harness__/drain-background-work';

// Test-only entry. It imports the real Worker and forwards every call to it,
// but hands it a ctx whose waitUntil also records the promise. A private route
// then awaits everything recorded, including work scheduled while draining.
// Miniflare exposes no response.waitUntil, so this is how background work is
// made observable. Production source is not touched.
function wrapperSource(entry) {
  return `
import worker from ${JSON.stringify(entry)};
// Re-exported so Miniflare can resolve the Durable Object class by name from
// this entrypoint. A star export skips the default, which is defined below.
export * from ${JSON.stringify(entry)};
const pending = new Set();
const DRAIN_PATH = ${JSON.stringify(DRAIN_PATH)};
export default {
  async fetch(request, env, ctx) {
    if (new URL(request.url).pathname === DRAIN_PATH) {
      let settled = 0;
      while (pending.size > 0) {
        const batch = [...pending];
        await Promise.allSettled(batch);
        for (const p of batch) pending.delete(p);
        settled += batch.length;
      }
      return Response.json({ drained: settled });
    }
    const tracked = new Proxy(ctx, {
      get(target, prop) {
        if (prop === 'waitUntil') {
          return (promise) => {
            const p = Promise.resolve(promise);
            pending.add(p);
            return target.waitUntil(p);
          };
        }
        const value = Reflect.get(target, prop, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    return worker.fetch(request, env, tracked);
  },
};
`;
}

async function bundleWorker(entry) {
  const result = await build({
    stdin: { contents: wrapperSource(entry), resolveDir: workerDir, sourcefile: 'harness-entry.mjs', loader: 'js' },
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
 * Starts the Worker in workerd. Returns the runtime, the egress record, a drain
 * function for background work, and a dispose function.
 */
export async function startRuntime({ entry = join(workerDir, 'src/index.ts'), extraBindings = {}, outboundService, withKv = true } = {}) {
  const script = await bundleWorker(entry);
  const { guard, attempts } = createEgressGuard();
  // An explicit handler lets a suite stand in for the provider; the default is
  // the deny-everything guard, so no suite silently inherits permissive egress.
  const handler = outboundService ?? guard;

  const runtime = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script,
      // Matches wrangler.toml, so request and response semantics are the same.
      compatibilityDate: '2024-01-01',
      bindings: { ...TEST_BINDINGS, ...extraBindings },
      kvNamespaces: withKv ? ['NEWSLETTER_SUBSCRIBERS'] : undefined,
      r2Buckets: ['R2_BUCKET'],
      durableObjects: { SUBSCRIPTION_COORDINATOR: 'SubscriptionCoordinator' },
      outboundService: (request) => handler(request),
    }),
  );

  return {
    runtime,
    attempts,
    /** Direct handle on the coordinator, for asserting durable state. */
    coordinator: async (email) => {
      const namespace = await runtime.getDurableObjectNamespace('SUBSCRIPTION_COORDINATOR');
      return namespace.get(namespace.idFromName(email.trim().toLowerCase()));
    },
    /** Waits until every ctx.waitUntil promise the Worker registered has settled. */
    // Consume any response body before calling this. `dispatchFetch` returns a
    // live stream, and issuing the drain request first can leave the body
    // already read, which surfaces intermittently as "Body is unusable".
    drain: async () => {
      const response = await runtime.dispatchFetch(`http://localhost${DRAIN_PATH}`);
      return (await response.json()).drained;
    },
    dispose: () => runtime.dispose(),
  };
}
