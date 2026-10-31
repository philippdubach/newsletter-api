import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkConfig, loadConfig, parseConfig } from './check-deploy-config.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workerDir = join(here, '..');
const script = join(here, 'check-deploy-config.mjs');
const realConfig = join(workerDir, 'wrangler.toml');

const SAFE = `
name = "newsletter-api-dev"
[[kv_namespaces]]
binding = "NEWSLETTER_SUBSCRIBERS"
id = "dev-placeholder"
[[r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "newsletter-dev-local"
[durable_objects]
bindings = [{ name = "SUBSCRIPTION_COORDINATOR", class_name = "SubscriptionCoordinator" }]
[[migrations]]
tag = "v1"
new_sqlite_classes = ["SubscriptionCoordinator"]
[vars]
ENVIRONMENT = "development"
COORDINATOR_MODE = "on"
ALLOWED_ORIGIN = "http://localhost:1313"
[env.production]
name = "newsletter-api"
[[env.production.durable_objects.bindings]]
name = "SUBSCRIPTION_COORDINATOR"
class_name = "SubscriptionCoordinator"
[[env.production.kv_namespaces]]
binding = "NEWSLETTER_SUBSCRIBERS"
id = "prod-kv-id"
[[env.production.r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "static-eu"
[env.production.vars]
ENVIRONMENT = "production"
COORDINATOR_MODE = "on"
`;

const check = (text) => checkConfig(parseConfig(text));
const has = (errors, re) => assert.ok(errors.some((e) => re.test(e)), errors.join('; ') || 'no errors');

test('the checked-in configuration passes', () => {
  assert.deepEqual(checkConfig(loadConfig(realConfig)), []);
});

test('the safe fixture passes', () => {
  assert.deepEqual(check(SAFE), []);
});

test('a shared KV namespace is rejected', () => {
  const errors = check(SAFE.replace('id = "dev-placeholder"', 'id = "prod-kv-id"'));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /production namespace/);
});

test('a shared R2 bucket is rejected', () => {
  const errors = check(SAFE.replace('bucket_name = "newsletter-dev-local"', 'bucket_name = "static-eu"'));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /production bucket/);
});

test('provider configuration in development is rejected', () => {
  for (const key of ['LISTMONK_API_URL', 'LISTMONK_LIST_ID', 'LISTMONK_WELCOME_TEMPLATE_ID', 'PLUNK_SECRET_KEY']) {
    const errors = check(SAFE.replace('[vars]', `[vars]\n${key} = "value"`));
    assert.equal(errors.length, 1, key);
    assert.match(errors[0], /real provider/);
  }
});

test('a development environment labelled production is rejected', () => {
  const errors = check(SAFE.replace(
    'ENVIRONMENT = "development"\nCOORDINATOR_MODE = "on"',
    'ENVIRONMENT = "production"\nCOORDINATOR_MODE = "on"',
  ));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /must be "development"/);
});

test('missing production bindings are rejected', () => {
  const errors = check(SAFE.replace(/\[\[env\.production\.kv_namespaces\]\]\nbinding = "NEWSLETTER_SUBSCRIBERS"\nid = "prod-kv-id"\n/, ''));
  assert.ok(errors.some((e) => /no KV namespace/.test(e)));
});

test('comments and quoted hashes do not confuse the parser', () => {
  const config = parseConfig(`
name = "newsletter-api-dev" # trailing comment
[[kv_namespaces]]
binding = "NEWSLETTER_SUBSCRIBERS"
id = "dev-placeholder"
[[r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "dev-bucket"
[durable_objects]
bindings = [{ name = "SUBSCRIPTION_COORDINATOR", class_name = "SubscriptionCoordinator" }]
[[migrations]]
tag = "v1"
new_sqlite_classes = ["SubscriptionCoordinator"]
[vars]
ENVIRONMENT = "development"
COORDINATOR_MODE = "on"
ALLOWED_ORIGIN = "https://example.invalid/#fragment"
[env.production]
name = "newsletter-api"
[[env.production.kv_namespaces]]
binding = "NEWSLETTER_SUBSCRIBERS"
id = "prod-kv-id"
[[env.production.r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "static-eu"
[[env.production.durable_objects.bindings]]
name = "SUBSCRIPTION_COORDINATOR"
class_name = "SubscriptionCoordinator"
[env.production.vars]
ENVIRONMENT = "production"
COORDINATOR_MODE = "on"
`);
  assert.equal(config.vars.ALLOWED_ORIGIN, 'https://example.invalid/#fragment');
  assert.deepEqual(checkConfig(config), []);
});

test('the CLI refuses a development deploy', () => {
  const result = spawnSync(process.execPath, [script, '--refuse-dev-deploy'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Refusing to deploy the development Worker/);
  assert.match(result.stderr, /deploy:production/);
});

test('the CLI fails on an unsafe configuration file', () => {
  const unsafeFile = join(mkdtempSync(join(tmpdir(), 'unsafe-')), 'wrangler.toml');
  writeFileSync(unsafeFile, 'name = "x"\n');
  const result = spawnSync(process.execPath, [script, '--config', unsafeFile], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Deploy configuration is unsafe/);
});

test('single-quoted values are read as real TOML', () => {
  const errors = check(SAFE.replace('id = "dev-placeholder"', "id = 'prod-kv-id'"));
  has(errors, /production namespace/);
  has(check(SAFE.replace('bucket_name = "newsletter-dev-local"', "bucket_name = 'static-eu'")), /production bucket/);
  assert.deepEqual(check(SAFE.replace('name = "newsletter-api-dev"', "name = 'newsletter-api-dev'")), []);
});

test('quoted keys cannot hide provider variables', () => {
  has(check(SAFE.replace('[vars]', '[vars]\n"LISTMONK_API_URL" = "x"')), /real provider/);
  has(check(SAFE.replace('[vars]', "[vars]\n'PLUNK_SECRET_KEY' = 'x'")), /real provider/);
});

test('inline tables cannot bypass the checks', () => {
  const inlineVars = SAFE.replace(/\[vars\][\s\S]*?\[env\.production\]/, '[env.production]')
    .replace('name = "newsletter-api-dev"\n',
      'name = "newsletter-api-dev"\nvars = { ENVIRONMENT = "development", COORDINATOR_MODE = "on", LISTMONK_LIST_ID = "3" }\n');
  has(check(inlineVars), /real provider/);
  const inlineKv = SAFE.replace(/\[\[kv_namespaces\]\][^\[]*/, 'kv_namespaces = [{ binding = "NEWSLETTER_SUBSCRIBERS", id = "prod-kv-id" }]\n');
  has(check(inlineKv.replace('name = "newsletter-api-dev"\n', 'name = "newsletter-api-dev"\n')), /production namespace/);
});

test('required binding names are enforced', () => {
  has(check(SAFE.replace('binding = "NEWSLETTER_SUBSCRIBERS"\nid = "dev-placeholder"', 'binding = "OTHER"\nid = "dev-placeholder"')), /NEWSLETTER_SUBSCRIBERS/);
  has(check(SAFE.replace('binding = "R2_BUCKET"\nbucket_name = "static-eu"', 'binding = "OTHER"\nbucket_name = "static-eu"')), /R2_BUCKET/);
});

test('resource identifiers cannot be missing or empty', () => {
  for (const id of ['dev-placeholder', 'prod-kv-id']) {
    has(check(SAFE.replace(`id = "${id}"`, 'id = ""')), /KV namespace has no id/);
    has(check(SAFE.replace(`id = "${id}"`, '')), /KV namespace has no id/);
  }
  for (const bucket of ['newsletter-dev-local', 'static-eu']) {
    has(check(SAFE.replace(`bucket_name = "${bucket}"`, 'bucket_name = ""')), /R2 bucket has no bucket_name/);
  }
});

test('the production Worker name and environment labels are required', () => {
  has(check(SAFE.replace('name = "newsletter-api"\n', 'name = "other"\n')), /production Worker name/);
  has(check(SAFE.replace(
    'ENVIRONMENT = "production"\nCOORDINATOR_MODE = "on"',
    'ENVIRONMENT = "development"\nCOORDINATOR_MODE = "on"',
  )), /production ENVIRONMENT/);
});

test('preview references to production resources are rejected', () => {
  has(check(SAFE.replace('id = "dev-placeholder"', 'id = "dev-placeholder"\npreview_id = "prod-kv-id"')), /production namespace/);
  has(check(SAFE.replace('bucket_name = "newsletter-dev-local"', 'bucket_name = "newsletter-dev-local"\npreview_bucket_name = "static-eu"')), /production bucket/);
});

test('remote development bindings and production routes are rejected', () => {
  has(check(SAFE.replace('id = "dev-placeholder"', 'id = "dev-placeholder"\nremote = true')), /remote = true/);
  has(check(SAFE.replace('name = "newsletter-api-dev"', 'name = "newsletter-api-dev"\nroutes = ["philippdubach.com/api/*"]')), /production route/);
  has(check(SAFE.replace('name = "newsletter-api-dev"', 'name = "newsletter-api-dev"\nroute = "philippdubach.com/*"')), /production route/);
  assert.deepEqual(check(SAFE.replace('name = "newsletter-api-dev"', 'name = "newsletter-api-dev"\nroutes = []')), []);
});

test('unknown named environments fail closed', () => {
  has(check(`${SAFE}\n[env.staging]\nname = "x"\n`), /unknown environment "staging"/);
});

test('malformed TOML throws from the parser and gives a clean CLI failure', () => {
  assert.throws(() => parseConfig('name = "unterminated'));
  const dir = mkdtempSync(join(tmpdir(), 'bad-toml-'));
  const file = join(dir, 'wrangler.toml');
  writeFileSync(file, 'name = "unterminated\n[[oops\n');
  const result = spawnSync(process.execPath, [script, '--config', file], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /could not be read/);
  assert.doesNotMatch(result.stderr, /\n\s+at /);
});

test('a missing coordinator binding is rejected', () => {
  const withoutDo = SAFE.replace(/\[durable_objects\]\nbindings = .*\n/, '');
  const errors = check(withoutDo);
  has(errors, /has no Durable Object/);
});

test('a wrongly named coordinator binding is rejected', () => {
  const errors = check(SAFE.replaceAll('name = "SUBSCRIPTION_COORDINATOR"', 'name = "COORDINATOR"'));
  has(errors, /must be named SUBSCRIPTION_COORDINATOR/);
});

test('a wrong coordinator class is rejected', () => {
  const errors = check(SAFE.replaceAll('class_name = "SubscriptionCoordinator"', 'class_name = "Other"'));
  has(errors, /class must be SubscriptionCoordinator/);
});

test('a missing migration is rejected', () => {
  const withoutMigration = SAFE.replace(/\[\[migrations\]\]\ntag = "v1"\nnew_sqlite_classes = .*\n/, '');
  const errors = check(withoutMigration);
  has(errors, /no migration declares the SubscriptionCoordinator class/);
});

test('a missing coordinator mode is rejected', () => {
  const errors = check(SAFE.replace(/COORDINATOR_MODE = "on"\n/g, ''));
  has(errors, /must set COORDINATOR_MODE/);
});

test('an unrecognised coordinator mode is rejected', () => {
  const errors = check(SAFE.replace(/COORDINATOR_MODE = "on"/g, 'COORDINATOR_MODE = "off"'));
  has(errors, /must be "on" or "legacy"/);
});

test('legacy mode is accepted', () => {
  assert.deepEqual(check(SAFE.replace(/COORDINATOR_MODE = "on"/g, 'COORDINATOR_MODE = "legacy"')), []);
});
