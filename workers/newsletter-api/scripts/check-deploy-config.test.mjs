import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
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
[vars]
ENVIRONMENT = "development"
ALLOWED_ORIGIN = "http://localhost:1313"
[env.production]
name = "newsletter-api"
[[env.production.kv_namespaces]]
binding = "NEWSLETTER_SUBSCRIBERS"
id = "prod-kv-id"
[[env.production.r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "static-eu"
[env.production.vars]
ENVIRONMENT = "production"
`;

const check = (text) => checkConfig(parseConfig(text));

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
  const errors = check(SAFE.replace('ENVIRONMENT = "development"', 'ENVIRONMENT = "production"'));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /must be "development"/);
});

test('missing production bindings are rejected', () => {
  const errors = check(SAFE.replace(/\[\[env\.production\.kv_namespaces\]\]\nbinding = "NEWSLETTER_SUBSCRIBERS"\nid = "prod-kv-id"\n/, ''));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /no KV namespace/);
});

test('comments and quoted hashes do not confuse the parser', () => {
  const config = parseConfig(`
name = "newsletter-api-dev" # trailing comment
[vars]
ENVIRONMENT = "development"
ALLOWED_ORIGIN = "https://example.invalid/#fragment"
[env.production]
name = "newsletter-api"
[[env.production.kv_namespaces]]
id = "prod-kv-id"
[[env.production.r2_buckets]]
bucket_name = "static-eu"
[env.production.vars]
ENVIRONMENT = "production"
`);
  assert.equal(config.get('vars')[0].get('ALLOWED_ORIGIN'), 'https://example.invalid/#fragment');
  assert.deepEqual(checkConfig(config), []);
});

test('the CLI refuses a development deploy', () => {
  const result = spawnSync(process.execPath, [script, '--refuse-dev-deploy'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Refusing to deploy the development Worker/);
  assert.match(result.stderr, /deploy:production/);
});

test('the CLI fails on an unsafe configuration file', () => {
  const result = spawnSync(process.execPath, [script, '--config', join(workerDir, 'package.json')], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Deploy configuration is unsafe/);
});
