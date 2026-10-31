#!/usr/bin/env node
// Guard the Wrangler configuration so a development Worker cannot reach
// production data or email real subscribers.
//
// The check uses smol-toml (a dev dependency) so the file is parsed with real
// TOML semantics. Unknown environments fail closed.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { fileURLToPath } from 'node:url';

const PROVIDER_KEYS = [
  'LISTMONK_API_URL',
  'LISTMONK_API_USER',
  'LISTMONK_API_TOKEN',
  'LISTMONK_LIST_ID',
  'LISTMONK_WELCOME_TEMPLATE_ID',
  'PLUNK_SECRET_KEY',
];

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const asArray = (value) => (Array.isArray(value) ? value : []);
const REQUIRED_KV = 'NEWSLETTER_SUBSCRIBERS';
const REQUIRED_R2 = 'R2_BUCKET';
const REQUIRED_DO = 'SUBSCRIPTION_COORDINATOR';
const REQUIRED_DO_CLASS = 'SubscriptionCoordinator';
const PROD_NAME = 'newsletter-api';

// Parses with a real TOML parser so single-quoted values, quoted keys and
// inline tables cannot be read differently here than by Wrangler. Throws on
// malformed TOML. Returns the plain parsed object.
export function parseConfig(text) {
  return parseToml(text);
}

function bindings(owner, key) {
  const raw = owner?.[key];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw.filter(isObject) : [];
}

function strings(entries, ...keys) {
  return entries.flatMap((entry) => keys.map((key) => entry[key]).filter((v) => typeof v === 'string' && v));
}

function checkBindingNames(errors, label, entries, required, kind) {
  if (entries.length === 0) errors.push(`${label} has no ${kind}`);
  for (const entry of entries) {
    if (entry.binding !== required) {
      errors.push(`${label} ${kind} binding must be named ${required}, found ${JSON.stringify(entry.binding)}`);
    }
  }
  if (entries.length > 0 && !entries.some((entry) => entry.binding === required)) {
    errors.push(`${label} is missing the ${required} binding`);
  }
}

function findRemote(node, path, found) {
  if (Array.isArray(node)) node.forEach((item, i) => findRemote(item, `${path}[${i}]`, found));
  else if (isObject(node)) {
    for (const [key, value] of Object.entries(node)) {
      if (key === 'remote' && value === true) found.push(path || 'top level');
      else findRemote(value, path ? `${path}.${key}` : key, found);
    }
  }
}

export function checkConfig(config) {
  const errors = [];
  if (!isObject(config)) return ['the configuration is not a TOML table'];
  const dev = config;
  const devVars = isObject(dev.vars) ? dev.vars : {};
  const envs = isObject(dev.env) ? dev.env : {};
  const prod = isObject(envs.production) ? envs.production : {};
  const prodVars = isObject(prod.vars) ? prod.vars : {};

  for (const name of Object.keys(envs)) {
    if (name !== 'production') errors.push(`unknown environment "${name}" is not supported`);
  }
  if (!isObject(envs.production)) errors.push('the production environment is missing');

  if (typeof dev.name !== 'string' || !dev.name) errors.push('the development Worker has no name');
  if (prod.name !== PROD_NAME) errors.push(`the production Worker name must be "${PROD_NAME}"`);
  if (dev.name && dev.name === prod.name) {
    errors.push('the development and production Workers share a name');
  }

  const devKvEntries = bindings(dev, 'kv_namespaces');
  const prodKvEntries = bindings(prod, 'kv_namespaces');
  checkBindingNames(errors, 'development', devKvEntries, REQUIRED_KV, 'KV namespace');
  checkBindingNames(errors, 'production', prodKvEntries, REQUIRED_KV, 'KV namespace');
  for (const [label, entries] of [['development', devKvEntries], ['production', prodKvEntries]]) {
    for (const entry of entries) {
      if (typeof entry.id !== 'string' || !entry.id.trim()) errors.push(`${label} KV namespace has no id`);
    }
  }
  const prodKv = strings(prodKvEntries, 'id', 'preview_id');
  for (const id of strings(devKvEntries, 'id', 'preview_id')) {
    if (prodKv.includes(id)) errors.push(`development KV namespace ${id} is a production namespace`);
  }

  const devR2Entries = bindings(dev, 'r2_buckets');
  const prodR2Entries = bindings(prod, 'r2_buckets');
  checkBindingNames(errors, 'development', devR2Entries, REQUIRED_R2, 'R2 bucket');
  checkBindingNames(errors, 'production', prodR2Entries, REQUIRED_R2, 'R2 bucket');
  for (const [label, entries] of [['development', devR2Entries], ['production', prodR2Entries]]) {
    for (const entry of entries) {
      if (typeof entry.bucket_name !== 'string' || !entry.bucket_name.trim()) errors.push(`${label} R2 bucket has no bucket_name`);
    }
  }
  const prodR2 = strings(prodR2Entries, 'bucket_name', 'preview_bucket_name');
  for (const bucket of strings(devR2Entries, 'bucket_name', 'preview_bucket_name')) {
    if (prodR2.includes(bucket)) errors.push(`development R2 bucket ${bucket} is a production bucket`);
  }

  // The coordinator is what serializes writes per address. A missing binding
  // silently downgrades to the unserialized inline path, so its absence is an
  // error rather than something to discover in production. Unlike KV and R2 the
  // binding carries `name` and `class_name` rather than `binding`.
  for (const [label, owner] of [['development', dev], ['production', prod]]) {
    const table = owner?.durable_objects;
    const entries = isObject(table) && Array.isArray(table.bindings) ? table.bindings.filter(isObject) : [];
    if (entries.length === 0) errors.push(`${label} has no Durable Object`);
    const named = entries.filter((entry) => entry.name === REQUIRED_DO);
    if (entries.length > 0 && named.length === 0) {
      errors.push(`${label} Durable Object binding must be named ${REQUIRED_DO}`);
    }
    for (const entry of named) {
      if (entry.class_name !== REQUIRED_DO_CLASS) {
        errors.push(`${label} Durable Object class must be ${REQUIRED_DO_CLASS}, found ${JSON.stringify(entry.class_name)}`);
      }
    }
  }

  const migrations = Array.isArray(dev.migrations) ? dev.migrations.filter(isObject) : [];
  const declaresClass = migrations.some((migration) => {
    for (const key of ['new_classes', 'new_sqlite_classes']) {
      const list = migration[key];
      if (Array.isArray(list) && list.includes(REQUIRED_DO_CLASS)) return true;
    }
    return false;
  });
  if (!declaresClass) errors.push(`no migration declares the ${REQUIRED_DO_CLASS} class`);

  const remote = [];
  const { env: _env, ...devOnly } = dev;
  findRemote(devOnly, '', remote);
  for (const path of remote) errors.push(`development sets remote = true (${path}), which reaches real resources`);

  const routes = [];
  if (typeof dev.route === 'string' ? dev.route : isObject(dev.route)) routes.push('route');
  if (asArray(dev.routes).length > 0) routes.push('routes');
  for (const name of routes) errors.push(`development sets ${name}, which is a production route`);

  for (const key of PROVIDER_KEYS) {
    if (key in devVars) errors.push(`development sets ${key}, which reaches a real provider`);
  }

  if (devVars.ENVIRONMENT !== 'development') {
    errors.push('development ENVIRONMENT must be "development"');
  }
  if (prodVars.ENVIRONMENT !== 'production') {
    errors.push('production ENVIRONMENT must be "production"');
  }
  if (prodVars.LISTMONK_API_URL && devVars.LISTMONK_API_URL === prodVars.LISTMONK_API_URL) {
    errors.push('development and production share a Listmonk URL');
  }

  return errors;
}

export function loadConfig(path) {
  return parseConfig(readFileSync(path, 'utf8'));
}

function main(argv) {
  const here = dirname(fileURLToPath(import.meta.url));
  const defaultConfig = join(here, '..', 'wrangler.toml');
  const configIndex = argv.indexOf('--config');
  const configPath = configIndex >= 0 ? argv[configIndex + 1] : defaultConfig;

  if (argv.includes('--refuse-dev-deploy')) {
    console.error('Refusing to deploy the development Worker.');
    console.error('Development bindings are placeholders and it has no provider configuration.');
    console.error('Deploy production with: npm run deploy:production');
    return 1;
  }

  let errors;
  try {
    errors = checkConfig(loadConfig(configPath));
  } catch (error) {
    console.error(`Deploy configuration could not be read (${configPath}):`);
    console.error(`  - ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`);
    return 1;
  }
  if (errors.length > 0) {
    console.error(`Deploy configuration is unsafe (${configPath}):`);
    for (const error of errors) console.error(`  - ${error}`);
    return 1;
  }
  console.log(`Deploy configuration is isolated: ${configPath}`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
