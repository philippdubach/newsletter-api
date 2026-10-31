#!/usr/bin/env node
// Guard the Wrangler configuration so a development Worker cannot reach
// production data or email real subscribers.
//
// The check is deliberately dependency-free: it parses the small, hand-written
// TOML file directly instead of pulling a parser into the deployment path.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROVIDER_KEYS = [
  'LISTMONK_API_URL',
  'LISTMONK_API_USER',
  'LISTMONK_API_TOKEN',
  'LISTMONK_LIST_ID',
  'LISTMONK_WELCOME_TEMPLATE_ID',
  'PLUNK_SECRET_KEY',
];

function stripComment(line) {
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') quoted = !quoted;
    if (character === '#' && !quoted) return line.slice(0, index);
  }
  return line;
}

function unquote(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

// Returns { root, vars, tables } where tables maps a section path to an array of
// key/value maps, so repeated [[kv_namespaces]] entries stay separate.
export function parseConfig(text) {
  const tables = new Map();
  let current = '';
  const push = () => {
    if (!tables.has(current)) tables.set(current, []);
    if (tables.get(current).length === 0) tables.get(current).push(new Map());
    return tables.get(current).at(-1);
  };
  tables.set('', [new Map()]);

  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine).trim();
    if (!line) continue;
    if (line.startsWith('[[') && line.endsWith(']]')) {
      current = line.slice(2, -2).trim();
      tables.set(current, [...(tables.get(current) ?? []), new Map()]);
      continue;
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      current = line.slice(1, -1).trim();
      push();
      continue;
    }
    const separator = line.indexOf('=');
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim();
    push().set(key, unquote(line.slice(separator + 1)));
  }
  return tables;
}

const section = (tables, name) => tables.get(name)?.[0] ?? new Map();
const values = (tables, name, key) => (tables.get(name) ?? []).map((entry) => entry.get(key)).filter(Boolean);

export function checkConfig(tables) {
  const errors = [];
  const dev = section(tables, '');
  const devVars = section(tables, 'vars');
  const prod = section(tables, 'env.production');
  const prodVars = section(tables, 'env.production.vars');

  if (!dev.get('name')) errors.push('the development Worker has no name');
  if (dev.get('name') && dev.get('name') === prod.get('name')) {
    errors.push('the development and production Workers share a name');
  }

  const devKv = values(tables, 'kv_namespaces', 'id');
  const prodKv = values(tables, 'env.production.kv_namespaces', 'id');
  if (prodKv.length === 0) errors.push('production has no KV namespace');
  for (const id of devKv) {
    if (prodKv.includes(id)) errors.push(`development KV namespace ${id} is a production namespace`);
  }

  const devR2 = values(tables, 'r2_buckets', 'bucket_name');
  const prodR2 = values(tables, 'env.production.r2_buckets', 'bucket_name');
  if (prodR2.length === 0) errors.push('production has no R2 bucket');
  for (const bucket of devR2) {
    if (prodR2.includes(bucket)) errors.push(`development R2 bucket ${bucket} is a production bucket`);
  }

  for (const key of PROVIDER_KEYS) {
    if (devVars.has(key)) errors.push(`development sets ${key}, which reaches a real provider`);
  }

  if (devVars.get('ENVIRONMENT') !== 'development') {
    errors.push('development ENVIRONMENT must be "development"');
  }
  if (prodVars.get('ENVIRONMENT') !== 'production') {
    errors.push('production ENVIRONMENT must be "production"');
  }
  if (prodVars.get('LISTMONK_API_URL') && devVars.get('LISTMONK_API_URL') === prodVars.get('LISTMONK_API_URL')) {
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

  const errors = checkConfig(loadConfig(configPath));
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
