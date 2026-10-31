#!/usr/bin/env node
// The only supported way to deploy production. It accepts a single optional
// --dry-run flag, runs the full verification gate, and then invokes the local
// Wrangler with a fixed config file and the production environment.
// Nothing else (--env, --config, --name, --var, ...) can be passed through.

import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const WORKER_DIR = join(here, '..');

// Returns { dryRun } or throws an Error for anything but one optional --dry-run.
export function parseArgs(argv) {
  let dryRun = false;
  for (const arg of argv) {
    if (arg !== '--dry-run') throw new Error(`unsupported argument ${JSON.stringify(arg)}; only --dry-run is accepted`);
    if (dryRun) throw new Error('--dry-run may only be given once');
    dryRun = true;
  }
  return { dryRun };
}

export function wranglerArgs({ dryRun }, workerDir = WORKER_DIR) {
  const args = ['deploy', '--config', join(workerDir, 'wrangler.toml'), '--env', 'production'];
  if (dryRun) args.push('--dry-run');
  return args;
}

const defaultSpawn = (command, args, options) => spawnSync(command, args, { stdio: 'inherit', ...options });

// `spawn` and `cwd` are injectable so tests never start real processes.
export function deployProduction(argv, { spawn = defaultSpawn, cwd = process.cwd(), workerDir = WORKER_DIR, log = console.error } = {}) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    log(`deploy:production: ${error.message}`);
    return 1;
  }

  let actualCwd;
  try {
    actualCwd = realpathSync(cwd);
    if (actualCwd !== realpathSync(workerDir)) throw new Error('wrong directory');
  } catch {
    log(`deploy:production: run this from the Worker directory (${workerDir})`);
    return 1;
  }

  const wrangler = join(workerDir, 'node_modules', '.bin', 'wrangler');
  if (!existsSync(wrangler)) {
    log('deploy:production: local Wrangler is not installed; run npm ci');
    return 1;
  }

  const verify = spawn('npm', ['run', 'verify'], { cwd: workerDir });
  if (verify.error || verify.status !== 0) {
    log('deploy:production: verification failed; not deploying');
    return verify.status || 1;
  }

  const deploy = spawn('npx', ['--no-install', 'wrangler', ...wranglerArgs(parsed, workerDir)], { cwd: workerDir });
  if (deploy.error) {
    log(`deploy:production: could not run Wrangler: ${deploy.error.message}`);
    return 1;
  }
  return deploy.status ?? 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = deployProduction(process.argv.slice(2));
}
