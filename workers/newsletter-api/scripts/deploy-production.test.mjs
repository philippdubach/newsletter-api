import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { WORKER_DIR, deployProduction, parseArgs, wranglerArgs } from './deploy-production.mjs';

const script = fileURLToPath(new URL('./deploy-production.mjs', import.meta.url));

function harness(results = {}) {
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    return command === 'npm' ? (results.npm ?? { status: 0 }) : (results.wrangler ?? { status: 0 });
  };
  return { calls, spawn, log: () => {} };
}
const run = (argv, h, extra = {}) => deployProduction(argv, { spawn: h.spawn, log: h.log, cwd: WORKER_DIR, ...extra });

test('parseArgs accepts nothing or one --dry-run', () => {
  assert.deepEqual(parseArgs([]), { dryRun: false });
  assert.deepEqual(parseArgs(['--dry-run']), { dryRun: true });
});

test('every other argument is rejected before any process is spawned', () => {
  const bad = [
    ['--env', 'staging'], ['--env=dev'], ['--config', 'x.toml'], ['--name', 'x'], ['--var', 'A:b'],
    ['--unknown'], ['positional'], ['--dry-run', '--dry-run'], ['--dry-run', '--env', 'production'], ['--dry-run=true'],
  ];
  for (const argv of bad) {
    const h = harness();
    assert.equal(run(argv, h), 1, argv.join(' '));
    assert.equal(h.calls.length, 0, argv.join(' '));
  }
});

test('running outside the Worker directory is rejected before spawning', () => {
  const h = harness();
  assert.equal(run([], h, { cwd: tmpdir() }), 1);
  assert.equal(h.calls.length, 0);
});

test('a failing verification gate never reaches Wrangler', () => {
  const h = harness({ npm: { status: 3 } });
  assert.equal(run([], h), 3);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].command, 'npm');
  assert.deepEqual(h.calls[0].args, ['run', 'verify']);
});

test('a verification spawn error never reaches Wrangler', () => {
  const h = harness({ npm: { status: null, error: new Error('boom') } });
  assert.equal(run([], h), 1);
  assert.equal(h.calls.length, 1);
});

test('after verification Wrangler runs with a fixed config and production env', () => {
  const h = harness();
  assert.equal(run([], h), 0);
  assert.equal(h.calls.length, 2);
  const [, wrangler] = h.calls;
  assert.equal(wrangler.command, 'npx');
  assert.deepEqual(wrangler.args, ['--no-install', 'wrangler', 'deploy', '--config', join(WORKER_DIR, 'wrangler.toml'), '--env', 'production']);
});

test('--dry-run is forwarded and a Wrangler failure is propagated', () => {
  const h = harness({ wrangler: { status: 7 } });
  assert.equal(run(['--dry-run'], h), 7);
  assert.deepEqual(h.calls[1].args.slice(-1), ['--dry-run']);
  assert.deepEqual(wranglerArgs({ dryRun: false }).includes('--dry-run'), false);
});

test('CLI rejects a forbidden flag without running npm', () => {
  const dir = mkdtempSync(join(tmpdir(), 'fake-npm-'));
  const marker = join(dir, 'npm-called');
  const fake = join(dir, 'npm');
  writeFileSync(fake, `#!/bin/sh\ntouch "${marker}"\nexit 0\n`);
  chmodSync(fake, 0o755);
  const result = spawnSync(process.execPath, [script, '--env', 'dev'], {
    cwd: WORKER_DIR, encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unsupported argument/);
  assert.equal(existsSync(marker), false);
});

test('CLI stops with the gate status when npm verify fails', () => {
  const dir = mkdtempSync(join(tmpdir(), 'fake-npm-'));
  const fake = join(dir, 'npm');
  writeFileSync(fake, '#!/bin/sh\nexit 4\n');
  chmodSync(fake, 0o755);
  const result = spawnSync(process.execPath, [script, '--dry-run'], {
    cwd: WORKER_DIR, encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
  });
  assert.equal(result.status, 4);
  assert.match(result.stderr, /not deploying/);
});
