import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, realpath, symlink, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkPython, cleanupRuntime, resolveTool, runtimeEnvironment } from '../src/runtime.js';

test('tool discovery accepts PATH installations and resolves npm symlinks', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-tools-')));
  const previousPath = process.env.PATH;
  t.after(async () => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    await rm(root, { recursive: true, force: true });
  });
  const bin = join(root, 'custom-tools');
  await mkdir(bin);
  const npm = join(root, 'npm-cli.js');
  const python = join(bin, 'python3');
  await writeFile(npm, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  await writeFile(python, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  await symlink(npm, join(bin, 'npm'));
  process.env.PATH = bin;
  assert.equal(await resolveTool('npm'), npm);
  assert.equal(await resolveTool('python3'), python);
  await rm(join(bin, 'npm'));
  await rm(python);
  await assert.rejects(resolveTool('npm'), /npm/);
  await assert.rejects(resolveTool('python3'), /python3/);
});

test('Python preflight checks the required version and modules in an isolated process', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-python-')));
  const previousSecret = process.env.RUNTIME_TEST_SECRET;
  process.env.RUNTIME_TEST_SECRET = 'must-not-inherit';
  t.after(async () => {
    if (previousSecret === undefined) delete process.env.RUNTIME_TEST_SECRET;
    else process.env.RUNTIME_TEST_SECRET = previousSecret;
    await rm(root, { recursive: true, force: true });
  });
  const python = join(root, 'python3');
  await writeFile(python, `#!${process.execPath}
    require('node:fs').writeFileSync('invocation.json', JSON.stringify({
      args: process.argv.slice(2), cwd: process.cwd(), env: process.env,
    }));
  `, { mode: 0o755 });
  const env = runtimeEnvironment({ root, home: root, codexHome: root, stateDirectory: root, pythonPath: python });
  await checkPython(python, root, env);
  const invocation = JSON.parse(await readFile(join(root, 'invocation.json'), 'utf8'));
  assert.deepEqual(invocation.args, ['-I', '-c', 'import sys, sqlite3, tomllib; assert sys.version_info >= (3, 11)']);
  assert.equal(invocation.cwd, root);
  for (const [key, value] of Object.entries(env)) assert.equal(invocation.env[key], value);
  assert.equal(invocation.env.RUNTIME_TEST_SECRET, undefined);
});

test('Python preflight reports a failed or terminated prerequisite check', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-python-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const python = join(root, 'python3');
  for (const script of ['process.exit(1)', 'process.kill(process.pid, "SIGTERM")']) {
    await writeFile(python, `#!${process.execPath}\n${script}\n`, { mode: 0o755 });
    await assert.rejects(checkPython(python, root, {}), /Python 3\.11.*sqlite3.*tomllib/);
  }
});

test('scan environment excludes all inherited credential/config channels', () => {
  const poison = { INPUT_GITHUB_TOKEN: 'secret', GITHUB_TOKEN: 'secret', ACTIONS_RUNTIME_TOKEN: 'secret', GITHUB_OUTPUT: 'file', NODE_OPTIONS: '--require=evil', PYTHONPATH: 'evil', NPM_CONFIG_REGISTRY: 'evil', AWS_SECRET_ACCESS_KEY: 'secret', CODEX_CLI_PATH: 'evil', OPENAI_BASE_URL: 'evil', HTTPS_PROXY: 'evil' };
  const previous = Object.fromEntries(Object.keys(poison).map((key) => [key, process.env[key]]));
  Object.assign(process.env, poison);
  try {
    const paths = { root: '/tmp/owned', home: '/tmp/owned/home', codexHome: '/tmp/owned/codex', stateDirectory: '/tmp/owned/state', pythonPath: '/usr/bin/python3' };
    const installer = runtimeEnvironment(paths);
    const scanner = runtimeEnvironment(paths, 'scan-only-key');
    for (const key of Object.keys(poison)) { assert.equal(installer[key], undefined); assert.equal(scanner[key], undefined); }
    assert.equal(installer.OPENAI_API_KEY, undefined);
    assert.equal(scanner.OPENAI_API_KEY, 'scan-only-key');
    assert.equal(scanner.PYTHONSAFEPATH, '1');
    assert.equal(scanner.GIT_CONFIG_VALUE_0, '');
  } finally { for (const key of Object.keys(poison)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } }
});

test('shipped runtime lock matches the manifest and records dependency integrity', async () => {
  const lock = JSON.parse(await readFile(new URL('../runtime/package-lock.json', import.meta.url), 'utf8'));
  const manifest = JSON.parse(await readFile(new URL('../runtime/package.json', import.meta.url), 'utf8'));
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.equal(lock.packages['node_modules/@openai/codex-security'].version, manifest.dependencies['@openai/codex-security']);
  for (const [path, entry] of Object.entries(lock.packages) as [string, { integrity?: string }][]) {
    if (path) assert.match(entry.integrity ?? '', /^sha512-/, `${path} is missing recorded integrity`);
  }
});

test('cleanup preserves reports and rejects arbitrary or symlink roots', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'runtime-test-'));
  const base = await import('node:fs/promises').then((fs) => fs.realpath(temp));
  const owned = join(base, 'codex-security-runtime-abc');
  const reports = join(base, 'codex-security-reports-abc');
  try {
    await mkdir(owned); await mkdir(reports);
    await writeFile(join(owned, '.codex-security-action-owned'), 'codex-security-action-v1\n');
    await writeFile(join(reports, 'report.sarif'), '{}');
    const link = join(base, 'codex-security-runtime-link');
    await symlink(owned, link);
    await assert.rejects(cleanupRuntime(link, base), /Refusing/);
    await assert.rejects(cleanupRuntime(reports, base), /Refusing/);
    await cleanupRuntime(owned, base);
    assert.ok((await stat(join(reports, 'report.sarif'))).isFile());
    await cleanupRuntime(owned, base);
  } finally { await rm(base, { recursive: true, force: true }); }
});
