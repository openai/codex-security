import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const post = fileURLToPath(new URL('../dist/post.cjs', import.meta.url));

test('packaged post action removes only its owned runtime and is safe to repeat', async (t) => {
  const tempRoot = await realpath(await mkdtemp(join(tmpdir(), 'action-post-')));
  t.after(() => rm(tempRoot, { recursive: true, force: true }));
  const root = join(tempRoot, 'codex-security-runtime-test');
  await mkdir(root);
  await writeFile(join(root, '.codex-security-action-owned'), 'codex-security-action-v1\n');
  await writeFile(join(root, 'temporary-data'), 'synthetic runtime data');
  const reports = join(tempRoot, 'codex-security-reports-test');
  await mkdir(reports);
  await writeFile(join(reports, 'report.json'), '{}');
  const env = { ...process.env, 'STATE_runtime-root': root, 'STATE_runtime-temp-root': tempRoot };

  for (let attempt = 0; attempt < 2; attempt++) {
    const result = spawnSync(process.execPath, [post], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    await assert.rejects(stat(root), { code: 'ENOENT' });
    assert.equal(await readFile(join(reports, 'report.json'), 'utf8'), '{}');
  }
});

test('packaged post action skips absent state and reports refused cleanup', async (t) => {
  const tempRoot = await realpath(await mkdtemp(join(tmpdir(), 'action-post-')));
  t.after(() => rm(tempRoot, { recursive: true, force: true }));
  const root = join(tempRoot, 'codex-security-runtime-unowned');
  await mkdir(root);
  for (const state of [
    { 'STATE_runtime-root': '', 'STATE_runtime-temp-root': tempRoot },
    { 'STATE_runtime-root': root, 'STATE_runtime-temp-root': '' },
  ]) {
    const result = spawnSync(process.execPath, [post], { env: { ...process.env, ...state }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
  }
  const result = spawnSync(process.execPath, [post], {
    env: { ...process.env, 'STATE_runtime-root': root, 'STATE_runtime-temp-root': tempRoot },
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '::error::Codex Security temporary runtime cleanup failed.\n');
  assert.ok((await stat(root)).isDirectory());
});
