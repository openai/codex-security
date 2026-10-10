import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { stageRelease, updateReleaseManifests, validateRelease, validateReleaseSource, writeReleaseMetadata } from '../scripts/release.mjs';

const version = '0.3.0';
const actionCommit = 'b'.repeat(40);
const cliIntegrity = 'sha512-' + Buffer.from('synthetic published CLI').toString('base64');
const packageName = '@openai/codex-security';
const writeJson = (path, data) => writeFile(path, JSON.stringify(data, null, 2) + '\n');
const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
const digest = async path => createHash('sha256').update(await readFile(path)).digest('hex');

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'action-release-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const actionRoot = join(root, 'github-action');
  await mkdir(join(actionRoot, 'runtime'), { recursive: true });
  await mkdir(join(actionRoot, 'build'));
  await mkdir(join(actionRoot, 'dist'));
  await writeFile(join(actionRoot, 'dist/index.cjs'), 'console.log("synthetic Action");\n');
  await writeFile(join(actionRoot, 'dist/post.cjs'), 'console.log("synthetic cleanup");\n');
  await mkdir(join(root, 'sdk/typescript'), { recursive: true });
  await writeJson(join(root, 'sdk/typescript/package.json'), { name: packageName, version });
  await writeJson(join(actionRoot, 'package.json'), { name: 'codex-security-action', version: '0.2.0', private: true, dependencies: { '@actions/core': '3.0.1' } });
  await writeJson(join(actionRoot, 'package-lock.json'), { name: 'codex-security-action', version: '0.2.0', lockfileVersion: 3, packages: { '': { name: 'codex-security-action', version: '0.2.0' }, 'node_modules/@actions/core': { version: '3.0.1', integrity: 'sha512-synthetic-action' } } });
  await writeJson(join(actionRoot, 'runtime/package.json'), { private: true, dependencies: { [packageName]: '0.2.0' } });
  await writeJson(join(actionRoot, 'runtime/package-lock.json'), { lockfileVersion: 3, packages: { '': { dependencies: { [packageName]: version } }, [`node_modules/${packageName}`]: { version, integrity: cliIntegrity } } });
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-b', 'main');
  git('add', '.');
  git('-c', 'user.name=Synthetic Test', '-c', 'user.email=synthetic@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'Synthetic release source');
  return { actionRoot, sourceCommit: git('rev-parse', 'HEAD').trim() };
}

async function buildMetadata(actionRoot) {
  const files = {};
  for (const file of ['dist/index.cjs', 'dist/post.cjs']) {
    const bytes = await readFile(join(actionRoot, file));
    files[file] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  }
  await writeJson(join(actionRoot, 'build/release-manifest.json'), {
    actionVersion: version, cliVersion: version, status: 'unreleased',
    actionLockSha256: await digest(join(actionRoot, 'package-lock.json')),
    runtimeLockSha256: await digest(join(actionRoot, 'runtime/package-lock.json')),
    sourceSha256: 'synthetic-source-hash', files,
  });
}

test('release preparation aligns manifests without changing locked Action dependencies', async t => {
  const { actionRoot } = await fixture(t);
  const before = await readJson(join(actionRoot, 'package-lock.json'));
  await updateReleaseManifests(actionRoot, version);
  assert.equal((await readJson(join(actionRoot, 'package.json'))).version, version);
  assert.equal((await readJson(join(actionRoot, 'runtime/package.json'))).dependencies[packageName], version);
  const after = await readJson(join(actionRoot, 'package-lock.json'));
  assert.equal(after.version, version);
  assert.equal(after.packages[''].version, version);
  assert.deepEqual(after.packages['node_modules/@actions/core'], before.packages['node_modules/@actions/core']);
  await validateRelease(actionRoot, version, cliIntegrity);
  await assert.rejects(updateReleaseManifests(actionRoot, '0.3.1'), /version of its CLI source/);
  assert.equal((await readJson(join(actionRoot, 'package.json'))).version, version);
});

test('publisher stages the tested runtime lock byte-for-byte without npm on PATH', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  const runtimeLock = join(actionRoot, '../tested-runtime-lock.json');
  const tested = await readJson(join(actionRoot, 'runtime/package-lock.json'));
  const testedBytes = JSON.stringify(tested);
  await writeFile(runtimeLock, testedBytes);
  await writeJson(join(actionRoot, 'runtime/package-lock.json'), {});
  execFileSync(process.execPath, [
    fileURLToPath(new URL('../scripts/release.mjs', import.meta.url)),
    'stage', version, sourceCommit, cliIntegrity, runtimeLock, actionRoot,
  ], { env: { ...process.env, PATH: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(await readFile(join(actionRoot, 'runtime/package-lock.json'), 'utf8'), testedBytes);
  await validateRelease(actionRoot, version, cliIntegrity);
  await validateReleaseSource(actionRoot, sourceCommit);
});

test('publisher rejects a tested lock for a different CLI release or npm archive', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  const runtimeLock = join(actionRoot, '../tested-runtime-lock.json');
  const tested = await readJson(join(actionRoot, 'runtime/package-lock.json'));
  tested.packages[`node_modules/${packageName}`].version = '0.2.0';
  await writeJson(runtimeLock, tested);
  await assert.rejects(stageRelease(actionRoot, version, sourceCommit, cliIntegrity, runtimeLock), /versions must agree/);
  tested.packages[`node_modules/${packageName}`].version = version;
  tested.packages[`node_modules/${packageName}`].integrity = 'sha512-other-tarball';
  await writeJson(runtimeLock, tested);
  await assert.rejects(stageRelease(actionRoot, version, sourceCommit, cliIntegrity, runtimeLock), /verified npm release/);
});

test('release metadata ties built locks to the verified CLI and immutable distribution commit', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  await updateReleaseManifests(actionRoot, version);
  await buildMetadata(actionRoot);
  await writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit);
  const metadata = await readJson(join(actionRoot, 'build/release-manifest.json'));
  assert.equal(metadata.status, 'released');
  assert.equal(metadata.actionVersion, version);
  assert.equal(metadata.cliVersion, version);
  assert.equal(metadata.sourceCommit, sourceCommit);
  assert.equal(metadata.actionCommit, actionCommit);
  assert.equal(metadata.cliIntegrity, cliIntegrity);
  assert.equal(metadata.npmTag, 'npm-v0.3.0');
  assert.equal(metadata.actionTag, 'action-v0.3.0');
  assert.equal(metadata.files['dist/index.cjs'].sha256, await digest(join(actionRoot, 'dist/index.cjs')));
  const first = await readFile(join(actionRoot, 'build/release-manifest.json'), 'utf8');
  await writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit);
  assert.equal(await readFile(join(actionRoot, 'build/release-manifest.json'), 'utf8'), first);
});

test('release metadata rejects a bundle changed or removed after the build', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  await updateReleaseManifests(actionRoot, version);
  await buildMetadata(actionRoot);
  for (const file of ['dist/index.cjs', 'dist/post.cjs']) {
    const path = join(actionRoot, file);
    const original = await readFile(path);
    const changed = Buffer.from(original);
    changed[0] ^= 1;
    await writeFile(path, changed);
    await assert.rejects(writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit), /differs from the built release metadata/);
    await rm(path);
    await assert.rejects(writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit), { code: 'ENOENT' });
    await writeFile(path, original);
  }
  const metadataPath = join(actionRoot, 'build/release-manifest.json');
  const metadata = await readJson(metadataPath);
  assert.equal(metadata.status, 'unreleased');
  metadata.files['dist/index.cjs'].bytes += 1;
  await writeJson(metadataPath, metadata);
  await assert.rejects(writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit), /length differs/);
});

test('release refuses a stale CLI lock or metadata generated before the lock changed', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  await updateReleaseManifests(actionRoot, version);
  await buildMetadata(actionRoot);
  await assert.rejects(validateRelease(actionRoot, version, 'sha512-other-tarball'), /verified npm release/);
  const runtimeLockPath = join(actionRoot, 'runtime/package-lock.json');
  const lock = await readJson(runtimeLockPath);
  lock.packages[`node_modules/${packageName}`].version = '0.2.0';
  await writeJson(runtimeLockPath, lock);
  await assert.rejects(validateRelease(actionRoot, version, cliIntegrity), /versions must agree/);
  lock.packages[`node_modules/${packageName}`].version = version;
  lock.packages['node_modules/example-dependency'] = { version: '1.0.0', integrity: 'sha512-synthetic-dependency' };
  await writeJson(runtimeLockPath, lock);
  await assert.rejects(writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit), /after updating its locks/);
  assert.equal((await readJson(join(actionRoot, 'build/release-manifest.json'))).status, 'unreleased');
});

test('distribution manifests preserve the reviewed source beyond owned version fields', async t => {
  const { actionRoot, sourceCommit } = await fixture(t);
  await updateReleaseManifests(actionRoot, version);
  await validateReleaseSource(actionRoot, sourceCommit);
  for (const [file, change] of [
    ['package.json', value => { value.dependencies['@actions/core'] = '3.0.2'; }],
    ['package-lock.json', value => { value.packages['node_modules/@actions/core'].integrity = 'sha512-changed-action'; }],
    ['runtime/package.json', value => { value.dependencies['example-package'] = '1.0.0'; }],
  ]) {
    const path = join(actionRoot, file);
    const original = await readFile(path, 'utf8');
    const value = JSON.parse(original);
    change(value);
    await writeJson(path, value);
    await assert.rejects(validateReleaseSource(actionRoot, sourceCommit), /must preserve the reviewed release source/);
    await writeFile(path, original);
  }
});
