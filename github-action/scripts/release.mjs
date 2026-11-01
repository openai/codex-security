import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const packageName = '@openai/codex-security';
const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
const writeJson = (path, value) => writeFile(path, JSON.stringify(value, null, 2) + '\n');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function releaseIdentity(version, sourceCommit, cliIntegrity, actionCommit) {
  assert.match(version, /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/, 'Action releases require a stable CLI version');
  assert.match(sourceCommit, /^[a-f0-9]{40}$/, 'Action releases require the npm source commit');
  assert.match(cliIntegrity, /^sha512-\S+$/, 'Action releases require verified npm integrity');
  if (actionCommit !== undefined) assert.match(actionCommit, /^[a-f0-9]{40}$/, 'Action releases require their distribution commit');
  return { sourceCommit, ...(actionCommit === undefined ? {} : { actionCommit }), npmTag: `npm-v${version}`, actionTag: `action-v${version}`, cliIntegrity };
}

export async function updateReleaseManifests(actionRoot, version) {
  const cli = await readJson(resolve(actionRoot, '../sdk/typescript/package.json'));
  assert.equal(cli.name, packageName);
  assert.equal(cli.version, version, 'Action release must use the version of its CLI source');
  const manifestPath = resolve(actionRoot, 'package.json');
  const lockPath = resolve(actionRoot, 'package-lock.json');
  const runtimePath = resolve(actionRoot, 'runtime/package.json');
  const manifest = await readJson(manifestPath);
  const lock = await readJson(lockPath);
  const runtime = await readJson(runtimePath);
  manifest.version = version;
  lock.version = version;
  lock.packages[''].version = version;
  runtime.dependencies[packageName] = version;
  await writeJson(manifestPath, manifest);
  await writeJson(lockPath, lock);
  await writeJson(runtimePath, runtime);
}

export async function validateRelease(actionRoot, version, cliIntegrity) {
  const cli = await readJson(resolve(actionRoot, '../sdk/typescript/package.json'));
  const manifest = await readJson(resolve(actionRoot, 'package.json'));
  const lockBytes = await readFile(resolve(actionRoot, 'package-lock.json'));
  const lock = JSON.parse(lockBytes);
  const runtime = await readJson(resolve(actionRoot, 'runtime/package.json'));
  const runtimeLockBytes = await readFile(resolve(actionRoot, 'runtime/package-lock.json'));
  const runtimeLock = JSON.parse(runtimeLockBytes);
  assert.equal(cli.name, packageName);
  for (const actual of [cli.version, manifest.version, lock.version, lock.packages[''].version, runtime.dependencies[packageName], runtimeLock.packages[''].dependencies[packageName], runtimeLock.packages[`node_modules/${packageName}`].version]) {
    assert.equal(actual, version, 'Action and CLI release versions must agree');
  }
  assert.equal(runtimeLock.packages[`node_modules/${packageName}`].integrity, cliIntegrity, 'Action must install the verified npm release');
  return { actionLockSha256: sha256(lockBytes), runtimeLockSha256: sha256(runtimeLockBytes) };
}

export async function validateReleaseSource(actionRoot, sourceCommit) {
  for (const file of ['package.json', 'package-lock.json', 'runtime/package.json']) {
    const source = JSON.parse(execFileSync('git', ['show', `${sourceCommit}:github-action/${file}`], {
      cwd: actionRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    }));
    const distribution = await readJson(resolve(actionRoot, file));
    for (const manifest of [source, distribution]) {
      if (file === 'runtime/package.json') delete manifest.dependencies[packageName];
      else {
        delete manifest.version;
        if (file === 'package-lock.json') delete manifest.packages[''].version;
      }
    }
    assert.deepEqual(distribution, source, `${file} must preserve the reviewed release source apart from its release version`);
  }
}

export async function prepareRelease(actionRoot, version, sourceCommit, cliIntegrity) {
  releaseIdentity(version, sourceCommit, cliIntegrity);
  await updateReleaseManifests(actionRoot, version);
  execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--include=optional', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'], {
    cwd: resolve(actionRoot, 'runtime'), stdio: 'inherit',
  });
  await validateRelease(actionRoot, version, cliIntegrity);
}

export async function stageRelease(actionRoot, version, sourceCommit, cliIntegrity, runtimeLock) {
  releaseIdentity(version, sourceCommit, cliIntegrity);
  await updateReleaseManifests(actionRoot, version);
  await copyFile(runtimeLock, resolve(actionRoot, 'runtime/package-lock.json'));
  await validateRelease(actionRoot, version, cliIntegrity);
}

export async function writeReleaseMetadata(actionRoot, version, sourceCommit, cliIntegrity, actionCommit) {
  const identity = releaseIdentity(version, sourceCommit, cliIntegrity, actionCommit);
  await validateReleaseSource(actionRoot, sourceCommit);
  const hashes = await validateRelease(actionRoot, version, cliIntegrity);
  const manifestPath = resolve(actionRoot, 'build/release-manifest.json');
  const manifest = await readJson(manifestPath);
  assert.equal(manifest.actionVersion, version, 'Rebuild the Action before publishing release metadata');
  assert.equal(manifest.cliVersion, version, 'Rebuild the Action before publishing release metadata');
  for (const [key, value] of Object.entries(hashes)) {
    assert.equal(manifest[key], value, 'Rebuild the Action after updating its locks');
  }
  for (const file of ['dist/index.cjs', 'dist/post.cjs']) {
    const bytes = await readFile(resolve(actionRoot, file));
    assert.equal(manifest.files[file].sha256, sha256(bytes), `${file} differs from the built release metadata`);
    assert.equal(manifest.files[file].bytes, bytes.length, `${file} length differs from the built release metadata`);
  }
  await writeJson(manifestPath, { ...manifest, status: 'released', ...identity });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, version, sourceCommit, cliIntegrity, ...rest] = process.argv.slice(2);
  if (command === 'prepare' && rest.length === 1) {
    await prepareRelease(resolve(rest[0]), version, sourceCommit, cliIntegrity);
  } else if (command === 'stage' && rest.length === 2) {
    await stageRelease(resolve(rest[1]), version, sourceCommit, cliIntegrity, resolve(rest[0]));
  } else if (command === 'verify' && rest.length === 1) {
    releaseIdentity(version, sourceCommit, cliIntegrity);
    await validateReleaseSource(resolve(rest[0]), sourceCommit);
    await validateRelease(resolve(rest[0]), version, cliIntegrity);
  } else if (command === 'metadata' && rest.length === 2) {
    await writeReleaseMetadata(resolve(rest[1]), version, sourceCommit, cliIntegrity, rest[0]);
  } else {
    throw new Error('Usage: release.mjs prepare VERSION SOURCE_SHA CLI_INTEGRITY ACTION_ROOT | stage VERSION SOURCE_SHA CLI_INTEGRITY RUNTIME_LOCK ACTION_ROOT | verify VERSION SOURCE_SHA CLI_INTEGRITY ACTION_ROOT | metadata VERSION SOURCE_SHA CLI_INTEGRITY ACTION_SHA ACTION_ROOT');
  }
}
