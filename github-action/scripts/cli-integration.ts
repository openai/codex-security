// Exercise the published, locked CLI and exporter without credentials or model calls.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseInputs, scanArguments } from '../src/inputs.js';
import { analyzeResults } from '../src/results.js';
import { resolveTool } from '../src/runtime.js';
import { exportSarifArgs } from '../src/sarif.js';
import runtimeManifest from '../runtime/package.json' with { type: 'json' };

const cliPackage = resolve(import.meta.dirname, '../runtime/node_modules/@openai/codex-security');
const installed = JSON.parse(await readFile(join(cliPackage, 'package.json'), 'utf8'));
assert.equal(installed.version, runtimeManifest.dependencies['@openai/codex-security']);
const cli = join(cliPackage, 'bin/codex-security.mjs');
const root = await mkdtemp(join(await realpath(tmpdir()), 'codex-action-cli-test-'));
try {
  const repository = join(root, 'repository');
  const home = join(root, 'home');
  await mkdir(repository);
  await mkdir(home);
  // Pass only executable lookup and isolated homes. Never inherit API keys or user configuration.
  const env = { PATH: process.env.PATH, HOME: home, CI: 'true', NO_COLOR: '1',
    CODEX_HOME: join(home, '.codex'), CODEX_SECURITY_STATE_DIR: join(root, 'state'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  const git = (...args: string[]) => execFileSync('git', [
    '-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid',
    '-c', 'commit.gpgsign=false', ...args,
  ], { cwd: repository, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-b', 'main');
  await writeFile(join(repository, 'example.ts'), 'export const example = 1;\n');
  git('add', 'example.ts');
  git('commit', '-m', 'Synthetic fixture');

  const run = (args: string[], expectedExit: number) => {
    const result = spawnSync(process.execPath, [cli, ...args], {
      cwd: repository, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(result.status, expectedExit, result.stderr);
    return result.stdout;
  };
  for (const threshold of [false, true]) {
    const resultsDirectory = join(root, threshold ? 'threshold-results' : 'report-results');
    const exitCode = threshold ? 1 : 0;
    const stdout = run(['scan', repository, '--mock', '--format', 'json', '--output-dir', resultsDirectory,
      ...(threshold ? ['--fail-on-severity', 'high'] : [])], exitCode);
    const cliResult = JSON.parse(stdout);
    assert.equal(cliResult.turn.mock, true, 'The integration scan must remain synthetic');
    assert.ok(cliResult.findings.findings.length > 0);
    // Use the same strict exporter invocation as the Action, including source-root handling.
    run(exportSarifArgs(resultsDirectory, repository, join(resultsDirectory, 'exports/results.sarif')), 0);
    const result = await analyzeResults({ stdout, resultsDirectory, exitCode, publishable: true, sarifExported: true });
    assert.equal(result.scanStatus, 'completed');
    assert.equal(result.policyStatus, threshold ? 'failed' : 'passed');
    assert.equal(result.reportStatus, 'ready');
    assert.equal(result.sarifUploadReady, true);
    assert.equal(result.findings.length, cliResult.findings.findings.length);
    for (const [level, count] of Object.entries(result.counts)) {
      assert.equal(count, cliResult.findings.findings.filter((finding: any) => finding.severity.level === level).length);
    }
    assert.deepEqual(result.findings.map(finding => finding.title),
      cliResult.findings.findings.map((finding: any) => finding.title));
    assert.equal(result.estimatedCost, cliResult.cost?.estimatedUsd);
  }

  // Deep Scan cannot use --mock; validate the Action's actual arguments without model calls.
  const deepInputs: Record<string, string> = {mode: 'deep', 'max-time-hours': '0.25', paths: 'example.ts', 'dry-run': 'true'};
  const deepArguments = scanArguments(parseInputs(name => deepInputs[name] ?? '', repository),
    {repository}, join(root, 'deep-results'), await resolveTool('python3'));
  const deepPreflight = JSON.parse(run(deepArguments, 0));
  assert.equal(deepPreflight.dryRun, true);
  assert.equal(deepPreflight.mode, 'deep');
  assert.equal(deepPreflight.maxTimeHours, 0.25);
  assert.deepEqual(deepPreflight.target.paths, ['example.ts']);

  // The CLI owns scan validation: an output directory inside the source checkout is forbidden.
  const resultsDirectory = join(repository, 'results');
  const stdout = run(['scan', repository, '--mock', '--format', 'json', '--output-dir', resultsDirectory], 2);
  const cliError = JSON.parse(stdout);
  assert.equal(cliError.status, 'failed');
  const result = await analyzeResults({ stdout, resultsDirectory, exitCode: 2, publishable: true });
  assert.equal(result.scanStatus, 'failed');
  assert.equal(result.policyStatus, 'not-evaluated');
  assert.equal(result.sarifUploadReady, false);
  assert.ok(result.errors.some(error => error.includes(cliError.message)));
  console.log(`Pinned CLI ${installed.version}: real JSON results, severity exits, SARIF export, Deep Scan preflight, and failures passed without model calls.`);
} finally {
  await rm(root, { recursive: true, force: true });
}
