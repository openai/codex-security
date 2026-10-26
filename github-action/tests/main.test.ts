import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import * as core from '@actions/core';
import { DefaultArtifactClient } from '@actions/artifact';
import { BlobClient } from '@azure/storage-blob';
import { runAction } from '../src/main.js';
import { INPUT_NAMES } from '../src/inputs.js';
import { gitEnvironment } from '../src/targets.js';
import { runtimeEnvironment, type Runtime } from '../src/runtime.js';
import type { ProcessResult } from '../src/process.js';
import { copyCompletedScan } from './fixtures.js';

type Scenario = 'schedule' | 'pr' | 'policy-pr';
const inputKey = (name: string): string => `INPUT_${name.toUpperCase()}`;

function assertAttribution(args: readonly string[], provider: string): void {
  assert.deepEqual(args.flatMap((arg, index) => arg === '--codex' ? [args[index + 1]] : []), [
    'analytics.enabled=false',
    'responses_api_metadata.codex_security_integration="github_action"',
    `responses_api_metadata.codex_security_provider="${provider}"`,
  ]);
}

function outputValues(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const marker = line.indexOf('<<');
    if (marker < 0) continue;
    const name = line.slice(0, marker);
    const delimiter = line.slice(marker + 2);
    const value: string[] = [];
    while (++index < lines.length && lines[index] !== delimiter) value.push(lines[index]);
    values[name] = value.join('\n');
  }
  return values;
}

async function harness(t: TestContext, scenario: Scenario = 'schedule', serverUrl = 'https://github.com') {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-main-test-')));
  const repository = join(root, 'repo');
  await mkdir(repository);
  const git = (...args: string[]): string => execFileSync('/usr/bin/git', [
    '-c', 'user.name=Offline Test', '-c', 'user.email=offline@example.invalid', '-c', 'core.hooksPath=/dev/null', ...args,
  ], { cwd: repository, env: gitEnvironment(), encoding: 'utf8' }).trim();
  git('init', '-q', '-b', 'main');
  git('remote', 'add', 'origin', `${serverUrl}/example/repo.git`);
  await writeFile(join(repository, 'app.txt'), 'synthetic source\n');
  git('add', '.'); git('commit', '-qm', 'base');
  const base = git('rev-parse', 'HEAD');
  let sha = base;
  if (scenario !== 'schedule') {
    await writeFile(join(repository, scenario === 'policy-pr' ? 'SECURITY.md' : 'app.txt'), 'synthetic change\n');
    git('add', '.'); git('commit', '-qm', 'PR change');
    sha = git('rev-parse', 'HEAD');
  }
  const previousEnv = { ...process.env };
  const previousExitCode = process.exitCode;
  t.after(async () => {
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    process.exitCode = previousExitCode;
    await rm(root, { recursive: true, force: true });
  });
  for (const name of INPUT_NAMES) delete process.env[inputKey(name)];
  const eventPath = join(root, 'event.json');
  const outputPath = join(root, 'outputs');
  const statePath = join(root, 'state');
  const payload = scenario === 'schedule' ? {} : { number: 4, pull_request: { number: 4,
    head: { sha, repo: { full_name: 'example/repo' } }, base: { sha: base, repo: { full_name: 'example/repo' } } } };
  await writeFile(eventPath, JSON.stringify(payload));
  await writeFile(outputPath, ''); await writeFile(statePath, '');
  Object.assign(process.env, {
    GITHUB_EVENT_PATH: eventPath, GITHUB_EVENT_NAME: scenario === 'schedule' ? 'schedule' : 'pull_request',
    GITHUB_REPOSITORY: 'example/repo', GITHUB_WORKSPACE: repository, GITHUB_SHA: sha,
    GITHUB_REF: scenario === 'schedule' ? 'refs/heads/main' : 'refs/pull/4/merge',
    GITHUB_ACTOR: 'trusted-maintainer', GITHUB_SERVER_URL: serverUrl,
    GITHUB_OUTPUT: outputPath, GITHUB_STATE: statePath, RUNNER_TEMP: root,
    OPENAI_API_KEY: 'synthetic-offline-test-key', INPUT_SUMMARY: 'true', INPUT_ANNOTATIONS: 'false',
    INPUT_SCOPE: scenario === 'schedule' ? 'repository' : 'diff',
  });
  delete process.env.CODEX_API_KEY;
  const runtime: Runtime = {
    root: join(root, 'runtime'), home: join(root, 'runtime/home'), codexHome: join(root, 'runtime/codex'),
    stateDirectory: join(root, 'runtime/state'), resultsDirectory: join(root, 'results'),
    nodePath: '/never-executed/node', cliPath: '/never-executed/cli.js',
    env: (credentials) => runtimeEnvironment(runtime, credentials),
  };
  let setups = 0;
  let processes = 0;
  let cleanups = 0;
  const configuration: { exitCode?: number; missingSarif?: boolean; mutateCheckout?: boolean; cleanupFails?: boolean; cliFailure?: boolean; scanProcess?: Partial<ProcessResult>; scanResult?: (value: any) => void; missingReport?: string; prepare?: () => void | Promise<void> } = {};
  let scanOutput = '';
  let summary = '';
  t.mock.method(core.summary, 'write', async () => {
    summary = core.summary.stringify();
    core.summary.emptyBuffer();
    return core.summary;
  });
  t.after(() => { core.summary.emptyBuffer(); });
  let capturedArgs: readonly string[] = [];
  let capturedEnvironment: NodeJS.ProcessEnv = {};
  async function reports(): Promise<void> {
    await copyCompletedScan(runtime.resultsDirectory);
    const manifestPath = join(runtime.resultsDirectory, 'scan-manifest.json');
    const coveragePath = join(runtime.resultsDirectory, 'coverage.json');
    const sarifPath = join(runtime.resultsDirectory, 'exports/results.sarif');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const coverage = JSON.parse(await readFile(coveragePath, 'utf8'));
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
    const scanSha = git('rev-parse', 'HEAD');
    manifest.scan.target.revision = scanSha;
    if (scenario !== 'schedule') {
      Object.assign(manifest.scan.target, { kind: 'git_diff', baseRevision: base, headRevision: scanSha });
      coverage.mode = 'branch_diff';
      sarif.runs[0].properties.codexSecurityTargetKind = 'git_diff';
    }
    if (process.env.INPUT_MODE === 'deep') coverage.mode = 'deep_repository';
    sarif.runs[0].versionControlProvenance[0].revisionId = scanSha;
    sarif.runs[0].versionControlProvenance[0].repositoryUri = `${serverUrl}/example/repo`;
    await writeFile(sarifPath, JSON.stringify(sarif));
    if (configuration.missingSarif) await rm(sarifPath);
    const value = {manifest, coverage, findings: JSON.parse(await readFile(join(runtime.resultsDirectory, 'findings.json'), 'utf8')),
      scanDir: runtime.resultsDirectory, sarifPath: configuration.missingSarif ? null : sarifPath, cost: {estimatedUsd: 0.125}};
    configuration.scanResult?.(value);
    await writeFile(coveragePath, JSON.stringify(coverage));
    await writeFile(manifestPath, JSON.stringify(manifest));
    scanOutput = JSON.stringify(value);
    if (configuration.missingReport) await rm(join(runtime.resultsDirectory, configuration.missingReport));
  }
  return {
    repository, sha, git,
    setInput: (name: string, value: string) => { process.env[inputKey(name)] = value; },
    configure: (options: typeof configuration) => Object.assign(configuration, options),
    run: async () => {
      const logs: string[] = [];
      const originalWrite = process.stdout.write;
      process.stdout.write = ((chunk: string | Uint8Array, encodingOrCallback?: unknown, callback?: unknown): boolean => {
        logs.push(String(chunk));
        if (typeof encodingOrCallback === 'function') encodingOrCallback();
        else if (typeof callback === 'function') callback();
        return true;
      }) as typeof process.stdout.write;
      let exitCode: typeof process.exitCode;
      try {
        process.exitCode = 0;
        await runAction(root, {
          setupRuntime: async () => { setups++; await configuration.prepare?.(); await reports(); return runtime; },
          cleanupRuntime: async () => { cleanups++; if (configuration.cleanupFails) throw new Error('Synthetic cleanup failure'); },
          runProcess: async (_executable, args, options): Promise<ProcessResult> => {
            processes++; capturedArgs = args; capturedEnvironment = options.env;
            options.log?.('[codex-security] Synthetic live CLI progress.');
            if (configuration.mutateCheckout) await writeFile(join(repository, 'app.txt'), 'modified while scanning\n');
            return { exitCode: configuration.exitCode ?? (process.env['INPUT_FAIL-ON-SEVERITY'] === 'high' ? 1 : 0), signal: null,
              stdout: configuration.cliFailure ? JSON.stringify({status: 'failed', code: 'SCAN_FAILED', message: 'Synthetic API authentication failure.'}) : scanOutput,
              stderr: '', interrupted: false, timedOut: false, ...configuration.scanProcess };
          },
        });
        exitCode = process.exitCode;
      } finally { process.stdout.write = originalWrite; process.exitCode = previousExitCode; }
      return { exitCode, setups, processes, cleanups, summary, args: capturedArgs, environment: capturedEnvironment,
        outputs: outputValues(await readFile(outputPath, 'utf8')), logs: logs.join('') };
    },
  };
}

test('PR severity failure retains SARIF outputs despite unrelated scope notes', async (t) => {
  const app = await harness(t, 'pr'); app.setInput('fail-on-severity', 'high'); app.configure({ exitCode: 1, scanResult: value => {
    value.coverage.deferred = [{reason: 'Dependency validation remains unavailable.'}];
  }});
  app.setInput('model', 'gpt-5.6-luna'); app.setInput('effort', 'medium');
  app.setInput('annotations', ''); // Use the default, as in the README's PR workflow.
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['policy-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'true'); assert.equal(result.outputs['analysis-ref'], 'refs/pull/4/head');
  assert.equal(result.outputs['scanned-sha'], app.sha); assert.equal(result.outputs['high-count'], '1');
  assert.equal(result.outputs['estimated-cost'], '0.125'); assert.ok(result.outputs['sarif-path']);
  assert.ok(result.args.includes('--model=gpt-5.6-luna'));
  assert.ok(result.args.includes('--effort=medium'));
  assert.ok(!result.args.includes('--max-cost'));
  assert.match(result.logs, /::error::Scan completed\. Findings meet the configured failure threshold\./);
  assert.match(result.summary, /^## Codex Security\n\n\*\*Scan completed\. Findings meet the configured failure threshold\.\*\*/);
  const annotation = /^::warning ([^\r\n]+)::([^\r\n]+)$/m.exec(result.logs);
  assert.ok(annotation, 'PR findings must emit a GitHub warning annotation even when the severity policy fails');
  const properties = Object.fromEntries(annotation[1].split(',').map(property => property.split('=')));
  assert.equal(properties.file, 'src/extract.py');
  assert.equal(properties.line, '41'); assert.equal(properties.endLine, '44');
  assert.match(properties.title, /^HIGH%3A Unsafe archive extraction/);
  assert.match(annotation[2], /filesystem write without containment validation/);
});

test('scheduled complete report-only scan succeeds', async (t) => {
  const app = await harness(t);
  process.env.INPUT_FOO = 'unrelated workflow value';
  app.setInput('effort', 'medium');
  app.configure({scanResult: value => {
    value.turn = {usage: {input_tokens: 1200, output_tokens: 50}};
  }});
  const result = await app.run();
  assertAttribution(result.args, 'openai');
  assert.ok(result.args.includes('--effort=medium'));
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'passed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.equal(result.outputs['report-status'], 'ready'); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['analysis-ref'], 'refs/heads/main');
  assert.ok(result.args.includes('--verbose'));
  assert.match(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /CLI preparation completed in \d+m \d+s/);
  assert.match(result.logs, /Target commit: [a-f0-9]{40}/);
  assert.match(result.logs, /Security scan exited after \d+m \d+s; exit code: 0/);
  assert.match(result.logs, /Scan: completed; findings policy: passed; report: ready/);
  assert.match(result.logs, /Estimated cost: \$0.1250/);
  assert.equal(result.outputs['estimated-cost'], '0.125');
  assert.ok(result.summary.includes('1,200 input (0 cached) · 50 output'));
  assert.match(result.logs, /Scan completed\. Findings are reported without failing the job\./);
  assert.match(result.summary, /\*\*Scan completed\. Findings are reported without failing the job\.\*\*/);
});

for (const [scenario, mode] of [['schedule', 'standard'], ['pr', 'standard'], ['schedule', 'deep']] as const) {
  test(`enterprise ${scenario} ${mode} scans preserve reports and upload identity`, async t => {
    const serverUrl = 'https://example-enterprise.ghe.com';
    const app = await harness(t, scenario, serverUrl);
    app.setInput('mode', mode); app.setInput('upload-artifacts', 'true'); app.setInput('annotations', 'true');
    let uploadedFiles: string[] = [];
    t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async (_name: string, files: string[]) => {
      assert.equal(process.env.GITHUB_SERVER_URL, serverUrl);
      uploadedFiles = files.map(file => basename(file));
      for (const file of files) assert.ok((await readFile(file)).length);
      return {id:1, size:1};
    });
    const result = await app.run();
    assert.equal(result.exitCode, 0); assert.equal(result.processes, 1); assert.equal(result.cleanups, 1);
    assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['report-status'], 'ready');
    assert.equal(result.outputs['policy-status'], 'passed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
    assert.equal(result.outputs['scanned-sha'], app.sha);
    assert.equal(result.outputs['analysis-ref'], scenario === 'pr' ? 'refs/pull/4/head' : 'refs/heads/main');
    assert.deepEqual(uploadedFiles.sort(), ['coverage.json', 'findings.json', 'results.sarif', 'scan-manifest.json']);
    const sarif = JSON.parse(await readFile(result.outputs['sarif-path'], 'utf8'));
    assert.equal(sarif.runs[0].versionControlProvenance[0].repositoryUri, `${serverUrl}/example/repo`);
    assert.match(result.logs, /^::warning .*file=src\/extract\.py/m);
    assert.match(result.summary, /Scan completed/);
  });
}

test('Deep scans forward their budget and publish completed reports with cleanup', async (t) => {
  const app = await harness(t);
  app.setInput('mode', 'deep'); app.setInput('max-time-hours', '1.5');
  const result = await app.run();
  assertAttribution(result.args, 'openai');
  assert.equal(result.args[result.args.indexOf('--mode') + 1], 'deep');
  assert.equal(result.args[result.args.indexOf('--max-time-hours') + 1], '1.5');
  assert.equal(result.exitCode, 0); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'passed');
  assert.equal(result.outputs['report-status'], 'ready');
  assert.equal(result.outputs['high-count'], '1');
  assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.match(result.logs, /mode: deep/);
  assert.match(result.summary, /\*\*Mode:\*\* deep/);
});

test('findings below the threshold pass with an explicit outcome', async (t) => {
  const app = await harness(t); app.setInput('fail-on-severity', 'critical');
  const result = await app.run();
  assert.equal(result.exitCode, 0);
  assert.equal(result.outputs['high-count'], '1');
  assert.match(result.logs, /Scan completed\. No findings meet the failure threshold\./);
  assert.match(result.summary, /\*\*Scan completed\. No findings meet the failure threshold\.\*\*/);
});

test('same-repository Dependabot PR scans with a supplied key', async (t) => {
  const app = await harness(t, 'pr'); process.env.GITHUB_ACTOR = 'dependabot[bot]';
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.setups, 1); assert.equal(result.processes, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['scanned-sha'], app.sha);
  assert.equal(result.environment.OPENAI_API_KEY, 'synthetic-offline-test-key');
  assert.equal(result.outputs['sarif-upload-ready'], 'true');
});

for (const mode of ['standard', 'deep']) {
  test(`Bedrock ${mode} scans use captured AWS credentials without an OpenAI key`, async t => {
    const app = await harness(t);
    app.setInput('provider', 'amazon-bedrock'); app.setInput('model', 'openai.synthetic-model'); app.setInput('mode', mode);
    delete process.env.OPENAI_API_KEY;
    Object.assign(process.env, {AWS_ACCESS_KEY_ID:'synthetic-access-key', AWS_SECRET_ACCESS_KEY:'synthetic-secret-key',
      AWS_SESSION_TOKEN:'synthetic-session-token', AWS_REGION:'us-east-2', GITHUB_TOKEN:'must-not-reach-scan'});
    app.configure({prepare: () => { process.env.AWS_SESSION_TOKEN = 'changed-during-setup'; }});
    const result = await app.run();
    assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
    assert.equal(result.outputs['sarif-upload-ready'], 'true');
    assert.equal(result.args[result.args.indexOf('--provider') + 1], 'amazon-bedrock');
    assertAttribution(result.args, 'amazon-bedrock');
    assert.equal(result.args[result.args.indexOf('--auth') + 1], 'auto');
    assert.equal(result.environment.AWS_ACCESS_KEY_ID, 'synthetic-access-key');
    assert.equal(result.environment.AWS_SECRET_ACCESS_KEY, 'synthetic-secret-key');
    assert.equal(result.environment.AWS_SESSION_TOKEN, 'synthetic-session-token');
    assert.equal(result.environment.AWS_REGION, 'us-east-2');
    assert.equal(result.environment.OPENAI_API_KEY, undefined); assert.equal(result.environment.GITHUB_TOKEN, undefined);
  });
}

for (const [provider, key] of [['openrouter', 'OPENROUTER_API_KEY'], ['fireworks', 'FIREWORKS_API_KEY']]) {
  for (const mode of ['standard', 'deep']) test(`${provider} ${mode} scans use only the captured provider key`, async t => {
    const app = await harness(t);
    app.setInput('provider', provider); app.setInput('model', 'synthetic/model'); app.setInput('mode', mode);
    Object.assign(process.env, {OPENROUTER_API_KEY:'synthetic-openrouter', FIREWORKS_API_KEY:'synthetic-fireworks',
      AWS_SESSION_TOKEN:'unrelated-aws', GITHUB_TOKEN:'unrelated-github'});
    const expectedKey = process.env[key];
    app.configure({prepare: () => { process.env[key] = 'changed-during-setup'; }});
    const result = await app.run();
    assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
    assert.equal(result.args[result.args.indexOf('--provider') + 1], provider);
    assertAttribution(result.args, provider);
    assert.equal(result.args[result.args.indexOf('--auth') + 1], 'api-key');
    assert.equal(result.environment[key], expectedKey);
    for (const other of ['OPENAI_API_KEY', 'CODEX_API_KEY', 'OPENROUTER_API_KEY', 'FIREWORKS_API_KEY', 'AWS_SESSION_TOKEN', 'GITHUB_TOKEN'])
      if (other !== key) assert.equal(result.environment[other], undefined);
  });
  test(`${provider} requires its own key and keeps dry-run credential-free`, async t => {
    const app = await harness(t);
    app.setInput('provider', provider); app.setInput('model', 'synthetic/model');
    delete process.env[key];
    const missing = await app.run();
    assert.equal(missing.exitCode, 1); assert.equal(missing.setups, 0);
    assert.ok(missing.summary.includes(key));
    process.env[key] = 'synthetic-provider-key';
    app.setInput('dry-run', 'true');
    const dry = await app.run();
    assert.equal(dry.exitCode, 0); assert.equal(dry.outputs['skip-reason'], 'dry-run');
    assert.equal(dry.environment[key], undefined); assert.equal(dry.environment.OPENAI_API_KEY, undefined);
  });
}

test('Bedrock PR scans retain diff scope and severity failure outputs', async t => {
  const app = await harness(t, 'pr');
  app.setInput('provider', 'amazon-bedrock'); app.setInput('model', 'openai.synthetic-model'); app.setInput('fail-on-severity', 'high');
  process.env.AWS_BEARER_TOKEN_BEDROCK = 'synthetic-bedrock-bearer';
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.ok(result.args.includes('--diff')); assert.ok(result.args.includes('--head'));
  assert.equal(result.environment.AWS_BEARER_TOKEN_BEDROCK, 'synthetic-bedrock-bearer');
  assert.equal(result.environment.OPENAI_API_KEY, undefined);
});

test('Bedrock dry-run forwards no credentials and remains a skipped scan', async t => {
  const app = await harness(t);
  app.setInput('provider', 'amazon-bedrock'); app.setInput('model', 'openai.synthetic-model'); app.setInput('dry-run', 'true');
  process.env.AWS_BEARER_TOKEN_BEDROCK = 'synthetic-bedrock-bearer';
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'skipped');
  assert.equal(result.outputs['skip-reason'], 'dry-run');
  assert.equal(result.environment.AWS_BEARER_TOKEN_BEDROCK, undefined); assert.equal(result.environment.OPENAI_API_KEY, undefined);
});

for (const scenario of ['schedule', 'pr'] as const) {
  test(`missing API key fails a ${scenario === 'pr' ? 'Dependabot PR' : 'scheduled scan'} with setup guidance`, async (t) => {
    const app = await harness(t, scenario); delete process.env.OPENAI_API_KEY;
    process.env.AWS_BEARER_TOKEN_BEDROCK = 'synthetic-bedrock-bearer';
    if (scenario === 'pr') process.env.GITHUB_ACTOR = 'dependabot[bot]';
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.setups, 0); assert.equal(result.processes, 0);
    assert.equal(result.outputs['scan-status'], 'failed'); assert.equal(result.outputs['policy-status'], 'not-evaluated');
    assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.match(result.logs, /::error::Scan could not complete\./);
    assert.match(result.summary, /\*\*Scan could not complete\.\*\*/);
    assert.match(result.summary, /Set CODEX_SECURITY_API_KEY in Actions secrets \(or Dependabot secrets for Dependabot runs\) and pass it as OPENAI_API_KEY/);
    assert.doesNotMatch(result.logs, /Findings meet the configured failure threshold/);
  });
}

test('cleanup failure fails the job and appears in the summary and final error', async (t) => {
  const app = await harness(t); app.configure({cleanupFails: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['report-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.logs, /::error::Scan completed\..*Runtime cleanup failed\./);
  assert.match(result.summary, /Runtime cleanup failed\.\*\*/);
});

for (const threshold of ['none', 'high']) {
  test(`summary write failure preserves the scan result with severity threshold ${threshold}`, async (t) => {
    const app = await harness(t);
    app.setInput('summary', 'true'); app.setInput('fail-on-severity', threshold);
    t.mock.method(core.summary, 'write', async () => { throw new Error('Synthetic summary write failure'); });
    const result = await app.run();
    assert.equal(result.exitCode, threshold === 'none' ? 0 : 1);
    assert.equal(result.outputs['scan-status'], 'completed');
    assert.equal(result.outputs['policy-status'], threshold === 'none' ? 'passed' : 'failed');
    assert.equal(result.outputs['report-status'], 'ready');
    assert.equal(result.outputs['sarif-upload-ready'], 'true');
    assert.ok(result.outputs['sarif-path']);
    assert.equal(result.cleanups, 1);
    assert.match(result.logs, /::warning::Could not write the job summary\./);
  });
}

test('configuration diagnostics preserve values and cannot inject runner commands', async (t) => {
  const app = await harness(t);
  app.setInput('model', 'synthetic-offline-test-key\u2028::error::injected');
  const result = await app.run();
  const logs = result.logs;
  assert.match(logs, /synthetic-offline-test-key/);
  assert.doesNotMatch(logs, /^::error::injected/m);
  assert.doesNotMatch(logs, /\[REDACTED\]/);
});

test('scope exclusions and deferred notes do not fail completed scans or make findings provisional', async (t) => {
  const app = await harness(t);
  app.configure({scanResult: value => {
    value.coverage.explicitExclusions = [{pattern: 'assets/', reason: 'Static assets outside review scope.'}];
    value.coverage.deferred = [{id: 'unreviewed-route', reason: 'Dependency <example> unavailable; validation deferred.'}];
  }});
  app.setInput('verbose', 'false');
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['exit-code'], '0');
  assert.equal(result.outputs['policy-status'], 'passed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.equal(result.outputs['high-count'], '1'); assert.ok(result.outputs['json-path']);
  assert.ok(!result.args.includes('--verbose'));
  assert.doesNotMatch(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /Starting security scan/);
  assert.match(result.logs, /Scan: completed/);
  assert.match(result.logs, /Findings:.*high: 1/);
  assert.doesNotMatch(result.logs, /Provisional|Scan coverage is partial|::error::/);
  assert.doesNotMatch(result.summary, /provisional|not evaluated|not-evaluated/i);
  const coverage = JSON.parse(await readFile(result.outputs['coverage-path'], 'utf8'));
  assert.equal(coverage.deferred[0].reason, 'Dependency <example> unavailable; validation deferred.');
});

test('CLI warnings fail a completed scan and cannot emit legacy runner commands', async (t) => {
  const app = await harness(t);
  app.configure({scanResult: value => {
    value.warnings = ['Synthetic diagnostic: ##[stop-commands]token'];
  }});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['exit-code'], '0');
  assert.equal(result.outputs['policy-status'], 'not-evaluated');
  assert.equal(result.outputs['scan-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.logs, /Synthetic diagnostic: ##\\\[stop-commands\]token/);
  assert.doesNotMatch(result.logs, /##\[stop-commands\]/);
  assert.match(result.summary, /Synthetic diagnostic: ##&#91;stop-commands&#93;token/);
});

test('exit 2 fails the step even when finalized reports were retained', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2});
  app.setInput('annotations', 'true');
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['exit-code'], '2');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], '1'); assert.ok(result.outputs['json-path']);
  assert.match(result.summary, /absence of findings is inconclusive/);
  assert.doesNotMatch(result.logs, /Provisional/);
});

for (const [name, scanProcess] of [
  ['timeout', {timedOut: true}], ['interruption', {interrupted: true}],
  ['signal', {signal: 'SIGTERM' as const}],
] as const) {
  test(`retained reports cannot hide scan ${name}`, async (t) => {
    const app = await harness(t); app.configure({scanProcess});
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
    assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  });
}

for (const missingReport of ['scan-manifest.json', 'findings.json', 'coverage.json']) {
  test(`completed scan fails when required ${missingReport} is missing without artifact upload`, async (t) => {
    const app = await harness(t); app.configure({missingReport});
    app.setInput('upload-artifacts', 'false');
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.outputs['report-status'], 'failed');
    assert.equal(result.outputs['json-path'], ''); assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.match(result.logs, /required reporting failed/);
  });
}

test('wrong checkout fails before setup or scanner execution', async (t) => {
  const app = await harness(t); process.env.GITHUB_SHA = '0'.repeat(40); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 0); assert.equal(result.processes, 0);
  assert.equal(result.outputs['scan-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
});

for (const restoreCheckout of [false, true]) {
  test(`a scan of a commit checked out during preparation fails${restoreCheckout ? ' even after restoring the requested checkout' : ''}`, async (t) => {
    const app = await harness(t);
    app.git('commit', '--allow-empty', '-qm', 'Synthetic second revision');
    const otherSha = app.git('rev-parse', 'HEAD');
    app.git('checkout', '--detach', app.sha);
    app.configure({
      prepare: () => { app.git('checkout', '--detach', otherSha); },
      scanResult: () => { if (restoreCheckout) app.git('checkout', '--detach', app.sha); },
    });
    const result = await app.run();
    assert.equal(result.exitCode, 1);
    assert.equal(result.outputs['scan-status'], 'failed');
    assert.equal(result.outputs['scanned-sha'], app.sha);
    assert.equal(result.outputs['json-path'], '');
    assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.match(result.summary, /revision does not match/);
  });
}

test('a worktree changed during preparation cannot establish a scan of the requested commit', async (t) => {
  const app = await harness(t);
  app.configure({
    prepare: () => writeFile(join(app.repository, 'app.txt'), 'Changed before the CLI snapshot.\n'),
    scanResult: value => { value.manifest.scan.target.kind = 'git_worktree'; },
  });
  const result = await app.run();
  assert.equal(result.exitCode, 1);
  assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['json-path'], '');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.summary, /revision does not match/);
});

test('PR policy changes are scanned at the checked-out revision', async (t) => {
  const app = await harness(t, 'policy-pr'); const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.setups, 1); assert.equal(result.processes, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['scanned-sha'], app.sha);
  assert.ok(result.args.includes('--diff')); assert.ok(result.args.includes(app.sha));
});

test('dry-run is explicitly skipped with no findings policy pass', async (t) => {
  const app = await harness(t); app.setInput('dry-run', 'true'); delete process.env.OPENAI_API_KEY;
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'skipped'); assert.equal(result.outputs['skip-reason'], 'dry-run');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], ''); assert.ok(result.args.includes('--dry-run')); assert.equal(result.environment.OPENAI_API_KEY, undefined);
});

test('scope conflict fails without runtime setup', async (t) => {
  const app = await harness(t, 'pr'); app.setInput('paths', 'app.txt'); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 0); assert.match(result.logs, /paths cannot be combined/u);
});

test('missing optional CLI SARIF preserves a successful scan and uploads the remaining reports', async (t) => {
  const app = await harness(t); app.configure({ missingSarif: true });
  app.setInput('annotations', 'true'); app.setInput('upload-artifacts', 'true');
  let uploadedFiles: string[] = [];
  t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async (_name: string, files: string[]) => {
    uploadedFiles = files.map(file => basename(file));
    for (const file of files) assert.ok((await readFile(file)).length);
    return {id: 1, size: 1};
  });
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.processes, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['policy-status'], 'passed');
  assert.equal(result.outputs['report-status'], 'partial'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['sarif-path'], ''); assert.equal(result.outputs['high-count'], '1');
  assert.ok(result.outputs['json-path']); assert.ok(result.outputs['coverage-path']); assert.ok(result.outputs['results-directory']);
  assert.deepEqual(uploadedFiles.sort(), ['coverage.json', 'findings.json', 'scan-manifest.json']);
  assert.match(result.logs, /::warning::SARIF report is unavailable; scan results and other reports are still available\./);
  assert.match(result.logs, /^::warning .*file=src\/extract\.py/m);
  assert.doesNotMatch(result.logs, /::error::/);
  assert.match(result.summary, /\*\*Scan completed\. Findings are reported without failing the job\.\*\*/);
  assert.match(result.summary, /SARIF report is unavailable/);
});

test('missing SARIF does not mask a findings threshold failure', async (t) => {
  const app = await harness(t); app.setInput('fail-on-severity', 'high');
  app.configure({missingSarif: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'failed'); assert.equal(result.outputs['report-status'], 'partial');
  assert.equal(result.outputs['sarif-upload-ready'], 'false'); assert.equal(result.outputs['high-count'], '1');
  assert.match(result.logs, /::error::Scan completed\. Findings meet the configured failure threshold\./);
  assert.match(result.summary, /\*\*Scan completed\. Findings meet the configured failure threshold\.\*\*/);
});

test('requested artifact upload failure remains fatal without SARIF', async (t) => {
  const app = await harness(t); app.configure({missingSarif: true});
  app.setInput('upload-artifacts', 'true');
  const upload = t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async () => {
    throw new Error('Synthetic artifact upload failure');
  });
  const result = await app.run();
  assert.equal(upload.mock.callCount(), 1); assert.equal(result.exitCode, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['policy-status'], 'passed');
  assert.equal(result.outputs['report-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.ok(result.outputs['json-path']); assert.ok(result.outputs['coverage-path']);
  assert.ok(result.outputs['results-directory']); assert.equal(result.outputs['sarif-path'], '');
  assert.match(result.logs, /::error::Scan completed, but required reporting failed\./);
  assert.match(result.summary, /Synthetic artifact upload failure/);
});

test('archive read failure preserves scan reports, summary and cleanup', {
  skip: process.platform === 'win32' || process.getuid?.() === 0,
}, async t => {
  const app = await harness(t);
  app.setInput('upload-artifacts', 'true');
  const requests: string[] = [];
  const server = createServer(async (request, response) => {
    for await (const _chunk of request) { /* Read the artifact creation request. */ }
    requests.push(request.url ?? '');
    response.writeHead(200, {'Content-Type': 'application/json'});
    response.end(JSON.stringify({ok: true, signed_upload_url: 'https://example.invalid/artifact'}));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const payload = Buffer.from(JSON.stringify({scp: 'Actions.Results:synthetic-run:synthetic-job'})).toString('base64url');
  Object.assign(process.env, {
    ACTIONS_RESULTS_URL: `http://127.0.0.1:${address.port}`,
    ACTIONS_RUNTIME_TOKEN: `e30.${payload}.synthetic-signature`,
  });
  let signal: AbortSignal | undefined;
  t.mock.method(BlobClient.prototype, 'getBlockBlobClient', () => ({
    uploadStream: async (input: AsyncIterable<Buffer>, _bufferSize: number, _concurrency: number, options: {abortSignal: AbortSignal}) => {
      signal = options.abortSignal;
      for await (const _chunk of input) { /* Consume the real archive stream. */ }
    },
  }));
  let staging = '';
  let unreadable = '';
  const uploadArtifact = DefaultArtifactClient.prototype.uploadArtifact;
  t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async function (this: DefaultArtifactClient, ...args: Parameters<typeof uploadArtifact>) {
    staging = args[2];
    unreadable = args[1][0];
    // Fail the archive's actual file read without altering the saved scan report.
    await chmod(unreadable, 0);
    return uploadArtifact.apply(this, args);
  });
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'passed');
  assert.equal(result.outputs['report-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  for (const name of ['json-path', 'coverage-path', 'sarif-path']) {
    assert.ok((await readFile(result.outputs[name])).length);
  }
  assert.match(result.summary, /EACCES/);
  assert.ok(result.summary.includes(unreadable));
  assert.match(result.logs, /::error::Scan completed, but required reporting failed\./);
  assert.deepEqual(requests, ['/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact']);
  assert.equal(signal?.aborted, true);
  await assert.rejects(stat(staging), {code: 'ENOENT'});
});

test('Bedrock CLI authentication failure leaves findings unavailable', async (t) => {
  const app = await harness(t);
  app.setInput('provider', 'amazon-bedrock'); app.setInput('model', 'openai.synthetic-model');
  delete process.env.OPENAI_API_KEY;
  app.configure({exitCode: 2, cliFailure: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.processes, 1); assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['json-path'], '');
  assert.match(result.summary, /Synthetic API authentication failure/);
  assert.doesNotMatch(result.logs, /Findings meet the configured failure threshold/);
  for (const level of ['critical', 'high', 'medium', 'low', 'informational']) assert.equal(result.outputs[`${level}-count`], '');
  assert.match(result.summary, /\*\*Findings:\*\* unavailable/);
  assert.match(result.logs, /Findings: unavailable/);
});

test('valid empty findings publish zero counts', async (t) => {
  const app = await harness(t); app.configure({scanResult: value => { value.findings.findings = []; }});
  const result = await app.run();
  assert.equal(result.exitCode, 0);
  for (const level of ['critical', 'high', 'medium', 'low', 'informational']) assert.equal(result.outputs[`${level}-count`], '0');
});

test('changed checkout during a committed diff scan fails', async (t) => {
  const app = await harness(t, 'pr');
  app.configure({mutateCheckout: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1);
  assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.summary, /source checkout changed/);
});
