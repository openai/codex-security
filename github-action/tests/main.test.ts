import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import * as core from '@actions/core';
import { DefaultArtifactClient } from '@actions/artifact';
import { runAction } from '../src/main.js';
import { INPUT_NAMES } from '../src/inputs.js';
import { gitEnvironment } from '../src/targets.js';
import type { Runtime } from '../src/runtime.js';
import type { ProcessResult } from '../src/process.js';

type Scenario = 'schedule' | 'pr' | 'policy-pr';
const inputKey = (name: string): string => `INPUT_${name.toUpperCase()}`;

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

async function harness(t: TestContext, scenario: Scenario = 'schedule') {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-main-test-')));
  const repository = join(root, 'repo');
  await mkdir(repository);
  const git = (...args: string[]): string => execFileSync('/usr/bin/git', [
    '-c', 'user.name=Offline Test', '-c', 'user.email=offline@example.invalid', '-c', 'core.hooksPath=/dev/null', ...args,
  ], { cwd: repository, env: gitEnvironment(), encoding: 'utf8' }).trim();
  git('init', '-q', '-b', 'main');
  git('remote', 'add', 'origin', 'https://github.com/example/repo.git');
  await writeFile(join(repository, 'app.txt'), 'synthetic source\n');
  git('add', '.'); git('commit', '-qm', 'base');
  const base = git('rev-parse', 'HEAD');
  if (scenario !== 'schedule') {
    await writeFile(join(repository, scenario === 'policy-pr' ? 'SECURITY.md' : 'app.txt'), 'synthetic change\n');
    git('add', '.'); git('commit', '-qm', 'PR change');
  }
  const sha = git('rev-parse', 'HEAD');
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
    GITHUB_ACTOR: 'trusted-maintainer', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_OUTPUT: outputPath, GITHUB_STATE: statePath, RUNNER_TEMP: root,
    OPENAI_API_KEY: 'synthetic-offline-test-key', INPUT_SUMMARY: 'true', INPUT_ANNOTATIONS: 'false',
    INPUT_SCOPE: scenario === 'schedule' ? 'repository' : 'diff',
  });
  delete process.env.CODEX_API_KEY;
  const runtime: Runtime = {
    root: join(root, 'runtime'), home: join(root, 'runtime/home'), codexHome: join(root, 'runtime/codex'),
    stateDirectory: join(root, 'runtime/state'), resultsDirectory: join(root, 'results'),
    nodePath: '/never-executed/node', cliPath: '/never-executed/cli.js',
    env: (key) => ({ OPENAI_API_KEY: key }),
  };
  let setups = 0;
  let processes = 0;
  let cleanups = 0;
  const configuration: { exitCode?: number; partial?: boolean; missingSarif?: boolean; mutateCheckout?: boolean; cleanupFails?: boolean; cliFailure?: boolean; scanProcess?: Partial<ProcessResult>; scanResult?: (value: any) => void; missingReport?: string; prepare?: () => void | Promise<void> } = {};
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
    await cp(new URL('./fixtures/completed-scan/', import.meta.url), runtime.resultsDirectory, { recursive: true });
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
    if (configuration.partial) {
      coverage.completeness = 'partial';
      coverage.deferred = [{id: 'unreviewed-route', reason: 'Dependency <example> unavailable; validation deferred.'}];
    }
    sarif.runs[0].versionControlProvenance[0].revisionId = scanSha;
    await writeFile(coveragePath, JSON.stringify(coverage));
    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(sarifPath, JSON.stringify(sarif));
    if (configuration.missingSarif) await rm(sarifPath);
    const value = {manifest, coverage, findings: JSON.parse(await readFile(join(runtime.resultsDirectory, 'findings.json'), 'utf8')),
      scanDir: runtime.resultsDirectory, sarifPath: configuration.missingSarif ? null : sarifPath, cost: {estimatedUsd: 0.125}};
    configuration.scanResult?.(value);
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

test('PR severity failure retains complete SARIF outputs for always upload steps', async (t) => {
  const app = await harness(t, 'pr'); app.setInput('fail-on-severity', 'high'); app.configure({ exitCode: 1 });
  app.setInput('model', 'gpt-5.6-luna'); app.setInput('effort', 'medium');
  app.setInput('annotations', ''); // Use the default, as in the README's PR workflow.
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['policy-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'true'); assert.equal(result.outputs['analysis-ref'], 'refs/pull/4/head');
  assert.equal(result.outputs['scanned-sha'], app.sha); assert.equal(result.outputs['high-count'], '1');
  assert.equal(result.outputs['estimated-cost'], '0.125'); assert.ok(result.outputs['sarif-path']);
  assert.ok(result.args.includes('--model=gpt-5.6-luna'));
  assert.equal(result.args[result.args.indexOf('--effort') + 1], 'medium');
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
  const app = await harness(t); const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'passed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.equal(result.outputs['analysis-ref'], 'refs/heads/main');
  assert.ok(result.args.includes('--verbose'));
  assert.match(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /CLI preparation completed in \d+m \d+s/);
  assert.match(result.logs, /Target commit: [a-f0-9]{40}/);
  assert.match(result.logs, /Security scan exited after \d+m \d+s; exit code: 0/);
  assert.match(result.logs, /Scan: completed; findings policy: passed; report: ready/);
  assert.match(result.logs, /Estimated cost: \$0.1250/);
  assert.match(result.logs, /Scan completed\. Findings are reported without failing the job\./);
  assert.match(result.summary, /\*\*Scan completed\. Findings are reported without failing the job\.\*\*/);
});

test('unrelated ambient input variables do not reject a valid scan', async (t) => {
  const app = await harness(t); process.env.INPUT_FOO = 'unrelated workflow value';
  app.setInput('effort', 'medium');
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.args[result.args.indexOf('--effort') + 1], 'medium');
});

test('Deep scans forward their budget and publish completed reports with cleanup', async (t) => {
  const app = await harness(t);
  app.setInput('mode', 'deep'); app.setInput('max-time-hours', '1.5');
  const result = await app.run();
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

for (const scenario of ['schedule', 'pr'] as const) {
  test(`missing API key fails a ${scenario === 'pr' ? 'Dependabot PR' : 'scheduled scan'} with setup guidance`, async (t) => {
    const app = await harness(t, scenario); delete process.env.OPENAI_API_KEY;
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

test('verbose false suppresses CLI diagnostics but retains lifecycle and results', async (t) => {
  const app = await harness(t); app.setInput('verbose', 'false'); const result = await app.run();
  assert.equal(result.exitCode, 0);
  assert.ok(!result.args.includes('--verbose'));
  assert.doesNotMatch(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /Starting security scan/);
  assert.match(result.logs, /Scan: completed/);
});

test('configuration diagnostics preserve values and cannot inject runner commands', async (t) => {
  const app = await harness(t);
  app.setInput('model', 'synthetic-offline-test-key\u2028::error::injected');
  const result = await app.run();
  const logs = result.logs;
  assert.match(logs, /synthetic-offline-test-key/);
  assert.doesNotMatch(logs, /^::error::injected/m);
  assert.doesNotMatch(logs, /\[REDACTED\]/);
});

test('partial scan warns with provisional findings and no SARIF upload eligibility', async (t) => {
  const app = await harness(t); app.configure({ exitCode: 2, partial: true, missingSarif: true }); app.setInput('verbose', 'false');
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'incomplete');
  assert.equal(result.outputs['exit-code'], '2');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], '1'); assert.ok(result.outputs['json-path']);
  assert.match(result.logs, /Provisional findings:/);
  assert.match(result.logs, /::warning::Scan coverage is partial\..*findings policy was not evaluated/);
  assert.doesNotMatch(result.logs, /::error::/);
  assert.match(result.summary, /\*\*Scan coverage is partial\. Available findings are provisional\.\*\*/);
  assert.match(result.summary, /Deferred work: Dependency &lt;example&gt; unavailable; validation deferred\./);
  assert.match(result.logs, /Report diagnostic: Deferred work: Dependency <example> unavailable; validation deferred\./);
  assert.doesNotMatch(result.logs, /Synthetic live CLI progress/);
});

test('partial scan reasons cannot emit legacy runner commands', async (t) => {
  const app = await harness(t);
  app.configure({exitCode: 2, partial: true, scanResult: value => {
    value.coverage.deferred[0].reason = 'Synthetic diagnostic: ##[stop-commands]token';
  }});
  const result = await app.run();
  assert.equal(result.exitCode, 0);
  assert.match(result.logs, /Synthetic diagnostic: ##\\\[stop-commands\]token/);
  assert.doesNotMatch(result.logs, /##\[stop-commands\]/);
  assert.match(result.summary, /Synthetic diagnostic: ##&#91;stop-commands&#93;token/);
});

test('partial scans retain reports without evaluating the configured findings threshold', async (t) => {
  const app = await harness(t);
  app.configure({exitCode: 2, partial: true}); app.setInput('fail-on-severity', 'high'); app.setInput('upload-artifacts', 'true');
  let uploadedFiles: string[] = [];
  t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async (_name: string, files: string[]) => {
    uploadedFiles = files.map(file => basename(file));
    return {id: 1, size: 1};
  });
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'incomplete');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], '1');
  assert.ok(uploadedFiles.includes('findings.json')); assert.ok(uploadedFiles.includes('coverage.json'));
  assert.match(result.logs, /::warning::Scan coverage is partial\..*findings policy was not evaluated/);
  assert.doesNotMatch(result.logs, /::error::/);
});

for (const [name, scanProcess] of [
  ['timeout', {timedOut: true}], ['interruption', {interrupted: true}],
  ['signal', {signal: 'SIGTERM' as const}], ['terminated exit', {exitCode: 143}],
  ['policy exit', {exitCode: 1}], ['malformed output', {stdout: 'not JSON'}],
] as const) {
  test(`partial report cannot hide scan ${name}`, async (t) => {
    const app = await harness(t); app.configure({exitCode: 2, partial: true, scanProcess});
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
    assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.doesNotMatch(result.logs, /::warning::Scan coverage is partial/);
  });
}

for (const [name, scanResult] of [
  ['unknown coverage', (value: any) => { value.coverage.completeness = 'unknown'; }],
  ['failed manifest', (value: any) => { value.manifest.scan.status = 'failed'; }],
  ['target-change warning', (value: any) => { value.warnings = ['Synthetic target changed during scanning.']; }],
] as const) {
  test(`${name} cannot become a warning-only partial scan`, async (t) => {
    const app = await harness(t); app.configure({exitCode: 2, partial: true, scanResult});
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
    assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  });
}

test('CLI failure remains fatal even with partial reports on disk', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2, partial: true, cliFailure: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['json-path'], '');
  assert.match(result.summary, /Synthetic API authentication failure/);
});

for (const missingReport of ['scan-manifest.json', 'findings.json', 'coverage.json']) {
  test(`partial scan fails when required ${missingReport} is missing without artifact upload`, async (t) => {
    const app = await harness(t); app.configure({exitCode: 2, partial: true, missingReport});
    app.setInput('upload-artifacts', 'false');
    const result = await app.run();
    assert.equal(result.exitCode, 1); assert.equal(result.outputs['report-status'], 'failed');
    assert.equal(result.outputs['json-path'], ''); assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.match(result.logs, /required reporting failed/);
    assert.doesNotMatch(result.logs, /::warning::Scan coverage is partial/);
  });
}

test('partial scan does not hide requested artifact upload failure', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2, partial: true}); app.setInput('upload-artifacts', 'true');
  t.mock.method(DefaultArtifactClient.prototype, 'uploadArtifact', async () => { throw new Error('Synthetic upload failure'); });
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['report-status'], 'failed');
  assert.match(result.summary, /Synthetic upload failure/);
});

test('partial scan does not hide runtime cleanup failure', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2, partial: true, cleanupFails: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['report-status'], 'failed');
  assert.match(result.summary, /Runtime cleanup failed/);
});

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

test('CLI authentication failure leaves findings unavailable instead of reporting a threshold failure', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2, cliFailure: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['json-path'], '');
  assert.match(result.summary, /Synthetic API authentication failure/);
  assert.doesNotMatch(result.logs, /Findings meet the configured failure threshold/);
  for (const level of ['critical', 'high', 'medium', 'low', 'informational']) assert.equal(result.outputs[`${level}-count`], '');
  assert.match(result.summary, /\*\*Findings:\*\* unavailable/);
  assert.match(result.logs, /Provisional findings: unavailable/);
});

test('malformed findings keep count outputs empty', async (t) => {
  const app = await harness(t); app.configure({scanResult: value => { value.findings.findings[0].severity = null; }});
  const result = await app.run();
  assert.equal(result.exitCode, 1);
  for (const level of ['critical', 'high', 'medium', 'low', 'informational']) assert.equal(result.outputs[`${level}-count`], '');
});

test('valid empty findings publish zero counts', async (t) => {
  const app = await harness(t); app.configure({scanResult: value => { value.findings.findings = []; }});
  const result = await app.run();
  assert.equal(result.exitCode, 0);
  for (const level of ['critical', 'high', 'medium', 'low', 'informational']) assert.equal(result.outputs[`${level}-count`], '0');
});

for (const partial of [false, true]) {
  test(`changed checkout during a committed diff scan fails with ${partial ? 'partial' : 'complete'} coverage`, async (t) => {
    const app = await harness(t, 'pr');
    app.configure({mutateCheckout: true, partial, exitCode: partial ? 2 : 0});
    const result = await app.run();
    assert.equal(result.exitCode, 1);
    assert.equal(result.outputs['scan-status'], 'failed');
    assert.equal(result.outputs['sarif-upload-ready'], 'false');
    assert.match(result.summary, /source checkout changed/);
  });
}
