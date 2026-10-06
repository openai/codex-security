import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, writeFile, rm, realpath, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { analyzeResults, readReportFile, type ResultOptions } from '../src/results.js';
import { collectReports } from '../src/artifacts.js';

async function fixture(t: { after(fn: () => Promise<void>): void }): Promise<ResultOptions> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-results-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  await cp(new URL('./fixtures/completed-scan/', import.meta.url), root, { recursive: true });
  const document = async (name: string) => JSON.parse(await readFile(join(root, name), 'utf8'));
  return {
    resultsDirectory: root, scannedSha: 'a'.repeat(40), exitCode: 0, publishable: true,
    stdout: JSON.stringify({
      manifest: await document('scan-manifest.json'),
      findings: await document('findings.json'),
      coverage: await document('coverage.json'),
      scanDir: root,
      sarifPath: join(root, 'exports/results.sarif'),
      cost: { estimatedUsd: 0.125 },
    }),
  };
}
function change(options: ResultOptions, update: (value: any) => void): void {
  const value = JSON.parse(options.stdout);
  update(value);
  options.stdout = JSON.stringify(value);
}

test('adapts a synthetic CLI JSON result into findings, counts and report outputs', async (t) => {
  const opts = await fixture(t);
  const result = await analyzeResults(opts);
  assert.deepEqual(result.errors, []);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.policyStatus, 'passed');
  assert.equal(result.reportStatus, 'ready');
  assert.equal(result.sarifUploadReady, true);
  assert.deepEqual(result.counts, { critical: 0, high: 1, medium: 0, low: 0, informational: 0 });
  assert.equal(result.estimatedCost, 0.125);
  assert.equal(result.findings[0]?.path, 'src/extract.py');
  assert.equal(result.findings[0]?.startLine, 41);
  assert.equal(result.paths.jsonPath, join(opts.resultsDirectory, 'findings.json'));
});

test('uses the structured CLI findings instead of reparsing report documents', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.findings.findings[0].title = 'Title from the CLI result'; });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.findings[0]?.title, 'Title from the CLI result');
});

test('annotations prefer the root control over an earlier entry point', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => {
    value.findings.findings[0].locations = [
      {role: 'entrypoint', path: 'src/route.ts', startLine: 7},
      {role: 'root_control', path: 'src/validation.ts', startLine: 30, endLine: 32},
    ];
  });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.findings[0]?.path, 'src/validation.ts');
  assert.equal(result.findings[0]?.startLine, 30);
  assert.equal(result.findings[0]?.endLine, 32);
});

test('reports must describe the requested repository or diff revision', async (t) => {
  const opts = await fixture(t);
  for (const kind of ['git_revision', 'git_diff']) {
    change(opts, (value) => {
      Object.assign(value.manifest.scan.target, {kind, revision: 'b'.repeat(40), headRevision: 'b'.repeat(40)});
    });
    const result = await analyzeResults(opts);
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.paths.jsonPath, '');
    assert.match(result.errors.join('\n'), /revision does not match/);
    change(opts, (value) => {
      value.manifest.scan.target[kind === 'git_diff' ? 'headRevision' : 'revision'] = opts.scannedSha;
    });
    assert.equal((await analyzeResults(opts)).scanStatus, 'completed');
  }
  change(opts, (value) => { Object.assign(value.manifest.scan.target, {kind: 'git_worktree', revision: opts.scannedSha}); });
  assert.equal((await analyzeResults(opts)).scanStatus, 'failed', 'a dirty worktree is not the requested immutable commit');
});

test('report collection preserves credential-shaped diagnostic content', async (t) => {
  const opts = await fixture(t);
  const report = JSON.parse(await readFile(join(opts.resultsDirectory, 'findings.json'), 'utf8'));
  report.findings[0].summary = 'Synthetic diagnostic: sk-test/secret+value';
  const bytes = Buffer.from(JSON.stringify(report));
  await writeFile(join(opts.resultsDirectory, 'findings.json'), bytes);
  const reports = await collectReports(await analyzeResults(opts));
  assert.deepEqual(reports.get('findings.json'), bytes);
});

test('exit 1 preserves completed reports and records the CLI severity-policy failure', async (t) => {
  const opts = await fixture(t); opts.exitCode = 1;
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.policyStatus, 'failed');
  assert.equal(result.sarifUploadReady, true);
});

test('operational exits and signal termination cannot turn complete output into success', async (t) => {
  const opts = await fixture(t);
  for (const exitCode of [2, 143, null]) {
    const result = await analyzeResults({ ...opts, exitCode });
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings.length, 1);
  }
});

test('a failed manifest cannot become successful from exit 0', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.manifest.scan.status = 'failed'; });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'failed');
  assert.equal(result.policyStatus, 'not-evaluated');
  assert.equal(result.sarifUploadReady, false);
});

test('valid partial coverage preserves findings and explains incomplete work without passing policy', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => {
    value.coverage.completeness = 'partial';
    value.coverage.deferred = [{ id: 'unreviewed-route', reason: 'Route validation could not finish.' }];
    value.coverage.surfaces[0].disposition = 'needs_follow_up';
  });
  for (const exitCode of [0, 2]) {
    const result = await analyzeResults({ ...opts, exitCode });
    assert.equal(result.scanStatus, 'incomplete');
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings.length, 1);
    assert.equal(result.paths.jsonPath, join(opts.resultsDirectory, 'findings.json'));
    assert.ok(result.errors.includes('Deferred work: Route validation could not finish.'));
    assert.ok(result.errors.includes('Needs follow-up: Archive extraction'));
  }
});

test('unknown coverage remains a failure even when findings and reports are available', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.coverage.completeness = 'unknown'; });
  for (const exitCode of [0, 1, 2]) {
    const result = await analyzeResults({ ...opts, exitCode });
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings.length, 1);
    assert.match(result.errors.join('\n'), /could not determine scan coverage/);
  }
});

test('partial reports do not override policy-failure, abnormal, or missing process exits', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.coverage.completeness = 'partial'; });
  for (const exitCode of [1, 130, 143, null]) {
    const result = await analyzeResults({ ...opts, exitCode });
    assert.equal(result.scanStatus, 'failed', `exit ${exitCode}`);
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings.length, 1);
  }
});

test('partial reports do not override failed or interrupted scan manifests', async (t) => {
  const opts = await fixture(t);
  for (const status of ['failed', 'interrupted', 'canceled']) {
    change(opts, (value) => {
      value.coverage.completeness = 'partial';
      value.manifest.scan.status = status;
    });
    const result = await analyzeResults({ ...opts, exitCode: 2 });
    assert.equal(result.scanStatus, 'failed', status);
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings.length, 1);
  }
});

test('partial reports cannot hide execution failure or a CLI target-change warning', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.coverage.completeness = 'partial'; });
  const executionFailure = await analyzeResults({ ...opts, exitCode: 2, executionFailed: true });
  assert.equal(executionFailure.scanStatus, 'failed');
  assert.equal(executionFailure.policyStatus, 'not-evaluated');
  assert.equal(executionFailure.sarifUploadReady, false);

  const warning = 'Scan target changed during execution.';
  change(opts, (value) => { value.warnings = [warning]; });
  const targetChange = await analyzeResults({ ...opts, exitCode: 2 });
  assert.equal(targetChange.scanStatus, 'failed');
  assert.equal(targetChange.policyStatus, 'not-evaluated');
  assert.equal(targetChange.sarifUploadReady, false);
  assert.ok(targetChange.errors.includes(warning));
});

test('a CLI failure envelope takes precedence over partial result fields', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => {
    value.coverage.completeness = 'partial';
    Object.assign(value, { status: 'failed', code: 'SCAN_FAILED', message: 'Synthetic runtime failure.' });
  });
  const result = await analyzeResults({ ...opts, exitCode: 2 });
  assert.equal(result.scanStatus, 'failed');
  assert.equal(result.policyStatus, 'not-evaluated');
  assert.equal(result.sarifUploadReady, false);
  assert.equal(result.paths.jsonPath, '');
  assert.deepEqual(result.errors, ['Synthetic runtime failure.']);
});

test('missing optional SARIF does not change partial coverage into an execution failure', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.coverage.completeness = 'partial'; });
  await rm(join(opts.resultsDirectory, 'exports/results.sarif'));
  const result = await analyzeResults({ ...opts, exitCode: 2 });
  assert.equal(result.scanStatus, 'incomplete');
  assert.equal(result.policyStatus, 'not-evaluated');
  assert.equal(result.reportStatus, 'partial');
  assert.equal(result.sarifUploadReady, false);
  assert.equal(result.findings.length, 1);
});

test('missing SARIF leaves a completed scan with partial reports', async (t) => {
  const opts = await fixture(t); await rm(join(opts.resultsDirectory, 'exports/results.sarif'));
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.reportStatus, 'partial');
  assert.equal(result.sarifUploadReady, false);
});

test('non-publishable checkouts never become SARIF upload ready', async (t) => {
  const opts = await fixture(t); opts.publishable = false;
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.reportStatus, 'ready');
  assert.equal(result.sarifUploadReady, false);
});

test('missing, malformed and error-only CLI output fails even when report files exist', async (t) => {
  const opts = await fixture(t);
  for (const stdout of ['', 'not JSON', 'null', '{}', JSON.stringify({ error: 'API key rejected' })]) {
    const result = await analyzeResults({ ...opts, stdout });
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.ok(result.errors.length > 0);
    assert.equal(result.counts, undefined);
  }
});

test('unreadable consumed fields fail instead of publishing misleading counts', async (t) => {
  const opts = await fixture(t);
  for (const update of [
    (value: any) => { value.findings.findings = null; },
    (value: any) => { value.findings.findings[0].severity = null; },
    (value: any) => { value.coverage = null; },
    (value: any) => { value.manifest.scan = null; },
  ]) {
    const invalid = { ...opts }; change(invalid, update);
    const result = await analyzeResults(invalid);
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.policyStatus, 'not-evaluated');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.counts, undefined);
  }
});

test('rejects output referring to a different scan directory', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.scanDir = join(opts.resultsDirectory, '..'); });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'failed');
  assert.equal(result.sarifUploadReady, false);
});

test('never publishes a SARIF path outside the private report directory', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.sarifPath = join(opts.resultsDirectory, '..', 'outside.sarif'); });
  const result = await analyzeResults(opts);
  assert.equal(result.paths.sarifPath, '');
  assert.equal(result.sarifUploadReady, false);
});

test('unsafe source locations cannot reach annotations or published results', async (t) => {
  const opts = await fixture(t);
  for (const path of ['../secret', '/etc/passwd', 'https://example.com/source', 'a\\b', 'C:/source.ts', 'C:source.ts']) {
    change(opts, (value) => { value.findings.findings[0].locations[0].path = path; });
    const result = await analyzeResults(opts);
    assert.equal(result.scanStatus, 'failed');
    assert.equal(result.sarifUploadReady, false);
    assert.equal(result.findings[0]?.path, undefined);
  }
});

test('safe reader rejects symlinks, hardlinks, FIFO and paths outside the report directory', async (t) => {
  const opts = await fixture(t); const path = join(opts.resultsDirectory, 'findings.json');
  await rm(path); await symlink('coverage.json', path);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await rm(path); await link(join(opts.resultsDirectory, 'coverage.json'), path);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await rm(path); execFileSync('mkfifo', [path]);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await assert.rejects(readReportFile(opts.resultsDirectory, '../outside'));
  await rm(join(opts.resultsDirectory, 'exports'), { recursive: true });
  await symlink('..', join(opts.resultsDirectory, 'exports'));
  await assert.rejects(readReportFile(opts.resultsDirectory, 'exports/results.sarif'));
});

test('safe reader accepts regular reports larger than the removed Action-only limit', async (t) => {
  const opts = await fixture(t);
  const bytes = Buffer.alloc(16 * 1024 * 1024 + 1, ' ');
  await writeFile(join(opts.resultsDirectory, 'findings.json'), bytes);
  assert.equal((await readReportFile(opts.resultsDirectory, 'findings.json')).length, bytes.length);
});

test('SARIF publication rejects external references and encoded traversal paths', async (t) => {
  const opts = await fixture(t);
  for (const sarif of [
    {runs: [{results: [{relatedLocations: [{physicalLocation: {artifactLocation: {uri: '%2e%2e/secret'}}}]}]}]},
    {runs: [{results: [{locations: [{physicalLocation: {artifactLocation: {uri: 'https://example.invalid/source'}}}]}]}]},
    {runs: [{results: [{locations: [{physicalLocation: {artifactLocation: {uri: 'file:/etc/passwd'}}}]}]}]},
    {runs: [{results: [{locations: [{physicalLocation: {artifactLocation: {uri: 'C%3A/source.ts'}}}]}]}]},
    {runs: [{externalPropertyFileReferences: {}}]},
  ]) {
    await writeFile(join(opts.resultsDirectory, 'exports/results.sarif'), JSON.stringify(sarif));
    const result = await analyzeResults(opts);
    assert.equal(result.scanStatus, 'completed');
    assert.equal(result.reportStatus, 'partial');
    assert.equal(result.paths.sarifPath, '');
    assert.equal(result.sarifUploadReady, false);
  }
});


test('valid empty and partial findings distinguish zero counts from unavailable results', async (t) => {
  const opts = await fixture(t);
  change(opts, (value) => { value.findings.findings = []; });
  assert.deepEqual((await analyzeResults(opts)).counts, {critical: 0, high: 0, medium: 0, low: 0, informational: 0});
  const partial = await fixture(t);
  change(partial, (value) => { value.coverage.completeness = 'partial'; });
  assert.equal((await analyzeResults({...partial, exitCode: 2})).counts?.high, 1);
});

test('accepted relative path spellings preserve completed findings and SARIF', async (t) => {
  const opts = await fixture(t);
  for (const path of ['./src/extract.py', 'src//extract.py', 'module:handler.ts']) {
    change(opts, (value) => { value.findings.findings[0].locations[0].path = path; });
    await writeFile(join(opts.resultsDirectory, 'exports/results.sarif'), JSON.stringify({runs: [{results: [
      {locations: [{physicalLocation: {artifactLocation: {uri: path.replaceAll(':', '%3A')}}}]},
    ]}]}));
    const result = await analyzeResults(opts);
    assert.equal(result.scanStatus, 'completed');
    assert.equal(result.findings[0]?.path, path);
    assert.equal(result.counts?.high, 1);
    assert.equal(result.sarifUploadReady, true);
  }
});

test('prepared SARIF lets the uploader set distinct workflow categories', async (t) => {
  const opts = await fixture(t);
  const original = JSON.parse(await readFile(join(opts.resultsDirectory, 'exports/results.sarif'), 'utf8'));
  assert.ok(original.runs[0].automationDetails.id);
  const result = await analyzeResults(opts);
  const sarif = JSON.parse(await readFile(result.paths.sarifPath, 'utf8'));
  const expected = structuredClone(original);
  for (const run of expected.runs) delete run.automationDetails;
  assert.deepEqual(sarif, expected);
  for (const category of ['security/frontend', 'security/backend']) {
    const upload = structuredClone(sarif);
    // Match upload-sarif's category precedence: it fills only missing automationDetails.
    for (const run of upload.runs) {
      if (run.automationDetails === undefined) run.automationDetails = {id: `${category}/`};
    }
    assert.ok(upload.runs.every((run: any) => run.automationDetails.id === `${category}/`));
  }
  assert.deepEqual((await collectReports(result)).get('exports/results.sarif'), await readFile(result.paths.sarifPath));
  assert.equal((await analyzeResults(opts)).sarifUploadReady, true, 'preparation is repeatable');
});


test('SARIF preparation never rewrites linked report files', async (t) => {
  const opts = await fixture(t);
  const path = join(opts.resultsDirectory, 'exports/results.sarif');
  const target = join(opts.resultsDirectory, 'findings.json');
  const before = await readFile(target);
  await rm(path); await symlink('../findings.json', path);
  assert.equal((await analyzeResults(opts)).sarifUploadReady, false);
  assert.deepEqual(await readFile(target), before);
  await rm(path); await link(target, path);
  assert.equal((await analyzeResults(opts)).sarifUploadReady, false);
  assert.deepEqual(await readFile(target), before);
});
