import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, writeFile, rm, realpath, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { analyzeResults, readReportFile, type ResultOptions } from '../src/results.js';
import { exportSarifArgs } from '../src/sarif.js';

async function fixture(t: { after(fn: () => Promise<void>): void }): Promise<ResultOptions> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-results-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  await cp(new URL('./fixtures/completed-scan/', import.meta.url), root, { recursive: true });
  const document = async (name: string) => JSON.parse(await readFile(join(root, name), 'utf8'));
  return {
    resultsDirectory: root, exitCode: 0, publishable: true,
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
  for (const path of ['../secret', '/etc/passwd', 'https://example.com/source', 'a\\b']) {
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

test('exporter args bind directory and checkout explicitly', () => {
  assert.deepEqual(exportSarifArgs('/tmp/a b', '/repo', '/tmp/a b/exports/results.sarif'),
    ['export', '/tmp/a b', '--export-format', 'sarif', '--source-root', '/repo', '--output', '/tmp/a b/exports/results.sarif']);
});

test('SARIF publication rejects external references and encoded traversal paths', async (t) => {
  const opts = await fixture(t);
  for (const sarif of [
    {runs: [{results: [{relatedLocations: [{physicalLocation: {artifactLocation: {uri: '%2e%2e/secret'}}}]}]}]},
    {runs: [{results: [{locations: [{physicalLocation: {artifactLocation: {uri: 'https://example.invalid/source'}}}]}]}]},
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
