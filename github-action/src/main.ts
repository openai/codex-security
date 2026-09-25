import * as core from '@actions/core';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { parseInputs, scanArguments, type Inputs } from './inputs.js';
import { resolveTarget, validateEvent, type EventContext, type Target } from './targets.js';
import { SUPPORTED_CLI_VERSION, setupRuntime, cleanupRuntime, runtimeEnvironment, type Runtime } from './runtime.js';
import { runProcess, safeLogLines } from './process.js';
import { analyzeResults, type ScanResults } from './results.js';
import { exportSarifArgs } from './sarif.js';
import { collectReports, uploadReports } from './artifacts.js';
import { resultSummary, emitAnnotations, plain, resultTitle } from './reporting.js';

export const OUTPUT_NAMES = [
  'sarif-path', 'json-path', 'coverage-path', 'results-directory', 'scan-status', 'skip-reason',
  'policy-status', 'report-status', 'exit-code', 'scanned-sha', 'analysis-ref', 'sarif-upload-ready',
  'critical-count', 'high-count', 'medium-count', 'low-count', 'informational-count', 'estimated-cost',
] as const;
interface Dependencies {
  setupRuntime: typeof setupRuntime;
  runProcess: typeof runProcess;
  cleanupRuntime: typeof cleanupRuntime;
}

async function context(): Promise<EventContext> {
  const path = process.env.GITHUB_EVENT_PATH;
  if (!path) throw new Error('GITHUB_EVENT_PATH is required; run this action in GitHub Actions.');
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 10 * 1024 * 1024) throw new Error('GitHub event payload is not a bounded regular file.');
  const payload: unknown = JSON.parse(await readFile(path, 'utf8'));
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid GitHub event payload.');
  return {eventName: process.env.GITHUB_EVENT_NAME ?? '', repository: process.env.GITHUB_REPOSITORY ?? '',
    sha: process.env.GITHUB_SHA ?? '', ref: process.env.GITHUB_REF ?? '',
    serverUrl: process.env.GITHUB_SERVER_URL ?? '', payload: payload as Record<string, unknown>};
}
function outputs(result: ScanResults, target: Target, exitCode: number): void {
  const values: Record<string, string | number | boolean> = {
    'sarif-path': result.paths.sarifPath, 'json-path': result.paths.jsonPath, 'coverage-path': result.paths.coveragePath,
    'results-directory': result.paths.resultsDirectory, 'scan-status': result.scanStatus, 'policy-status': result.policyStatus,
    'report-status': result.reportStatus, 'exit-code': exitCode, 'scanned-sha': target.scannedSha,
    'analysis-ref': target.analysisRef, 'sarif-upload-ready': result.sarifUploadReady,
    'estimated-cost': result.estimatedCost ?? '',
  };
  for (const [level, count] of Object.entries(result.counts)) values[`${level}-count`] = count;
  for (const [key, value] of Object.entries(values)) core.setOutput(key, String(value));
}
function elapsed(started: number): string {
  const seconds = Math.floor((performance.now() - started) / 1000);
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}
function heartbeat(label: string, started: number): NodeJS.Timeout {
  const timer = setInterval(() => core.info(`${label} is still running; elapsed: ${elapsed(started)}.`), 30_000);
  timer.unref();
  return timer;
}

export async function runAction(actionRoot: string, overrides: Partial<Dependencies> = {}): Promise<void> {
  const deps = {setupRuntime, runProcess, cleanupRuntime, ...overrides};
  let inputs: Inputs | undefined;
  let target: Target | undefined;
  let runtime: Runtime | undefined;
  let tempRoot = '';
  let secrets: string[] = [];
  let success = false;
  let finalSummary = '';
  let finalTitle = 'Scan could not complete.';
  for (const name of OUTPUT_NAMES) core.setOutput(name, '');
  core.setOutput('scan-status', 'failed');
  core.setOutput('policy-status', 'not-evaluated');
  core.setOutput('report-status', 'failed');
  core.setOutput('sarif-upload-ready', 'false');
  try {
    const apiKey = process.env.OPENAI_API_KEY || process.env.CODEX_API_KEY || '';
    secrets = [apiKey].filter(Boolean);
    for (const secret of secrets) core.setSecret(secret);
    inputs = parseInputs(name => core.getInput(name), process.env.GITHUB_WORKSPACE ?? '');
    const event = await context();
    validateEvent(event);
    target = await resolveTarget(inputs, event);
    core.setOutput('scanned-sha', target.scannedSha);
    core.setOutput('analysis-ref', target.analysisRef);
    if (target.emptyDiff && !inputs.dryRun) {
      core.setOutput('scan-status', 'skipped');
      core.setOutput('skip-reason', 'empty-diff');
      core.setOutput('report-status', 'ready');
      success = true;
      finalTitle = 'No committed changes to scan';
      finalSummary = 'The requested diff is empty. No scan ran and no model cost was incurred.';
      core.info(finalSummary);
    } else {
      if (!inputs.dryRun && (!apiKey || /[\r\n\u0000]/.test(apiKey))) throw new Error('Set CODEX_SECURITY_API_KEY in Actions secrets (or Dependabot secrets for Dependabot runs) and pass it as OPENAI_API_KEY to this step. No scan was started.');
      tempRoot = await realpath(process.env.RUNNER_TEMP ?? '');
      if (!process.env.RUNNER_TEMP) throw new Error('RUNNER_TEMP is required.');
      core.info(`Preparing Codex Security ${SUPPORTED_CLI_VERSION}. Scope: ${inputs.scope}; mode: ${inputs.mode}; effort: ${inputs.effort}.`);
      const preparationStarted = performance.now();
      let timer = heartbeat('CLI preparation', preparationStarted);
      try { runtime = await deps.setupRuntime({actionRoot, tempRoot, log: core.info}); }
      finally { clearInterval(timer); }
      core.info(`CLI preparation completed in ${elapsed(preparationStarted)}.`);
      core.saveState('runtime-root', runtime.root);
      core.saveState('runtime-temp-root', tempRoot);
      const args = scanArguments(inputs, target, runtime.resultsDirectory, runtime.pythonPath);
      const log = (message: string): void => {
        for (const line of safeLogLines(message, secrets)) core.info(line);
      };
      log(`Target commit: ${target.scannedSha}.${target.diffBase ? ` Diff: ${target.diffBase}..${target.diffHead}.` : ''}`);
      if (inputs.paths.length) log(`Paths: ${inputs.paths.join(', ')}.`);
      log(`Model: ${inputs.model}; estimated cost stop threshold: ${inputs.maxCost === undefined ? 'unset' : `$${inputs.maxCost}`}; findings failure threshold: ${inputs.failOnSeverity}.`);
      const scanLabel = inputs.dryRun ? 'CLI configuration validation' : 'Security scan';
      const scanStarted = performance.now();
      core.info(`Starting ${scanLabel.toLowerCase()}. CLI diagnostics: ${inputs.verbose ? 'streaming' : 'disabled (verbose: false)'}.`);
      timer = heartbeat(scanLabel, scanStarted);
      let execution;
      try {
        execution = await deps.runProcess(runtime.nodePath, [runtime.cliPath, ...args], {
          cwd: target.repository, env: inputs.dryRun ? runtimeEnvironment(runtime) : runtime.env(apiKey),
          timeoutMs: 6 * 60 * 60 * 1000, maxOutputBytes: 4 * 1024 * 1024, maxStdoutBytes: Infinity, secrets,
          // Stream bounded, sanitized stderr; structured stdout stays private.
          log: inputs.verbose ? core.info : undefined,
        });
      } finally { clearInterval(timer); }
      core.info(`${scanLabel} exited after ${elapsed(scanStarted)}; exit code: ${execution.exitCode}${execution.signal ? `; signal: ${execution.signal}` : ''}${execution.timedOut ? '; timed out' : ''}${execution.interrupted ? '; interrupted' : ''}.`);
      core.setOutput('exit-code', String(execution.exitCode));
      const interrupted = execution.interrupted || execution.timedOut || !!execution.signal;
      if (inputs.dryRun) {
        if (execution.exitCode !== 0 || interrupted) throw new Error(`CLI configuration validation failed. ${inputs.verbose ? 'See the CLI diagnostics above.' : 'Set verbose: true for bounded, redacted diagnostics.'}`);
        core.setOutput('scan-status', 'skipped');
        core.setOutput('skip-reason', 'dry-run');
        core.setOutput('report-status', 'ready');
        success = true;
        finalTitle = 'Configuration validated; no security scan performed';
        finalSummary = 'Dry-run validated local CLI configuration without credentials. It did not verify authentication/model access, scan code, or evaluate findings. Use a separate configuration job, never the production required security check.';
        core.info(finalSummary);
      } else {
        core.info('Checking the checkout and preparing CLI results for GitHub.');
        let checkoutError = '';
        try { await resolveTarget(inputs, event); }
        catch { checkoutError = 'The source checkout changed during scanning. Results cannot establish a completed scan of the requested revision.'; }
        const resultOptions = {stdout: execution.stdout, resultsDirectory: runtime.resultsDirectory,
          exitCode: execution.exitCode, executionFailed: interrupted || !!checkoutError,
          publishable: target.publishable && !interrupted && !checkoutError};
        let result = await analyzeResults(resultOptions);
        if (result.paths.jsonPath && !result.paths.sarifPath && !interrupted && !checkoutError) {
          core.info('Producing a SARIF export from the validated scan.');
          try {
            const exported = await deps.runProcess(runtime.nodePath, [runtime.cliPath, ...exportSarifArgs(runtime.resultsDirectory, target.repository, join(runtime.resultsDirectory, 'exports/results.sarif')), '--python', runtime.pythonPath], {
              cwd: target.repository, env: runtimeEnvironment(runtime), timeoutMs: 60_000, secrets,
              log: inputs.verbose ? core.info : undefined,
            });
            if (exported.exitCode === 0 && !exported.interrupted && !exported.timedOut && !exported.signal)
              result = await analyzeResults({...resultOptions, sarifExported: true});
          } catch { log('SARIF export could not run; retaining the scan result.'); }
        }
        if (result.paths.jsonPath && !result.paths.sarifPath)
          core.warning('SARIF report is unavailable; scan results and other reports are still available.');
        if (checkoutError) result.errors.unshift(checkoutError);
        if (interrupted) result.errors.unshift('Scan was interrupted or exceeded its execution limit. Available findings are provisional.');
        try {
          const reports = await collectReports(result, secrets);
          if (inputs.uploadArtifacts) {
            core.info('Uploading validated report artifacts.');
            await uploadReports(reports, inputs, tempRoot);
          }
        } catch (error) {
          result.reportStatus = 'failed';
          result.sarifUploadReady = false;
          result.errors.push(plain(error instanceof Error ? error.message : 'Report publication failed.', secrets));
          // Withhold all report paths after credential/containment/upload failure.
          result.paths = {resultsDirectory: '', manifestPath: '', jsonPath: '', coveragePath: '', sarifPath: ''};
        }
        outputs(result, target, execution.exitCode);
        core.info(`Scan: ${result.scanStatus}; findings policy: ${result.policyStatus}; report: ${result.reportStatus}; SARIF upload ready: ${result.sarifUploadReady}.`);
        core.info(`${result.scanStatus === 'completed' ? 'Findings' : 'Provisional findings'}: ${Object.entries(result.counts).map(([level, count]) => `${level}: ${count}`).join(', ')}.`);
        core.info(`Estimated cost: ${result.estimatedCost === undefined ? 'unavailable' : `$${result.estimatedCost.toFixed(4)}`}.`);
        for (const error of result.errors.slice(0, 10)) log(`Report diagnostic: ${error}`);
        finalSummary = resultSummary(result, inputs, target, secrets);
        if (inputs.annotations) emitAnnotations(result, secrets);
        success = result.reportStatus !== 'failed' && (result.scanStatus === 'incomplete' ||
          (result.scanStatus === 'completed' && result.policyStatus === 'passed'));
        finalTitle = resultTitle(result, inputs);
        if (success && result.scanStatus === 'incomplete')
          core.warning('Scan coverage is partial. Available findings are provisional; the findings policy was not evaluated. Review the deferred work in the reports.');
      }
    }
  } catch (error) {
    const message = plain(error instanceof Error ? error.message : 'Unexpected action failure.', secrets, 2000);
    finalSummary = `<pre>${message.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/@/g, '&#64;')}</pre>`;
    core.setOutput('sarif-upload-ready', 'false');
    core.error(message);
  } finally {
    if (runtime) {
      try { await deps.cleanupRuntime(runtime.root, tempRoot); }
      catch {
        success = false;
        finalTitle += ' Runtime cleanup failed.';
        finalSummary += '\n\nTemporary runtime cleanup failed; inspect this dedicated runner before reuse.';
        core.setOutput('report-status', 'failed');
        core.setOutput('sarif-upload-ready', 'false');
      }
    }
    if (inputs?.summary !== false) {
      try { await core.summary.addRaw(`## Codex Security\n\n**${finalTitle}**\n\n${finalSummary}`).write(); }
      catch { core.warning('Could not write the job summary.'); }
    }
    if (success) core.info(finalTitle);
    else core.setFailed(`${finalTitle} See the job summary and logs for details.`);
  }
}
