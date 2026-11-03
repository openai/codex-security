import * as core from '@actions/core';
import { readFile, realpath } from 'node:fs/promises';
import { parseInputs, scanArguments, type Inputs } from './inputs.js';
import { resolveTarget, type EventContext, type Target } from './targets.js';
import { SUPPORTED_CLI_VERSION, setupRuntime, cleanupRuntime, runtimeEnvironment, scanCredentials, API_KEY_ENVIRONMENT_VARIABLES, type Runtime } from './runtime.js';
import { runProcess, safeLogLines } from './process.js';
import { analyzeResults, type ScanResults, type Severity } from './results.js';
import { collectReports, uploadReports } from './artifacts.js';
import { resultSummary, emitAnnotations, plain, resultTitle } from './reporting.js';

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

export const OUTPUT_NAMES = [
  'sarif-path', 'json-path', 'manifest-path', 'coverage-path', 'results-directory', 'scan-status', 'skip-reason',
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
  const payload: unknown = JSON.parse(await readFile(path, 'utf8'));
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid GitHub event payload.');
  return {eventName: process.env.GITHUB_EVENT_NAME ?? '', repository: process.env.GITHUB_REPOSITORY ?? '',
    sha: process.env.GITHUB_SHA ?? '', ref: process.env.GITHUB_REF ?? '',
    serverUrl: process.env.GITHUB_SERVER_URL ?? '', payload: payload as Record<string, unknown>};
}
function outputs(result: ScanResults, target: Target, exitCode: number): void {
  const values: Record<string, string | number | boolean> = {
    'sarif-path': result.paths.sarifPath, 'json-path': result.paths.jsonPath, 'coverage-path': result.paths.coveragePath, 'manifest-path': result.paths.manifestPath,
    'results-directory': result.paths.resultsDirectory, 'scan-status': result.scanStatus, 'policy-status': result.policyStatus,
    'report-status': result.reportStatus, 'exit-code': exitCode, 'scanned-sha': target.scannedSha,
    'analysis-ref': target.analysisRef, 'sarif-upload-ready': result.sarifUploadReady,
    'estimated-cost': result.estimatedCost ?? '',
  };
  for (const [level, count] of Object.entries(result.counts ?? {})) values[`${level}-count`] = count;
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
  let success = false;
  let finalSummary = '';
  let finalTitle = 'Scan could not complete.';
  for (const name of OUTPUT_NAMES) core.setOutput(name, '');
  core.setOutput('scan-status', 'failed');
  core.setOutput('policy-status', 'not-evaluated');
  core.setOutput('report-status', 'failed');
  core.setOutput('sarif-upload-ready', 'false');
  try {
    inputs = parseInputs(name => core.getInput(name), process.env.GITHUB_WORKSPACE ?? '');
    const credentials = scanCredentials(inputs.provider, process.env);
    const event = await context();
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
      if (!inputs.dryRun && credentials.provider !== 'amazon-bedrock' && (!credentials.apiKey || /[\r\n\u0000]/.test(credentials.apiKey))) {
        throw new Error(credentials.provider === 'openai'
          ? 'Set CODEX_SECURITY_API_KEY in Actions secrets (or Dependabot secrets for Dependabot runs) and pass it as OPENAI_API_KEY to this step. No scan was started.'
          : `Pass ${API_KEY_ENVIRONMENT_VARIABLES[credentials.provider]} from Actions secrets to this step. No scan was started.`);
      }
      if (!process.env.RUNNER_TEMP) throw new Error('RUNNER_TEMP is required.');
      tempRoot = await realpath(process.env.RUNNER_TEMP);
      core.info(`Preparing Codex Security ${SUPPORTED_CLI_VERSION}. Scope: ${inputs.scope}; mode: ${inputs.mode}; effort: ${inputs.effort}.`);
      const preparationStarted = performance.now();
      let timer = heartbeat('CLI preparation', preparationStarted);
      try {
        runtime = await deps.setupRuntime({actionRoot, tempRoot, repository: target.repository, provider: inputs.provider, model: inputs.model, log: inputs.verbose ? core.info : undefined});
      }
      finally { clearInterval(timer); }
      core.info(`CLI preparation completed in ${elapsed(preparationStarted)}.`);
      core.saveState('runtime-root', runtime.root);
      core.saveState('runtime-temp-root', tempRoot);
      const args = scanArguments(inputs, target, runtime.resultsDirectory);
      const log = (message: string): void => {
        for (const line of safeLogLines(message)) core.info(line);
      };
      log(`Target commit: ${target.scannedSha}.${target.diffBase ? ` Diff: ${target.diffBase}..${target.diffHead}.` : ''}`);
      if (inputs.paths.length) log(`Paths: ${inputs.paths.join(', ')}.`);
      log(`Model: ${inputs.model || '(not specified)'}; estimated cost stop threshold: ${inputs.maxCost === undefined ? 'unset' : `$${inputs.maxCost}`}; findings failure threshold: ${inputs.failOnSeverity}.`);
      if (inputs.cyberAccessProgram) log(`Requested Cyber access program: ${inputs.cyberAccessProgram}.`);
      const scanLabel = inputs.dryRun ? 'CLI configuration validation' : 'Security scan';
      const scanStarted = performance.now();
      core.info(`Starting ${scanLabel.toLowerCase()}. CLI diagnostics: ${inputs.verbose ? 'streaming' : 'disabled (verbose: false)'}.`);
      timer = heartbeat(scanLabel, scanStarted);
      let execution;
      try {
        execution = await deps.runProcess(runtime.nodePath, [runtime.cliPath, ...args], {
          cwd: target.repository, env: inputs.dryRun ? runtimeEnvironment(runtime) : runtime.env(credentials),
          // Stream stderr with terminal controls escaped; structured stdout is consumed below.
          log: inputs.verbose ? core.info : undefined,
        });
      } finally { clearInterval(timer); }
      core.info(`${scanLabel} exited after ${elapsed(scanStarted)}; exit code: ${execution.exitCode}${execution.signal ? `; signal: ${execution.signal}` : ''}${execution.timedOut ? '; timed out' : ''}${execution.interrupted ? '; interrupted' : ''}.`);
      core.setOutput('exit-code', String(execution.exitCode));
      const interrupted = execution.interrupted || execution.timedOut || !!execution.signal;
      if (inputs.dryRun) {
        if (execution.exitCode !== 0 || interrupted) throw new Error(`CLI configuration validation failed. ${inputs.verbose ? 'See the CLI diagnostics above.' : 'Set verbose: true for diagnostics.'}`);
        core.setOutput('scan-status', 'skipped');
        core.setOutput('skip-reason', 'dry-run');
        core.setOutput('report-status', 'ready');
        success = true;
        finalTitle = 'Configuration validated; no security scan performed';
        finalSummary = 'Dry-run validated local CLI configuration without credentials. It did not verify authentication/model access, scan code, or evaluate findings. Use a separate configuration job, never the production required security check.';
        core.info(finalSummary);
      } else {
        core.info('Preparing CLI results for GitHub.');
        let checkoutError = '';
        // The pinned CLI does not snapshot working-tree state for committed diff scans.
        if (inputs.scope === 'diff') {
          try { await resolveTarget(inputs, event); }
          catch { checkoutError = 'The source checkout changed during scanning. Results cannot establish a completed scan of the requested revision.'; }
        }
        const result = await analyzeResults({stdout: execution.stdout, resultsDirectory: runtime.resultsDirectory, scannedSha: target.scannedSha,
          exitCode: execution.exitCode, executionFailed: interrupted || !!checkoutError, publishable: target.publishable});
        if (result.paths.jsonPath && !result.paths.sarifPath)
          core.warning('SARIF report is unavailable; scan results and other reports are still available.');
        if (checkoutError) result.errors.unshift(checkoutError);
        if (interrupted) result.errors.unshift('Scan was interrupted or exceeded its execution limit.');
        let reportsValidated = false;
        let artifactUrl: string | undefined;
        try {
          const reports = await collectReports(result);
          reportsValidated = true;
          if (inputs.uploadArtifacts) {
            core.info('Uploading validated report artifacts.');
            const artifactId = await uploadReports(reports, inputs, tempRoot);
            if (artifactId !== undefined && process.env.GITHUB_RUN_ID)
              artifactUrl = `${event.serverUrl}/${event.repository}/actions/runs/${process.env.GITHUB_RUN_ID}/artifacts/${artifactId}`;
          }
        } catch (error) {
          result.reportStatus = 'failed';
          result.sarifUploadReady = false;
          result.errors.push(plain(error instanceof Error ? error.message : 'Report publication failed.'));
          // Keep local reports available when only the remote upload failed.
          if (!reportsValidated) result.paths = {resultsDirectory: '', manifestPath: '', jsonPath: '', coveragePath: '', sarifPath: ''};
        }
        outputs(result, target, execution.exitCode);
        core.info(`Scan: ${result.scanStatus}; findings policy: ${result.policyStatus}; report: ${result.reportStatus}; SARIF upload ready: ${result.sarifUploadReady}.`);
        core.info(`Findings: ${result.counts ? Object.entries(result.counts).map(([level, count]) => `${level}: ${count}`).join(', ') : 'unavailable'}.`);
        core.info(`Estimated cost: ${result.estimatedCost === undefined ? 'unavailable' : `$${result.estimatedCost.toFixed(4)}`}.`);
        for (const error of result.errors) log(`Report diagnostic: ${error}`);
        const displayResult = {
          ...result,
          findings: [...result.findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]),
        };
        finalSummary = resultSummary(displayResult, inputs, target, artifactUrl);
        if (inputs.annotations) emitAnnotations(displayResult);
        success = result.reportStatus !== 'failed' && result.scanStatus === 'completed' && result.policyStatus === 'passed';
        finalTitle = resultTitle(result, inputs);
      }
    }
  } catch (error) {
    const message = plain(error instanceof Error ? error.message : 'Unexpected action failure.');
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
    if (inputs?.summary ?? (core.getInput('summary') !== 'false')) {
      try { await core.summary.addRaw(`## Codex Security\n\n**${finalTitle}**\n\n${finalSummary}`).write(); }
      catch { core.warning('Could not write the job summary.'); }
    }
    if (success) core.info(finalTitle);
    else core.setFailed(`${finalTitle} See the job summary and logs for details.`);
  }
}
