import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { isRecord, safeSourcePath, assertSafeSarif } from './sarif.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ScanStatus = 'completed' | 'incomplete' | 'failed' | 'skipped';
export type PolicyStatus = 'passed' | 'failed' | 'not-evaluated';
export type ReportStatus = 'ready' | 'partial' | 'failed';
export interface Finding {
  severity: Severity;
  title: string;
  summary: string;
  path?: string;
  startLine?: number;
  endLine?: number;
}
export interface ResultOptions {
  stdout: string;
  resultsDirectory: string;
  scannedSha: string;
  exitCode: number | null;
  executionFailed?: boolean;
  publishable: boolean;
}
export interface ResultPaths {
  resultsDirectory: string;
  manifestPath: string;
  jsonPath: string;
  coveragePath: string;
  sarifPath: string;
}
export interface ScanResults {
  scanStatus: ScanStatus;
  policyStatus: PolicyStatus;
  reportStatus: ReportStatus;
  findings: Finding[];
  counts?: Record<Severity, number>;
  estimatedCost?: number;
  paths: ResultPaths;
  errors: string[];
  sarifUploadReady: boolean;
}

const REPORT_FILES = new Set(['scan-manifest.json', 'findings.json', 'coverage.json', 'exports/results.sarif']);

/** Access only owned report files after the scanner exits; never follow links. */
async function processReportFile(root: string, name: string, adapt?: (bytes: Buffer) => Buffer): Promise<Buffer> {
  if (!REPORT_FILES.has(name)) throw new Error('Unsupported report filename.');
  const absoluteRoot = resolve(root);
  if (await realpath(absoluteRoot) !== absoluteRoot) throw new Error('Report root must be canonical and cannot contain symlinks.');
  const rootInfo = await lstat(absoluteRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('Report root is not a directory.');
  const components = name.split('/');
  let directory = absoluteRoot;
  for (const part of components.slice(0, -1)) {
    directory = join(directory, part);
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(directory) !== directory) throw new Error('Report directory contains a symlink or non-directory.');
  }
  const path = join(absoluteRoot, name);
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) throw new Error('Report must be a regular file without links.');
  const file = await open(path, (adapt ? constants.O_RDWR : constants.O_RDONLY) | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await file.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error('Report changed while opening.');
    const bytes = await file.readFile();
    const after = await file.stat();
    if (bytes.length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        await realpath(path) !== path) throw new Error('Report changed while reading.');
    const prepared = adapt ? adapt(bytes) : bytes;
    if (!prepared.equals(bytes)) {
      let offset = 0;
      while (offset < prepared.length) {
        const { bytesWritten } = await file.write(prepared, offset, prepared.length - offset, offset);
        if (!bytesWritten) throw new Error('Report could not be rewritten.');
        offset += bytesWritten;
      }
      await file.truncate(prepared.length);
    }
    return prepared;
  } finally { await file.close(); }
}

export async function readReportFile(root: string, name: string): Promise<Buffer> {
  return processReportFile(root, name);
}

async function prepareSarif(root: string): Promise<void> {
  await processReportFile(root, 'exports/results.sarif', (bytes) => {
    const sarif: unknown = JSON.parse(bytes.toString('utf8'));
    assertSafeSarif(sarif);
    // upload-sarif applies its category only when automationDetails is absent.
    // The CLI's scan UUID must not override the workflow's stable scope category.
    if (isRecord(sarif) && Array.isArray(sarif.runs)) {
      for (const run of sarif.runs) if (isRecord(run)) delete run.automationDetails;
    }
    return Buffer.from(JSON.stringify(sarif));
  });
}

// Consume only the fields needed for GitHub reporting. The CLI owns the report contract.
export async function analyzeResults(options: ResultOptions): Promise<ScanResults> {
  const result: ScanResults = { scanStatus: 'failed', policyStatus: 'not-evaluated', reportStatus: 'failed', findings: [],
    paths: { resultsDirectory: '', manifestPath: '', jsonPath: '', coveragePath: '', sarifPath: '' }, errors: [],
    sarifUploadReady: false };
  let value: any;
  try {
    value = JSON.parse(options.stdout);
    if (isRecord(value) && value.status === 'failed' && typeof value.message === 'string') {
      result.errors.push(value.message);
      return result;
    }
    if (!value?.manifest?.scan?.target || !Array.isArray(value?.findings?.findings) || !value?.coverage)
      throw new Error();
  } catch {
    result.errors.push('CLI did not return a usable JSON scan result. See the CLI diagnostics.');
    return result;
  }
  if (value.scanDir !== options.resultsDirectory) {
    result.errors.push('CLI report directory does not match the private output directory.');
    return result;
  }
  const target = value.manifest.scan.target;
  const revision = target.kind === 'git_diff' ? target.headRevision : target.kind === 'git_revision' ? target.revision : undefined;
  if (revision !== options.scannedSha) {
    result.errors.push('CLI scan revision does not match the requested checkout commit.');
    return result;
  }
  try {
    result.findings = value.findings.findings.map((finding: any): Finding => {
      const location = finding.locations.find((item: any) => item.role === 'root_control') ?? finding.locations[0];
      if (location && (!safeSourcePath(location.path) || !Number.isSafeInteger(location.startLine) || location.startLine < 1 ||
          (location.endLine !== undefined && (!Number.isSafeInteger(location.endLine) || location.endLine < location.startLine))))
        throw new Error('CLI finding has an unsafe source location for GitHub annotations.');
      return {title: finding.title, summary: finding.summary, severity: finding.severity.level as Severity,
        path: location?.path, startLine: location?.startLine, endLine: location?.endLine ?? location?.startLine};
    });
  } catch (error) {
    result.errors.push((error as Error).message);
    return result;
  }
  result.counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const finding of result.findings) result.counts[finding.severity] += 1;
  result.estimatedCost = value.cost?.estimatedUsd;
  result.paths = {resultsDirectory: options.resultsDirectory, manifestPath: join(options.resultsDirectory, 'scan-manifest.json'),
    jsonPath: join(options.resultsDirectory, 'findings.json'), coveragePath: join(options.resultsDirectory, 'coverage.json'), sarifPath: ''};
  const warnings: string[] = value.warnings ?? [];
  // The CLI includes target-change warnings in result data even when it exits 2.
  // Those and failed execution must not become warning-only partial scans.
  if (options.executionFailed || value.manifest.scan.status !== 'completed' || warnings.length > 0) {
    result.errors.push('CLI did not complete successfully. See the CLI diagnostics.');
  } else if (value.coverage.completeness === 'partial' && (options.exitCode === 0 || options.exitCode === 2)) {
    result.scanStatus = 'incomplete';
  } else if (value.coverage.completeness === 'complete' && (options.exitCode === 0 || options.exitCode === 1)) {
    result.scanStatus = 'completed';
    result.policyStatus = options.exitCode === 1 ? 'failed' : 'passed';
  } else result.errors.push(value.coverage.completeness === 'unknown'
    ? 'CLI could not determine scan coverage. See the CLI diagnostics.'
    : 'CLI did not complete successfully. See the CLI diagnostics.');
  if (value.coverage.completeness !== 'complete') {
    for (const item of Array.isArray(value.coverage.deferred) ? value.coverage.deferred : []) if (typeof item?.reason === 'string') result.errors.push(`Deferred work: ${item.reason}`);
    for (const item of Array.isArray(value.coverage.surfaces) ? value.coverage.surfaces : []) if (item?.disposition === 'needs_follow_up' && typeof item.label === 'string')
      result.errors.push(`Needs follow-up: ${item.label}`);
  }
  result.errors.push(...warnings);
  const sarifPath = join(options.resultsDirectory, 'exports/results.sarif');
  if (value.sarifPath != null) {
    try {
      if (value.sarifPath !== sarifPath) throw new Error('SARIF path is outside the expected report location.');
      await prepareSarif(options.resultsDirectory);
      result.paths.sarifPath = sarifPath;
    } catch { result.errors.push('SARIF report is missing, unsafe, or unreadable.'); }
  }
  result.reportStatus = result.paths.sarifPath ? 'ready' : 'partial';
  result.sarifUploadReady = result.scanStatus === 'completed' && result.reportStatus === 'ready' && options.publishable;
  return result;
}
