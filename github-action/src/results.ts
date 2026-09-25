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
  exitCode: number | null;
  executionFailed?: boolean;
  publishable: boolean;
  sarifExported?: boolean;
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
  counts: Record<Severity, number>;
  estimatedCost?: number;
  paths: ResultPaths;
  errors: string[];
  sarifUploadReady: boolean;
}

const REPORT_FILES = new Set(['scan-manifest.json', 'findings.json', 'coverage.json', 'exports/results.sarif']);
const LEVELS: readonly Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];

/** Read only owned report files after the scanner exits; never follow links. */
export async function readReportFile(root: string, name: string): Promise<Buffer> {
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
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await file.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error('Report changed while opening.');
    const bytes = await file.readFile();
    const after = await file.stat();
    if (bytes.length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        await realpath(path) !== path) throw new Error('Report changed while reading.');
    return bytes;
  } finally { await file.close(); }
}

// Consume only the fields needed for GitHub reporting. The CLI owns the report contract.
export async function analyzeResults(options: ResultOptions): Promise<ScanResults> {
  const result: ScanResults = { scanStatus: 'failed', policyStatus: 'not-evaluated', reportStatus: 'failed', findings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    paths: { resultsDirectory: '', manifestPath: '', jsonPath: '', coveragePath: '', sarifPath: '' }, errors: [],
    sarifUploadReady: false };
  let value: any;
  try {
    value = JSON.parse(options.stdout);
    if (isRecord(value) && value.status === 'failed' && typeof value.message === 'string') {
      result.errors.push(value.message);
      return result;
    }
    if (!isRecord(value) || !isRecord(value.manifest) || !isRecord(value.manifest.scan) ||
        !isRecord(value.manifest.scan.target) || !isRecord(value.findings) || !Array.isArray(value.findings.findings) ||
        !isRecord(value.coverage) || !['complete', 'partial', 'unknown'].includes(String(value.coverage.completeness)))
      throw new Error();
  } catch {
    result.errors.push('CLI did not return a usable JSON scan result. See the CLI diagnostics.');
    return result;
  }
  if (value.scanDir !== options.resultsDirectory) {
    result.errors.push('CLI report directory does not match the private output directory.');
    return result;
  }
  try {
    result.findings = value.findings.findings.map((finding: any): Finding => {
      if (!isRecord(finding) || typeof finding.title !== 'string' || typeof finding.summary !== 'string' ||
          !isRecord(finding.severity) || !LEVELS.includes(finding.severity.level as Severity) || !Array.isArray(finding.locations))
        throw new Error('CLI finding is missing fields needed for GitHub reporting.');
      const location = finding.locations[0];
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
  for (const finding of result.findings) result.counts[finding.severity] += 1;
  if (isRecord(value.cost) && typeof value.cost.estimatedUsd === 'number' && Number.isFinite(value.cost.estimatedUsd) && value.cost.estimatedUsd >= 0)
    result.estimatedCost = value.cost.estimatedUsd;
  result.paths = {resultsDirectory: options.resultsDirectory, manifestPath: join(options.resultsDirectory, 'scan-manifest.json'),
    jsonPath: join(options.resultsDirectory, 'findings.json'), coveragePath: join(options.resultsDirectory, 'coverage.json'), sarifPath: ''};
  const warnings = (Array.isArray(value.warnings) ? value.warnings : []).filter((warning: unknown): warning is string => typeof warning === 'string');
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
  if (options.sarifExported || value.sarifPath != null) {
    try {
      if (!options.sarifExported && value.sarifPath !== sarifPath) throw new Error('SARIF path is outside the expected report location.');
      assertSafeSarif(JSON.parse((await readReportFile(options.resultsDirectory, 'exports/results.sarif')).toString('utf8')));
      result.paths.sarifPath = sarifPath;
    } catch { result.errors.push('SARIF report is missing, unsafe, or unreadable.'); }
  }
  result.reportStatus = result.paths.sarifPath ? 'ready' : 'partial';
  result.sarifUploadReady = result.scanStatus === 'completed' && result.reportStatus === 'ready' && options.publishable &&
    ['git_revision', 'git_diff'].includes(String(value.manifest.scan.target.kind));
  return result;
}
