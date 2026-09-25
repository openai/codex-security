import * as core from '@actions/core';
import type { Inputs } from './inputs.js';
import type { Target } from './targets.js';
import type { ScanResults } from './results.js';

export function plain(value: string, secrets: readonly string[] = [], limit = 6000): string {
  let text = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '');
  for (const secret of secrets.filter(Boolean)) {
    for (const form of [secret, Buffer.from(secret).toString('base64'), encodeURIComponent(secret)]) text = text.split(form).join('[REDACTED]');
  }
  return text.slice(0, limit);
}
function html(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/@/g, '&#64;');
}
export function resultTitle(result: ScanResults, inputs: Inputs): string {
  if (result.scanStatus === 'incomplete') return result.reportStatus === 'failed'
    ? 'Scan coverage is partial, and required reporting failed.'
    : 'Scan coverage is partial. Available findings are provisional.';
  if (result.scanStatus !== 'completed') return 'Scan could not complete. Available findings are provisional.';
  if (result.reportStatus === 'failed') return 'Scan completed, but required reporting failed.';
  if (result.policyStatus === 'failed') return 'Scan completed. Findings meet the configured failure threshold.';
  if (inputs.failOnSeverity === 'none') return 'Scan completed. Findings are reported without failing the job.';
  return 'Scan completed. No findings meet the failure threshold.';
}
export function resultSummary(result: ScanResults, inputs: Inputs, target: Target, secrets: readonly string[] = []): string {
  const esc = (value: string, limit = 4000) => html(plain(value, secrets, limit));
  const counts = Object.entries(result.counts).map(([level, count]) => `${level}: ${count}`).join(' · ');
  const parts = [
    `**Scan:** ${result.scanStatus} · **Findings policy:** ${result.policyStatus} · **Report:** ${result.reportStatus}`,
    `**Findings:** ${counts}`,
    `**Scope:** ${inputs.scope}${inputs.paths.length ? ` <code>${esc(inputs.paths.join(', '))}</code>` : ''} · **Mode:** ${inputs.mode}`,
    `**Commit:** <code>${target.scannedSha}</code>`,
    `**Model:** <code>${esc(inputs.model)}</code> · **Reasoning effort:** ${inputs.effort}`,
    `**Failure threshold:** ${inputs.failOnSeverity === 'none' ? 'report-only findings' : inputs.failOnSeverity + ' and above'}. Valid partial scans warn without evaluating this policy. Scanner errors, unknown coverage, and required reporting errors fail the action.`,
    ...(inputs.maxCost !== undefined ? [`**Stop threshold:** $${inputs.maxCost} (estimated; in-flight requests can exceed it)`] : []),
    'Applicable root and nested SECURITY.md policy is discovered by the scanner.',
  ];
  if (result.reportStatus === 'partial') parts.push('SARIF report is unavailable; scan results and other reports are still available.');
  if (result.scanStatus === 'incomplete') parts.push('Partial coverage alone does not fail the job. The findings policy was not evaluated; review the deferred work before treating the security review as complete.');
  if (result.scanStatus !== 'completed') parts.push('**Findings below are provisional. This is not a completed scan.**');
  for (const error of result.errors.slice(0, 10)) parts.push(`<pre>${esc(error)}</pre>`);
  for (const finding of result.findings.slice(0, 30)) {
    parts.push(`<h3>${finding.severity.toUpperCase()}: ${esc(finding.title, 200)}</h3>\n\n<code>${esc(finding.path ?? 'No source location')}:${finding.startLine ?? '?'}</code>\n\n<pre>${esc(finding.summary, 1200)}</pre>`);
  }
  if (result.findings.length > 30) parts.push(`${result.findings.length - 30} additional findings are available in the JSON/SARIF reports.`);
  parts.push('Use the action outputs for full JSON, coverage, and SARIF. Upload SARIF only when sarif-upload-ready is true. Reports can contain source code and vulnerability details.');
  // GitHub check output is byte bounded. Truncate at UTF-8 boundaries.
  return Buffer.from(parts.join('\n\n')).subarray(0, 58_000).toString('utf8').replace(/\uFFFD$/, '');
}

export function emitAnnotations(result: ScanResults, secrets: readonly string[]): void {
  for (const finding of result.findings.slice(0, 50)) {
    const message = plain(`${result.scanStatus === 'completed' ? '' : 'Provisional finding: '}${finding.summary}`, secrets, 4000);
    const props = {title: plain(`${finding.severity.toUpperCase()}: ${finding.title}`, secrets, 200), file: finding.path,
      startLine: finding.startLine, endLine: finding.endLine};
    core.warning(message, props);
  }
  if (result.findings.length > 50) core.notice('Additional findings are available in the job summary and reports.');
}
