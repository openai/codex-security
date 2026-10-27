import * as core from '@actions/core';
import type { Inputs } from './inputs.js';
import type { Target } from './targets.js';
import type { ScanResults } from './results.js';

export function plain(value: string, limit?: number): string {
  const text = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '');
  return text.slice(0, limit);
}
function html(value: string): string {
  // Inline HTML still parses Markdown; entities keep report fields literal.
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/@/g, '&#64;').replace(/\r/g, '&#13;').replace(/\n/g, '&#10;')
    .replace(/[\\`*_\[\]~]/g, character => `&#${character.charCodeAt(0)};`);
}
export function resultTitle(result: ScanResults, inputs: Inputs): string {
  if (result.scanStatus !== 'completed') return 'Scan could not complete.';
  if (result.reportStatus === 'failed') return 'Scan completed, but required reporting failed.';
  if (result.policyStatus === 'failed') return 'Scan completed. Findings meet the configured failure threshold.';
  if (inputs.failOnSeverity === 'none') return 'Scan completed. Findings are reported without failing the job.';
  return 'Scan completed. No findings meet the failure threshold.';
}
export function resultSummary(result: ScanResults, inputs: Inputs, target: Target): string {
  const esc = (value: string, limit = 4000) => html(plain(value, limit));
  const counts = result.counts ? Object.entries(result.counts).map(([level, count]) => `${level}: ${count}`).join(' · ') : 'unavailable';
  const usage = result.usage;
  const tokens = usage ? `${usage.input_tokens.toLocaleString('en-US')} input (${usage.cached_input_tokens.toLocaleString('en-US')} cached) · ${usage.output_tokens.toLocaleString('en-US')} output` : 'unavailable';
  const range = result.estimatedCostRange;
  const cost = range && range.max !== range.min
    ? range.max === null ? `$${range.min.toFixed(4)} (upper estimate unavailable)` : `$${range.min.toFixed(4)}–$${range.max.toFixed(4)}`
    : result.estimatedCost === undefined ? 'unavailable' : `$${result.estimatedCost.toFixed(4)}`;
  const parts = [
    `**Scan:** ${result.scanStatus} · **Findings policy:** ${result.policyStatus} · **Report:** ${result.reportStatus}`,
    `**Findings:** ${counts}`,
    `**Scope:** ${inputs.scope}${inputs.paths.length ? ` <code>${esc(inputs.paths.join(', '))}</code>` : ''} · **Mode:** ${inputs.mode}`,
    `**Commit:** <code>${target.scannedSha}</code>`,
    `**Configured provider:** <code>${esc(inputs.provider)}</code> · **Model:** <code>${esc(inputs.model)}</code> · **Reasoning effort:** ${inputs.effort}`,
    `**Tokens:** ${tokens} · **Estimated cost:** ${cost}`,
    `**Failure threshold:** ${inputs.failOnSeverity === 'none' ? 'report-only findings' : inputs.failOnSeverity + ' and above'}. Findings at or above the configured threshold fail the action. Scanner and required reporting errors also fail the action.`,
    ...(inputs.maxCost !== undefined ? [`**Stop threshold:** $${inputs.maxCost} (estimated; in-flight requests can exceed it)`] : []),
    'Applicable root and nested SECURITY.md policy is discovered by the scanner.',
  ];
  if (result.reportStatus === 'partial') parts.push('SARIF report is unavailable; scan results and other reports are still available.');
  if (result.scanStatus !== 'completed') parts.push('**Scan execution failed. Retained findings are shown below; absence of findings is inconclusive.**');
  for (const error of result.errors.slice(0, 10)) parts.push(`<pre>${esc(error)}</pre>`);
  for (const finding of result.findings.slice(0, 30)) {
    parts.push(`<h3>${finding.severity.toUpperCase()}: ${esc(finding.title, 200)}</h3>\n\n<code>${esc(finding.path ?? 'No source location')}:${finding.startLine ?? '?'}</code>\n\n<pre>${esc(finding.summary, 1200)}</pre>`);
  }
  if (result.findings.length > 30) parts.push(`${result.findings.length - 30} additional findings are available in the JSON/SARIF reports.`);
  parts.push('Use the action outputs for full JSON and SARIF. Upload SARIF only when sarif-upload-ready is true. Reports can contain source code and vulnerability details.');
  // GitHub check output is byte bounded. Truncate at UTF-8 boundaries.
  return Buffer.from(parts.join('\n\n')).subarray(0, 58_000).toString('utf8').replace(/\uFFFD$/, '');
}

export function emitAnnotations(result: ScanResults): void {
  for (const finding of result.findings.slice(0, 50)) {
    const message = plain(finding.summary, 4000);
    const props = {title: plain(`${finding.severity.toUpperCase()}: ${finding.title}`, 200), file: finding.path,
      startLine: finding.startLine, endLine: finding.endLine};
    core.warning(message, props);
  }
  if (result.findings.length > 50) core.notice('Additional findings are available in the job summary and reports.');
}
