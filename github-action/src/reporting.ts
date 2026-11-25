import * as core from '@actions/core';
import type { Inputs } from './inputs.ts';
import type { Target } from './targets.ts';
import type { ScanResults } from './results.ts';

export function plain(value: string, limit?: number): string {
  const text = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '');
  const prefix = text.slice(0, limit);
  // A two-unit code point starting at the last included unit spans the cut.
  const codePoint = text.codePointAt(prefix.length - 1);
  return codePoint !== undefined && codePoint > 0xffff ? prefix.slice(0, -1) : prefix;
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
export function resultSummary(result: ScanResults, inputs: Inputs, target: Target, artifactUrl?: string): string {
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
    ...(artifactUrl ? [`**Reports:** <a href="${html(artifactUrl)}">${esc(inputs.artifactName)}</a> · Retention: up to ${inputs.retentionDays} days.`] : []),
    `**Findings:** ${counts}`,
    `**Scope:** ${inputs.scope}${inputs.paths.length ? ` <code>${esc(inputs.paths.join(', '))}</code>` : ''} · **Mode:** ${inputs.mode}`,
    `**Commit:** <code>${target.scannedSha}</code>`,
    `**Configured provider:** <code>${esc(inputs.provider)}</code> · **Model:** <code>${esc(inputs.model)}</code> · **Reasoning effort:** ${inputs.effort}`,
    `**Tokens:** ${tokens} · **Estimated cost:** ${cost}`,
    `**Failure threshold:** ${inputs.failOnSeverity === 'none' ? 'report-only findings' : inputs.failOnSeverity + ' and above'}. Findings at or above the configured threshold fail the action. Scanner and required reporting errors also fail the action.`,
    ...(inputs.maxCost !== undefined ? [`**Stop threshold:** $${inputs.maxCost} (estimated; in-flight requests can exceed it)`] : []),
    'Applicable root and nested SECURITY.md policy is discovered by the scanner.',
  ];
  const statusNotes: string[] = [];
  if (result.reportStatus === 'partial') statusNotes.push('SARIF report is unavailable; scan results and other reports are still available.');
  if (result.scanStatus !== 'completed') statusNotes.push('**Scan execution failed. Retained findings are shown below; absence of findings is inconclusive.**');
  const ready = result.reportStatus === 'ready';
  const footer = (ready ? 'Use the action outputs for full JSON and SARIF.' : 'Check the action outputs for available reports.') +
    ' Upload SARIF only when sarif-upload-ready is true. Reports can contain source code and vulnerability details.';
  const omittedFindings = (count: number) =>
    `${count} additional ${count === 1 ? 'finding is' : 'findings are'} ${ready ? 'available in the JSON/SARIF reports' : 'omitted from this summary'}.`;
  const findingCount = result.findings.length;
  const maxBytes = 58_000;

  const render = (reserved: number) => {
    let remaining = maxBytes - reserved - Buffer.byteLength([...statusNotes, footer].join('\n\n'));
    // Each block precedes a separator, including the one before the footer.
    const fits = (block: string, separatorBytes = 2): boolean => {
      const bytes = Buffer.byteLength(block) + separatorBytes;
      if (bytes > remaining) return false;
      remaining -= bytes;
      return true;
    };
    // Keep a prefix of complete items. Lines within one list use a single newline.
    function take<T>(items: T[], format: (item: T, index: number) => string, separatorBytes = 2): string[] {
      const kept: string[] = [];
      for (const item of items) {
        const block = format(item, kept.length);
        if (!fits(block, kept.length ? separatorBytes : 2)) break;
        kept.push(block);
      }
      return kept;
    }
    const blocks = parts.filter(part => fits(part));
    // Budget diagnostics before scope notes without changing the display order.
    const errors = take(result.errors.slice(0, 10), error => `<pre>${esc(error)}</pre>`);
    const notes = take(result.scopeLimitations ?? [], (note, index) =>
      (index ? '' : '**Scope limitations**\n\n') + `- ${esc(note)}`, 1);
    const findings = take(result.findings.slice(0, 30), finding =>
      `<h3>${finding.severity.toUpperCase()}: ${esc(finding.title, 200)}</h3>\n\n<code>${esc(finding.path ?? 'No source location')}:${finding.startLine ?? '?'}</code>\n\n<pre>${esc(finding.summary, 1200)}</pre>`);
    if (notes.length) blocks.push(notes.join('\n'));
    blocks.push(...statusNotes, ...errors, ...findings);
    if (findings.length < findingCount) blocks.push(omittedFindings(findingCount - findings.length));
    return [...blocks, footer].join('\n\n');
  };

  // Reserve space for the largest omission notice only if the summary actually overflows.
  const summary = render(0);
  return Buffer.byteLength(summary) <= maxBytes ? summary : render(Buffer.byteLength(omittedFindings(findingCount)) + 2);
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
