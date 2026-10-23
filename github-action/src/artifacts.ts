import { DefaultArtifactClient } from '@actions/artifact';
import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { readReportFile, type ScanResults } from './results.js';
import type { Inputs } from './inputs.js';

export async function collectReports(result: ScanResults): Promise<Map<string, Buffer>> {
  const reports = new Map<string, Buffer>();
  for (const [name, path] of [
    ['scan-manifest.json', result.paths.manifestPath], ['findings.json', result.paths.jsonPath],
    ['coverage.json', result.paths.coveragePath], ['exports/results.sarif', result.paths.sarifPath],
  ]) {
    if (!path) continue;
    const data = await readReportFile(result.paths.resultsDirectory, name);
    reports.set(name, data);
  }
  return reports;
}
export async function uploadReports(reports: Map<string, Buffer>, inputs: Inputs, tempRoot: string): Promise<void> {
  if (!reports.size) throw new Error('Artifact upload requested, but no validated reports are available.');
  const staging = await mkdtemp(join(tempRoot, 'codex-security-upload-'));
  await chmod(staging, 0o700);
  try {
    const files: string[] = [];
    for (const [name, bytes] of reports) {
      const dest = join(staging, name === 'exports/results.sarif' ? 'results.sarif' : name);
      await writeFile(dest, bytes, {mode: 0o600, flag: 'wx'});
      files.push(dest);
    }
    await new DefaultArtifactClient().uploadArtifact(inputs.artifactName, files, staging, {retentionDays: inputs.retentionDays, compressionLevel: 0});
  } finally { await rm(staging, {recursive: true, force: true}); }
}
