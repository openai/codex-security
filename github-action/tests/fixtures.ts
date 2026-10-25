import { cp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function copyCompletedScan(destination: string): Promise<void> {
  await cp(new URL('./fixtures/completed-scan/', import.meta.url), destination, { recursive: true });
  for (const name of ['scan-manifest.json', 'findings.json', 'coverage.json']) {
    await cp(new URL(`../../plugins/codex-security/examples/completed-scan/${name}`, import.meta.url), join(destination, name));
  }
  const manifestPath = join(destination, 'scan-manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  Object.assign(manifest.scan.target, { kind: 'git_revision', revision: 'a'.repeat(40) });
  await writeFile(manifestPath, JSON.stringify(manifest));
}
