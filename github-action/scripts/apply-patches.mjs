import { execFileSync, spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const patches = (await readdir(resolve(root, 'patches'))).filter(name => name.endsWith('.patch')).sort();
const options = { cwd: resolve(root, '..') };
for (const name of patches) {
  const patch = resolve(root, 'patches', name);
  const args = ['apply', '--directory=' + basename(root)];
  // Builds and tests can run consecutively against the same installation.
  if (spawnSync('git', [...args, '--reverse', '--check', patch], options).status === 0) continue;
  execFileSync('git', [...args, patch], { ...options, stdio: 'inherit' });
}
