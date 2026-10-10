import { lstat, readFile, realpath, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

export const MARKER = '.codex-security-action-owned';
export const ROOT_PREFIX = 'codex-security-runtime-';

export async function cleanupRuntime(root: string, tempRoot: string): Promise<void> {
  if (!isAbsolute(root) || !isAbsolute(tempRoot)) throw new Error('Cleanup requires absolute owned paths.');
  const base = await realpath(tempRoot);
  const info = await lstat(root).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (!info) return;
  const canonical = await realpath(root);
  const child = relative(base, canonical);
  if (!info.isDirectory() || info.isSymbolicLink() || dirname(canonical) !== base || !child.startsWith(ROOT_PREFIX) || child.includes(sep) || resolve(root) !== canonical) throw new Error('Refusing to clean a path outside the owned runtime root.');
  const marker = join(canonical, MARKER);
  if (!(await lstat(marker)).isFile() || await readFile(marker, 'utf8') !== 'codex-security-action-v1\n') throw new Error('Refusing to clean a directory without the ownership marker.');
  await rm(canonical, { recursive: true, force: false });
}
