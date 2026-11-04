import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { parse } from "node:path";

export function windowsLoopbackPath(path: string): string {
  const root = parse(path).root;
  // File URLs normalize localhost to an empty host, which breaks Node ESM on UNC paths.
  return `\\\\127.0.0.1\\${root[0]}$\\${path.slice(root.length)}`;
}

export const hasWindowsLoopbackShare =
  process.platform === "win32" && existsSync(windowsLoopbackPath(tmpdir()));
