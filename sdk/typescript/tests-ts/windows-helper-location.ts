import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { parse } from "node:path";

export function windowsLoopbackPath(path: string): string {
  const root = parse(path).root;
  return `\\\\localhost\\${root[0]}$\\${path.slice(root.length)}`;
}

export const hasWindowsLoopbackShare =
  process.platform === "win32" && existsSync(windowsLoopbackPath(tmpdir()));
