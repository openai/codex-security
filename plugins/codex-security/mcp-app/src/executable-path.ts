import { win32 } from "node:path";

export function executablePathForSpawn(command: string): string {
  if (process.platform !== "win32" || !win32.isAbsolute(command)) return command;
  // Root-relative paths still depend on the child's drive and working directory.
  const root = win32.parse(command).root;
  return root === "\\" || root === "/"
    ? command
    : win32.toNamespacedPath(command);
}
