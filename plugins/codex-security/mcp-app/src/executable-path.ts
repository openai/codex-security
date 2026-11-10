import { accessSync, constants, statSync } from "node:fs";
import { win32 } from "node:path";

export function executablePathForSpawn(command: string): string {
  if (process.platform !== "win32" || !win32.isAbsolute(command))
    return command;
  // Root-relative paths still depend on the child's drive and working directory.
  const root = win32.parse(command).root;
  return root === "\\" || root === "/"
    ? command
    : win32.toNamespacedPath(command);
}

export function isExecutableFile(value: string): boolean {
  try {
    if (!statSync(value).isFile()) return false;
    accessSync(value, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function configuredExecutableValue(
  value: string | undefined,
  platform: NodeJS.Platform,
  literalIsExecutable: (value: string) => boolean,
): string | undefined {
  const trimmed = value?.trim();
  // Preserve conventional padding unless the literal POSIX name selects a file.
  if (!value || !trimmed || value === trimmed || platform === "win32")
    return trimmed;
  return literalIsExecutable(value) ? value : trimmed;
}
