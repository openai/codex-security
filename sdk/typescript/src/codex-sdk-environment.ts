import { statSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";

export function bundledCodexSdkEnvironment(
  command: string,
  environment: Record<string, string>,
): Record<string, string> {
  // An SDK executable override disables its bundled-tool PATH setup.
  const toolsDirectory = join(dirname(dirname(command)), "codex-path");
  try {
    if (!statSync(toolsDirectory).isDirectory()) return environment;
  } catch {
    return environment;
  }
  const result = { ...environment };
  const pathKeys = Object.keys(result).filter((key) =>
    process.platform === "win32"
      ? key.toLowerCase() === "path"
      : key === "PATH",
  );
  const pathKey = pathKeys.includes("Path")
    ? "Path"
    : (pathKeys.at(-1) ?? "PATH");
  for (const key of pathKeys) {
    if (key !== pathKey) delete result[key];
  }
  const entries = (result[pathKey] ?? "")
    .split(delimiter)
    .filter((entry) => entry.length > 0 && entry !== toolsDirectory);
  result[pathKey] = [toolsDirectory, ...entries].join(delimiter);
  return result;
}
