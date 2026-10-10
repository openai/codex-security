import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, join } from "node:path";
import { PluginBootstrapError } from "./errors.js";

export function bundledCodexSdkEnvironment(
  command: string,
  environment: Record<string, string>,
): Record<string, string> {
  // An SDK executable override disables its bundled-tool PATH setup.
  let toolsDirectory: string;
  try {
    toolsDirectory = join(
      dirname(realpathSync.native(dirname(command))),
      "codex-path",
    );
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

export function resolveBundledCodexExecutable(
  codexPackageJson?: string,
): string {
  const platform = process.platform === "android" ? "linux" : process.platform;
  const packageName = `@openai/codex-${platform}-${process.arch}`;
  let packageJson: string;
  try {
    codexPackageJson ??= createRequire(import.meta.url).resolve(
      "@openai/codex/package.json",
    );
    packageJson = createRequire(codexPackageJson).resolve(
      `${packageName}/package.json`,
    );
  } catch (error) {
    throw new PluginBootstrapError(
      `The bundled Codex executable could not be resolved from ${packageName}. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
      { cause: error },
    );
  }
  const vendor = join(dirname(packageJson), "vendor");
  const target = readdirSync(vendor, { withFileTypes: true }).find((entry) =>
    entry.isDirectory(),
  );
  const command = join(
    vendor,
    target?.name ?? "",
    "bin",
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  if (target === undefined || !existsSync(command)) {
    throw new PluginBootstrapError(
      `The ${packageName} package does not contain the Codex executable. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
    );
  }
  return command;
}
