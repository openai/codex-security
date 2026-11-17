import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, join } from "node:path";
import { PluginBootstrapError } from "./errors.js";
import { campaignExecutable } from "./trusted-executable.js";

export function definedEnvironment(
  environment: Readonly<NodeJS.ProcessEnv>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

/** Bind the native launch after the packaged SDK tools have been added to PATH. */
export async function nativeCodexLaunch(
  command: string,
  inherited?: Record<string, string>,
) {
  const environment =
    inherited && bundledCodexSdkEnvironment(command, inherited);
  const campaign = campaignExecutable(command, environment ?? process.env);
  if (!campaign) return { command, environment };
  const selected = await campaign;
  return {
    command: selected.executable,
    environment: definedEnvironment({
      ...selected.environment,
      CODEX_CLI_PATH: selected.executable,
    }),
  };
}

export function bundledCodexSdkEnvironment(
  command: string,
  environment: Record<string, string>,
): Record<string, string> {
  // An SDK executable override disables its bundled-tool PATH setup.
  let toolsDirectory: string;
  try {
    toolsDirectory = join(
      dirname(dirname(realpathSync.native(command))),
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
  let vendor: string;
  let entries;
  let legacyVendor = false;
  try {
    const selectedPackageJson =
      codexPackageJson ??
      createRequire(import.meta.url).resolve("@openai/codex/package.json");
    let packageJson: string;
    try {
      packageJson = createRequire(selectedPackageJson).resolve(
        `${packageName}/package.json`,
      );
    } catch (error) {
      if (codexPackageJson === undefined) throw error;
      packageJson = selectedPackageJson;
      legacyVendor = true;
    }
    vendor = join(dirname(packageJson), "vendor");
    entries = readdirSync(vendor, { withFileTypes: true });
  } catch (error) {
    throw new PluginBootstrapError(
      `The bundled Codex executable could not be resolved from ${packageName}. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
      { cause: error },
    );
  }
  const architecture = process.arch === "arm64" ? "aarch64" : "x86_64";
  const legacyTarget = `${architecture}-${platform === "darwin" ? "apple-darwin" : platform === "win32" ? "pc-windows-msvc" : "unknown-linux-musl"}`;
  const target = entries.find(
    (entry) =>
      entry.isDirectory() && (!legacyVendor || entry.name === legacyTarget),
  );
  const targetRoot = join(vendor, target?.name ?? "");
  const binaryName = process.platform === "win32" ? "codex.exe" : "codex";
  let command = join(targetRoot, "bin", binaryName);
  if (codexPackageJson !== undefined && !existsSync(command))
    command = join(targetRoot, "codex", binaryName);
  if (target === undefined || !existsSync(command)) {
    throw new PluginBootstrapError(
      `The ${packageName} package does not contain the Codex executable. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
    );
  }
  return command;
}
