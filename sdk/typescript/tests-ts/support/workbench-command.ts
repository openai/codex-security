import { runWorkbench } from "../../src/runtime.js";
import { PLUGIN_ROOT } from "../plugin-root.js";

export function workbenchCommand(
  python: string,
  environment: string | (() => NodeJS.ProcessEnv),
) {
  if (typeof environment === "string")
    return workbenchCommand(python, () => ({
      PATH: process.env["PATH"],
      CODEX_SECURITY_STATE_DIR: environment,
    }));
  return (args: readonly string[], input?: string) =>
    runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment: environment() },
      args,
      input,
    );
}

export function scanRegistrationArguments(
  repository: string,
  scanDirectory: string,
): string[] {
  return [
    "register-cli-scan",
    "--repository",
    repository,
    "--scan-dir",
    scanDirectory,
    "--recipe-json",
    JSON.stringify({
      config: {},
      mode: "standard",
      repository,
      target: { kind: "repository", paths: [] },
    }),
  ];
}
