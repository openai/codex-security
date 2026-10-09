import { execFileSync } from "node:child_process";
import {
  accessSync,
  constants,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";
import type { ApiProvider, ProviderOptions } from "promptfoo";
import {
  bundledCodexSdkEnvironment,
  resolveBundledCodexExecutable,
} from "../../../sdk/typescript/dist/codex-sdk-environment.js";

type CodexProvider = ApiProvider & {
  getCodexInstanceForTurn(
    environment: NodeJS.ProcessEnv,
    config: ProviderOptions["config"],
    apiKey?: string,
  ): Promise<{
    activeInstance: { exec: { executablePath: string; pathDirs: string[] } };
  }>;
  callApiInternal(
    prompt: Parameters<ApiProvider["callApi"]>[0],
    context: Parameters<ApiProvider["callApi"]>[1],
    options: Parameters<ApiProvider["callApi"]>[2],
    config: ProviderOptions["config"],
  ): ReturnType<ApiProvider["callApi"]>;
};

function resolveCommand(
  command: string,
  cwd: string,
  environment: NodeJS.ProcessEnv,
) {
  if (
    command.includes("/") ||
    (process.platform === "win32" && command.includes("\\"))
  )
    return process.platform === "win32"
      ? path.resolve(cwd, command)
      : path.isAbsolute(command)
        ? command
        : `${cwd}/${command}`;
  if (process.platform === "win32") {
    return execFileSync(
      path.join(process.env.SystemRoot!, "System32", "where.exe"),
      [command],
      { cwd, env: environment, encoding: "utf8" },
    )
      .trim()
      .split(/\r?\n/)[0];
  }
  for (const directory of (environment.PATH ?? "/usr/bin:/bin").split(
    path.delimiter,
  )) {
    const candidate = `${path.isAbsolute(directory) ? directory : `${cwd}/${directory}`}/${command}`;
    try {
      accessSync(candidate, constants.X_OK);
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // Continue the same executable search used by native spawn.
    }
  }
  throw new Error(`Executable not found on PATH: ${command}`);
}

const wrappedProviders = new WeakSet<ApiProvider>();

// Keep native provider loading and authentication unchanged. Bind the staged
// runtime after Promptfoo has created each provider for this evaluation.
export function beforeAll({ suite }: { suite: { providers: ApiProvider[] } }) {
  for (const apiProvider of suite.providers) {
    const provider = apiProvider as CodexProvider;
    if (
      typeof provider.getCodexInstanceForTurn !== "function" ||
      wrappedProviders.has(provider)
    )
      continue;
    const getInstance = provider.getCodexInstanceForTurn.bind(provider);
    provider.getCodexInstanceForTurn = async (environment, config, apiKey) => {
      const instance = await getInstance(environment, config, apiKey);
      // The pinned provider exposes its selected SDK executor before creating
      // thread options. Extend this call's config without changing selection
      // or the SDK's bundled-tool PATH handling.
      const { executablePath, pathDirs } = instance.activeInstance.exec;
      const executable = realpathSync.native(
        resolveCommand(executablePath, process.cwd(), environment),
      );
      const directories = [path.dirname(executable), ...pathDirs];
      if (path.basename(executable) === "codex.js") {
        try {
          const packageJson = path.join(
            path.dirname(executable),
            "..",
            "package.json",
          );
          if (
            JSON.parse(readFileSync(packageJson, "utf8")).name ===
            "@openai/codex"
          ) {
            const native = resolveBundledCodexExecutable(packageJson);
            directories.push(
              path.dirname(native),
              ...Object.values(bundledCodexSdkEnvironment(native, {})),
            );
          }
        } catch {
          // Other launcher layouts keep their configured directories and
          // report their own dependency errors when the SDK starts them.
        }
      }
      config.additional_directories = [
        ...(config.additional_directories ?? []),
        ...directories,
      ];
      return instance;
    };
    const callApiInternal = provider.callApiInternal.bind(provider);
    // The pinned Codex provider merges prompt overrides and renders case
    // variables before this call. Keep that upstream behavior for each case.
    provider.callApiInternal = (prompt, context, options, config) => {
      const runtimeRoot = process.env.TRIAGE_RUNTIME_ROOT;
      if (!runtimeRoot) {
        throw new Error(
          "Run this evaluation through scripts/run-promptfoo.mts.",
        );
      }
      const requestedNode =
        (config.cli_env?.CODEX_MCP_NODE_PATH ??
          process.env.CODEX_MCP_NODE_PATH ??
          process.execPath) ||
        process.execPath;
      const environment = { ...process.env, ...config.cli_env };
      let nodeCommand: string;
      try {
        nodeCommand = resolveCommand(requestedNode, runtimeRoot, environment);
        accessSync(
          nodeCommand,
          process.platform === "win32" ? constants.F_OK : constants.X_OK,
        );
      } catch {
        nodeCommand = resolveCommand("node", runtimeRoot, environment);
      }
      const nodePath =
        process.platform === "win32"
          ? realpathSync(nodeCommand)
          : realpathSync.native(nodeCommand);
      return callApiInternal(prompt, context, options, {
        ...config,
        working_dir: runtimeRoot,
        cli_env: { ...config.cli_env, CODEX_MCP_NODE_PATH: nodeCommand },
        additional_directories: [
          ...(config.additional_directories ?? []),
          path.dirname(nodePath),
          path.dirname(nodeCommand),
        ],
      });
    };
    wrappedProviders.add(provider);
  }
}
