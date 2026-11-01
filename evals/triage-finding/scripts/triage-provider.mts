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
    apiKey: string | undefined,
    cleanupGeneration: number,
  ): Promise<{
    activeInstance: { exec: { executablePath: string; pathDirs: string[] } };
  }>;
  callApiInternal(
    prompt: Parameters<ApiProvider["callApi"]>[0],
    context: Parameters<ApiProvider["callApi"]>[1],
    options: Parameters<ApiProvider["callApi"]>[2],
    config: ProviderOptions["config"],
    inIsolatedWorkspace: boolean,
    cleanupGeneration: number,
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

const wrappedProviders = new WeakSet<CodexProvider>();
const explicitProviders = new WeakSet<ApiProvider>();

function usesTriageRuntime(provider: CodexProvider) {
  return (
    explicitProviders.has(provider) ||
    provider.config?.working_dir === undefined ||
    provider.config?.cli_config?.default_permissions ===
      "triage_runtime_only" ||
    provider.config?.cli_config?.default_permissions ===
      "sastbench_runtime_only"
  );
}

// Promptfoo 0.124.1 exposes these private methods after per-case rendering and
// SDK selection. Keep the native loader, authentication, and lifecycle intact.
export function initializeProvider(provider: CodexProvider) {
  for (let target = provider; target; target = Object.getPrototypeOf(target)) {
    if (wrappedProviders.has(target)) return;
  }
  const getInstance = provider.getCodexInstanceForTurn;
  provider.getCodexInstanceForTurn = async function (
    this: CodexProvider,
    environment,
    config,
    apiKey,
    cleanupGeneration,
  ) {
    const instance = await getInstance.call(
      this,
      environment,
      config,
      apiKey,
      cleanupGeneration,
    );
    if (!usesTriageRuntime(this)) return instance;
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
          JSON.parse(readFileSync(packageJson, "utf8")).name === "@openai/codex"
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
  const callApiInternal = provider.callApiInternal;
  // The pinned Codex provider merges prompt overrides and renders case
  // variables before this call. Keep that upstream behavior for each case.
  provider.callApiInternal = function (
    this: CodexProvider,
    prompt,
    context,
    options,
    config,
    ...lifecycle
  ) {
    if (!usesTriageRuntime(this)) {
      return callApiInternal.call(
        this,
        prompt,
        context,
        options,
        config,
        ...lifecycle,
      );
    }
    const runtimeRoot = process.env.TRIAGE_RUNTIME_ROOT;
    if (!runtimeRoot) {
      throw new Error("Run this evaluation through scripts/run-promptfoo.mts.");
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
    return callApiInternal.call(
      this,
      prompt,
      context,
      options,
      {
        ...config,
        working_dir: runtimeRoot,
        cli_env: { ...config.cli_env, CODEX_MCP_NODE_PATH: nodeCommand },
        additional_directories: [
          ...(config.additional_directories ?? []),
          path.dirname(nodePath),
          path.dirname(nodeCommand),
        ],
      },
      ...lifecycle,
    );
  };
  wrappedProviders.add(provider);
}

// Older saved evaluations still load this hook during retry and resume.
export function beforeAll({ suite }: { suite: { providers: ApiProvider[] } }) {
  for (const apiProvider of suite.providers) {
    const provider = apiProvider as CodexProvider;
    if (
      typeof provider.getCodexInstanceForTurn !== "function" ||
      typeof provider.callApiInternal !== "function"
    )
      continue;
    explicitProviders.add(provider);
    initializeProvider(provider);
  }
}
