import { accessSync, constants as fsConstants, existsSync, promises as fs, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, isAbsolute, join, resolve, win32 } from "node:path";
import { Codex } from "@openai/codex-sdk";
import {
  classifyCodexWorkerError,
  DeepScanNonRetryableError
} from "./errors.js";
import {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  deepScanPermissionProfileFallbackError,
  preflightDeepScanWorkerPermissionProfile
} from "./permission-profile-preflight.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";
import type {
  CodexWorkerDiagnostic,
  CodexWorkerExecutor,
  CodexWorkerRequest,
  CodexWorkerResult
} from "./types.js";

export interface CodexSdkWorkerModelSettings {
  model?: string;
  reasoningEffort?: string;
  artifactContext?: CodexSdkWorkerArtifactContext;
  parentSandbox?: DeepWorkerParentSandbox;
}

/** The coordinator supplies scan identity; worker tools never choose paths. */
export interface CodexSdkWorkerArtifactContext {
  pluginRoot: string;
  scanRoot: string;
  repoRoot: string;
  scanId: string;
  scope?: string;
  pythonCommand?: string;
}

export class CodexSdkWorkerExecutor implements CodexWorkerExecutor {
  constructor(private readonly modelSettings: CodexSdkWorkerModelSettings = {}) {}

  async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
    try {
      const parentSandbox = this.modelSettings.parentSandbox;
      if (!parentSandbox) {
        throw new DeepScanNonRetryableError(
          "Deep Scan cannot start a read-only worker without verified parent sandbox metadata."
        );
      }
      const workerProfile = workerPermissionProfile(parentSandbox);
      const configOverrides = workerPermissionProfileConfigOverrides(workerProfile);
      const originalCwd = process.cwd();
      const childEnv = await snapshotWorkerEnvironment();
      const codexPath = resolveCodexPath(
        childEnv,
        process.platform,
        process.arch,
        originalCwd
      );
      await preflightDeepScanWorkerPermissionProfile({
        codexPath,
        cwd: request.workingDirectory,
        profileId: DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
        configOverrides,
        expectedProfile: workerProfile,
        env: childEnv,
        signal: request.signal
      });
      const prompt = await fs.readFile(request.promptPath, "utf8");
      const codex = new Codex({
        codexPathOverride: codexPath,
        env: childEnv,
        config: {
          // The CLI can add effort levels before the pinned SDK widens ThreadOptions.
          ...(this.modelSettings.reasoningEffort
            ? { model_reasoning_effort: this.modelSettings.reasoningEffort }
            : {}),
          mcp_servers: {
            // Discovery workers use the bundled skills and artifacts, not the parent workbench MCP.
            // A disabled server still needs a valid transport while Codex resolves plugin configuration.
            "codex-security": { command: "node", enabled: false },
            ...this.compactArtifactServer(request)
          },
          ...workerSubagentConfig(request.subagents)
        },
        // Structured SDK config cannot preserve literal filesystem keys such as
        // ":root" or "/repo/.env"; raw overrides keep this inline TOML intact.
        configOverrides
      });
      const threadOptions = {
        ...(this.modelSettings.model ? { model: this.modelSettings.model } : {}),
        threadSource: "security_scan",
        approvalPolicy: "never",
        skipGitRepoCheck: true,
        workingDirectory: request.workingDirectory
      } as const;
      const thread = request.resumeThreadId
        ? codex.resumeThread(request.resumeThreadId, threadOptions)
        : codex.startThread(threadOptions);
      const input = request.resumeThreadId
        ? request.continuationPrompt ?? prompt
        : prompt;
      const controller = new AbortController();
      const forwardAbort = () => controller.abort(request.signal.reason);
      if (request.signal.aborted) {
        forwardAbort();
      } else {
        request.signal.addEventListener("abort", forwardAbort, { once: true });
      }

      try {
        const { events } = await thread.runStreamed(input, { signal: controller.signal });
        let finalResponse = "";
        let threadId: string | undefined;
        let turnCompleted = false;
        let lastStreamError: string | undefined;
        const diagnostics: CodexWorkerDiagnostic[] = [];
        for await (const event of events) {
          if (event.type === "thread.started") {
            threadId = event.thread_id;
            await request.onThreadStarted?.(threadId);
          } else if (event.type === "item.completed") {
            const fallbackError = event.item.type === "error"
              ? deepScanPermissionProfileFallbackError(event.item.message)
              : undefined;
            if (fallbackError) {
              controller.abort(fallbackError);
              throw fallbackError;
            }
            if (event.item.type === "agent_message") {
              finalResponse = event.item.text;
            } else {
              appendSafeItemDiagnostic(diagnostics, event.item);
            }
          } else if (event.type === "turn.completed") {
            turnCompleted = true;
            request.signal.removeEventListener("abort", forwardAbort);
            break;
          } else if (event.type === "turn.failed") {
            throw new Error(event.error.message);
          } else if (event.type === "error") {
            const fallbackError = deepScanPermissionProfileFallbackError(event.message);
            if (fallbackError) {
              controller.abort(fallbackError);
              throw fallbackError;
            }
            // Codex exec currently emits retry-in-progress notifications as error events.
            lastStreamError = event.message;
          }
        }
        if (!turnCompleted) {
          const detail = lastStreamError ? `: ${lastStreamError}` : "";
          throw new Error(`Codex worker stream ended before turn.completed${detail}`);
        }
        return {
          finalResponse,
          threadId: threadId ?? thread.id ?? undefined,
          ...(diagnostics.length > 0 ? { diagnostics } : {})
        };
      } finally {
        request.signal.removeEventListener("abort", forwardAbort);
      }
    } catch (error) {
      throw classifyCodexWorkerError(error);
    }
  }

  private compactArtifactServer(request: CodexWorkerRequest): Record<string, {
    command: string;
    args: string[];
    env: Record<string, string>;
    required: true;
    startup_timeout_sec: number;
    tool_timeout_sec: number;
  }> {
    const scan = this.modelSettings.artifactContext;
    if (!scan) return {};

    const assigned = request.artifactContext;
    if (!assigned) {
      throw new Error(
        "Deep Scan worker has no coordinator-bound artifact context."
      );
    }
    const expectedLayout = request.kind === "dedup" ? "reducer" : "worker";
    if (assigned.layout !== expectedLayout) {
      throw new Error(
        "Deep Scan worker artifact context does not match its assigned phase."
      );
    }
    if ((expectedLayout === "reducer") !== (assigned.deepReducer !== undefined)) {
      throw new Error(
        "Deep Scan reducer requires its coordinator-bound source assignments."
      );
    }

    return {
      // Keep every qualified worker tool within Codex's existing name limit.
      cs_artifacts: {
        command: process.execPath,
        args: [
          join(scan.pluginRoot, "mcp", "server.mjs"),
          "--artifact-writer",
          "--stdio"
        ],
        env: {
          CODEX_SECURITY_ARTIFACT_ROOT: assigned.root,
          CODEX_SECURITY_REPO_ROOT: scan.repoRoot,
          CODEX_SECURITY_ARTIFACT_LAYOUT: assigned.layout,
          CODEX_SECURITY_SCAN_ID: scan.scanId,
          CODEX_SECURITY_PLUGIN_ROOT: scan.pluginRoot,
          ...(scan.scope !== undefined
            ? { CODEX_SECURITY_SCOPE: scan.scope }
            : {}),
          ...(scan.pythonCommand !== undefined
            ? { CODEX_SECURITY_PYTHON_COMMAND: scan.pythonCommand }
            : {}),
          ...(assigned.deepReducer
            ? {
              CODEX_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify(
                assigned.deepReducer
              )
            }
            : {})
        },
        required: true,
        startup_timeout_sec: 180,
        tool_timeout_sec: 86_400
      }
    };
  }
}

function workerSubagentConfig(subagents: number) {
  return {
    // V1 counts children; V2 counts the root plus its children. Keeping its
    // feature disabled lets the model choose either runtime without rejecting
    // inherited agents.max_threads configuration.
    ...(subagents > 0 ? { agents: { max_threads: subagents } } : {}),
    features: {
      multi_agent_v2: {
        enabled: false,
        max_concurrent_threads_per_session: subagents + 1
      },
      ...(subagents === 0
        ? {
          // V1 rejects max_threads=0. Worker prompts request no children;
          // preserve host tool exclusions instead of weakening them.
          enable_fanout: false
        }
        : {})
    }
  };
}

type TomlValue = string | number | boolean | TomlObject;
type TomlObject = { [key: string]: TomlValue };

function workerPermissionProfile(
  sandbox: DeepWorkerParentSandbox
): TomlObject {
  const filesystemEntries: Array<[string, TomlValue]> = [[":root", "read"]];
  const seenFilesystemKeys = new Set<string>();

  for (const key of sandbox.filesystemDenies) {
    if (seenFilesystemKeys.has(key)) continue;
    seenFilesystemKeys.add(key);
    filesystemEntries.push([key, "deny"]);
  }

  if (sandbox.globScanMaxDepth !== undefined) {
    filesystemEntries.push(["glob_scan_max_depth", sandbox.globScanMaxDepth]);
  }

  return {
    extends: ":read-only",
    // Object.fromEntries preserves literal keys such as "__proto__" without
    // letting a denied path mutate the serializer object prototype.
    filesystem: Object.fromEntries(filesystemEntries) as TomlObject,
    network: { enabled: false }
  };
}

function workerPermissionProfileConfigOverrides(profile: TomlObject): string[] {
  return [
    `default_permissions=${tomlString(DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID)}`,
    `permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}=${tomlInlineValue(profile)}`
  ];
}

function tomlInlineValue(value: TomlValue): string {
  if (typeof value === "string") return tomlString(value);
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  return `{${Object.entries(value)
    .map(([key, entry]) => `${tomlKey(key)}=${tomlInlineValue(entry)}`)
    .join(",")}}`;
}

function tomlKey(value: string): string {
  return /^[A-Za-z0-9_-]+$/.test(value) ? value : tomlString(value);
}

function tomlString(value: string): string {
  return JSON.stringify(value).replace(/\u007f/g, "\\u007f");
}

/**
 * Convert SDK item failures into bounded classifications without retaining the
 * command, output, or paths carried by the event. Those fields can contain
 * repository contents and credentials, while the coordinator only needs the
 * reason a later deterministic artifact check failed.
 */
function appendSafeItemDiagnostic(
  diagnostics: CodexWorkerDiagnostic[],
  item: unknown
): void {
  if (!isRecord(item) || item.status !== "failed" || typeof item.type !== "string") return;
  if (item.type === "command_execution") {
    const output = typeof item.aggregated_output === "string" ? item.aggregated_output : "";
    if (isSandboxNamespaceExhaustion(output)) {
      appendUniqueDiagnostic(diagnostics, {
        code: "sandbox_namespace_exhausted",
        message: "Codex worker sandbox namespace creation failed (bwrap ENOSPC)."
      });
    }
    return;
  }
  if (item.type === "file_change") {
    appendUniqueDiagnostic(diagnostics, {
      code: "file_change_failed",
      message: "Codex worker file change failed."
    });
    return;
  }
  if (
    item.type === "mcp_tool_call"
    && (item.server === "cs_artifacts" || item.server === "codex_security_artifacts")
    && typeof item.tool === "string"
  ) {
    const reason = isRecord(item.result)
      ? "returned an error"
      : isRecord(item.error)
        ? "transport failed"
        : "failed";
    appendUniqueDiagnostic(diagnostics, {
      code: "artifact_tool_failed",
      message: `Codex worker artifact tool ${item.tool} ${reason}.`
    });
  }
}

function isSandboxNamespaceExhaustion(output: string): boolean {
  return /bwrap:\s*Creating new namespace failed:.*(?:ENOSPC|max_[a-z_]*_namespaces exceeded|Resource temporarily unavailable)/is
    .test(output);
}

function appendUniqueDiagnostic(
  diagnostics: CodexWorkerDiagnostic[],
  diagnostic: CodexWorkerDiagnostic
): void {
  if (!diagnostics.some((existing) => existing.code === diagnostic.code)) {
    diagnostics.push(diagnostic);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function snapshotWorkerEnvironment(): Promise<Record<string, string>> {
  const environment = Object.fromEntries(
    Object.entries(process.env)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
  ) as Record<string, string>;
  if (process.platform === "win32") {
    // process.env is case-insensitive on Windows; a plain object is not.
    // Keep its selected values while giving the child one spelling per key.
    for (const name of ["CODEX_CLI_PATH", "CODEX_HOME", "CODEX_MANAGED_PACKAGE_ROOT", "LOCALAPPDATA"]) {
      const value = process.env[name];
      for (const key of Object.keys(environment)) {
        if (key.toUpperCase() === name) delete environment[key];
      }
      if (value !== undefined) environment[name] = value;
    }
  }
  const codexHome = environment.CODEX_HOME;
  if (
    codexHome !== undefined
    && codexHome.length > 0
    && (!isAbsolute(codexHome) || isNativeWindowsRootRelativePath(codexHome))
  ) {
    // Keep the original home and credentials; only make the same path stable
    // after the worker switches cwd. Never create, copy, or mutate a home.
    // This runs before a worker cwd is passed to either child. realpath must
    // receive the original spelling; lexical resolve() would change
    // symlink/.. meaning.
    environment.CODEX_HOME = await fs.realpath(codexHome);
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  originalCwd: string = process.cwd()
): string {
  const searchPath = searchPathForPlatform(env, platform);
  const configured = environmentVariable(env, "CODEX_CLI_PATH", platform)?.trim();
  if (configured && (platform !== "win32" || !isWindowsAppsPath(configured))) {
    if (isBareCommandName(configured)) {
      const executableName = platform === "win32" && !configured.toLowerCase().endsWith(".exe")
        ? `${configured}.exe`
        : configured;
      const fromSearchPath = platform === "win32"
        ? configured === "codex" || configured === "codex.exe"
          ? resolveWindowsCodexFromSearchPath(searchPath, architecture, originalCwd)
          : resolveWindowsDirectFromSearchPath(searchPath, executableName, originalCwd)
        : resolveFromSearchPath(searchPath, executableName, originalCwd);
      if (fromSearchPath) return fromSearchPath;
    }
    return absoluteCodexPath(configured, platform, originalCwd);
  }

  if (platform !== "win32") {
    return resolveFromSearchPath(searchPath, "codex", originalCwd)
      ?? resolve(originalCwd, "codex");
  }

  const managedPackageRoot = environmentVariable(env, "CODEX_MANAGED_PACKAGE_ROOT", platform)?.trim();
  if (managedPackageRoot) {
    const managedBinary = resolveWindowsPackageBinary(
      absoluteCodexPath(managedPackageRoot, platform, originalCwd),
      architecture
    );
    if (managedBinary && !isWindowsAppsPath(managedBinary)) return managedBinary;
  }

  const pathBinary = resolveWindowsCodexFromSearchPath(
    searchPath,
    architecture,
    originalCwd
  );
  if (pathBinary) return pathBinary;

  const localAppData = environmentVariable(env, "LOCALAPPDATA", platform)?.trim();
  return resolveWindowsCachedBinary(
    localAppData ? absoluteCodexPath(localAppData, platform, originalCwd) : undefined
  ) ?? resolve(originalCwd, "codex.exe");
}

function searchPathForPlatform(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform
): string | undefined {
  if (platform !== "win32") return env.PATH?.trim() ? env.PATH : undefined;
  return Object.entries(env)
    .find(([name, value]) => name.toLowerCase() === "path" && value?.trim())?.[1];
}

function environmentVariable(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform
): string | undefined {
  const value = env[name];
  if (value !== undefined || platform !== "win32") return value;
  return Object.entries(env)
    .find(([key]) => key.toUpperCase() === name)?.[1];
}

function isBareCommandName(value: string): boolean {
  return !value.includes("/")
    && !value.includes("\\")
    && !/^[A-Za-z]:/.test(value);
}

function resolveFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteSearchDirectory(directory, originalCwd),
      executableName
    );
    if (isExecutableFile(candidate)) return candidate;
  }
  return undefined;
}

function resolveWindowsDirectFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteSearchDirectory(directory, originalCwd),
      executableName
    );
    if (!isWindowsAppsPath(candidate) && existsSync(candidate)) return candidate;
  }
  return undefined;
}

function resolveWindowsCodexFromSearchPath(
  searchPath: string | undefined,
  architecture: NodeJS.Architecture,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const absoluteDirectory = absoluteSearchDirectory(directory, originalCwd);
    const directBinary = join(absoluteDirectory, "codex.exe");
    if (!isWindowsAppsPath(directBinary) && existsSync(directBinary)) return directBinary;

    const packageRoot = join(absoluteDirectory, "node_modules", "@openai", "codex");
    const nativeBinary = resolveWindowsPackageBinary(packageRoot, architecture);
    if (nativeBinary && !isWindowsAppsPath(nativeBinary)) return nativeBinary;
  }
  return undefined;
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
}

function resolveWindowsCachedBinary(localAppData: string | undefined): string | undefined {
  const root = localAppData?.trim();
  if (!root) return undefined;

  const cacheRoot = join(root, "OpenAI", "Codex", "bin");
  let selected: { path: string; modifiedAt: number } | undefined;
  try {
    for (const entry of readdirSync(cacheRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^[a-f0-9]{8,128}$/iu.test(entry.name)) continue;
      const candidate = join(cacheRoot, entry.name, "codex.exe");
      let metadata: ReturnType<typeof statSync>;
      try {
        metadata = statSync(candidate);
      } catch {
        continue;
      }
      if (!metadata.isFile() || metadata.size === 0 || isWindowsAppsPath(candidate)) continue;
      if (
        !selected
        || metadata.mtimeMs > selected.modifiedAt
        || (metadata.mtimeMs === selected.modifiedAt && candidate > selected.path)
      ) {
        selected = { path: candidate, modifiedAt: metadata.mtimeMs };
      }
    }
  } catch {
    return undefined;
  }
  return selected?.path;
}

function isExecutableFile(value: string): boolean {
  try {
    if (!statSync(value).isFile()) return false;
    accessSync(value, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function absoluteSearchDirectory(directory: string, originalCwd: string): string {
  return resolve(originalCwd, directory || ".");
}

function absoluteCodexPath(
  value: string,
  platform: NodeJS.Platform,
  originalCwd: string
): string {
  if (platform === "win32" && isNativeWindowsRootRelativePath(value)) {
    // A rooted Windows path still depends on the original drive.
    return win32.resolve(originalCwd, value);
  }
  if (isAbsolute(value) || (platform === "win32" && win32.isAbsolute(value))) {
    return value;
  }
  return resolve(originalCwd, value);
}

function isNativeWindowsRootRelativePath(value: string): boolean {
  if (process.platform !== "win32") return false;
  const root = win32.parse(value).root;
  return root === "\\" || root === "/";
}

function resolveWindowsPackageBinary(
  packageRoot: string,
  architecture: NodeJS.Architecture
): string | undefined {
  const packageJson = join(packageRoot, "package.json");
  if (!existsSync(packageJson)) return undefined;

  const targetTriple = architecture === "arm64"
    ? "aarch64-pc-windows-msvc"
    : architecture === "x64"
      ? "x86_64-pc-windows-msvc"
      : undefined;
  if (!targetTriple) return undefined;

  try {
    const platformPackageJson = createRequire(packageJson)
      .resolve(`@openai/codex-win32-${architecture}/package.json`);
    const nativeBinary = join(
      dirname(platformPackageJson),
      "vendor",
      targetTriple,
      "bin",
      "codex.exe"
    );
    return existsSync(nativeBinary) ? nativeBinary : undefined;
  } catch {
    return undefined;
  }
}
