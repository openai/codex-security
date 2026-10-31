import { spawn } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import { CodexSecurityError } from "./errors.js";
import { inlineToml, type JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import {
  executablePathForSpawn,
  PLUGIN_NAME,
  runCodexCommand,
  type CodexCommand,
} from "./runtime.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import {
  nativePermissionPreflight,
  nativeProfileClient,
  withCodexPreflightLock,
} from "./provider-profile.js";

export interface DirectDeepScanOptions {
  codexOptions: CodexOptions & { nativeProfile?: string };
  preflightCommand: CodexCommand;
  pluginRoot: string;
  repository: string;
  scanDir: string;
  scanId: string;
  prompt: string;
  signal: AbortSignal;
}

// The stock SDK emits one flag per leaf, including literal dotted keys in order.
function sdkConfigFlags(config: JsonObject, prefix = ""): string[] {
  return Object.entries(config).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return isRecord(value) && Object.keys(value).length
      ? sdkConfigFlags(value, path)
      : [`${path}=${inlineToml(value)}`];
  });
}

// Older app-servers cannot read the scan's native configuration without first
// loading the caller's project. Keep their coordinator routing scoped to the
// settings supplied to exec; native policy still applies to the actual turn.
function suppliedParentRouting(
  overrides: readonly string[],
): JsonObject | undefined {
  const routing = new Map<string, string>();
  for (const override of overrides) {
    const key = override.slice(0, override.indexOf("="));
    if (/^(?:features|mcp_servers)(?:\.|$)/u.test(key))
      routing.set(key, override);
  }
  try {
    const config = parse([...routing.values()].join("\n")) as JsonObject;
    const servers = config["mcp_servers"];
    const owner = isRecord(servers) ? servers[PLUGIN_NAME] : undefined;
    // Even a supplied transport can inherit a machine-level direct opt-out.
    if (isRecord(owner) && !Array.isArray(owner["omit_tools_from"])) return;
    return config;
  } catch {
    // Leave overlapping or malformed TOML for exec's own parser.
    return undefined;
  }
}

/** Read the same native layers and CLI overrides as the parent before adding its tool. */
export async function readDeepScanParentConfig(
  options: Pick<
    DirectDeepScanOptions,
    "codexOptions" | "preflightCommand" | "scanDir" | "signal"
  > & { plugin?: { marketplacePath: string; pluginName: string } },
): Promise<JsonObject | undefined> {
  const { codexOptions, preflightCommand: command } = options;
  const config = codexOptions.config ?? {};
  // The provider-profile launcher emits whole top-level tables instead.
  const overrides =
    codexOptions.nativeProfile === undefined
      ? sdkConfigFlags(config)
      : (await nativeProfileClient()).profileConfigOverrides(config);
  const environment = bundledCodexSdkEnvironment(command.command, {
    ...codexOptions.env,
    ...(codexOptions.apiKey === undefined
      ? {}
      : { CODEX_API_KEY: codexOptions.apiKey }),
  });
  const configOverrides = [
    ...overrides,
    ...(codexOptions.configOverrides ?? []),
  ];
  // Subcommand help does not load a project. A global --cd is ignored by
  // older app-servers, so require support on the subcommand itself.
  const help = await runCodexCommand(
    command,
    ["app-server", "--cd", options.scanDir, "--help"],
    environment,
    undefined,
    options.signal,
  );
  if (!help.success || !/^\s*(?:-C,\s*)?--cd\s+<[^>\n]+>/mu.test(help.stdout))
    return options.plugin ? undefined : suppliedParentRouting(configOverrides);

  const native = await nativePermissionPreflight();
  return withCodexPreflightLock(environment, options.signal, () =>
    native.readDeepScanRuntimeConfig({
      codexPath: command.command,
      commandArgs: command.args,
      // The parent launcher inherits this directory and passes the scan via --cd.
      cwd: process.cwd(),
      configCwd: options.scanDir,
      configOverrides,
      env: environment,
      signal: options.signal,
      context: "parent-config",
      plugin: options.plugin,
    }),
  );
}

/** Keep direct dispatch scoped to the original SDK coordinator turn and MCP server. */
export function deepScanParentToolOverrides(
  config: JsonObject,
  pluginServers: Record<string, unknown>,
): string[] {
  const features = config["features"] ?? {};
  if (!isRecord(features)) return [];
  const mode = features["code_mode"];
  if (mode !== undefined && typeof mode !== "boolean" && !isRecord(mode))
    return [];
  const direct =
    (isRecord(mode) ? mode["direct_only_tool_namespaces"] : undefined) ?? [];
  if (!Array.isArray(direct)) return [];

  const owner = PLUGIN_NAME;
  const bare = "codex_security";
  const prefixed = "mcp__codex_security";
  let required = [prefixed, bare];
  const overrides: string[] = [];
  const configured = config["mcp_servers"];
  // Native registrations take precedence over the selected plugin's entries.
  const servers: Record<string, unknown> = {
    ...pluginServers,
    ...(isRecord(configured) ? configured : {}),
  };
  const ownerConfig = servers[owner];
  if (!isRecord(ownerConfig) || ownerConfig["enabled"] === false) return [];
  const omitted = ownerConfig["omit_tools_from"];
  if (Array.isArray(omitted) && omitted.includes("direct")) return [];
  // A raw transport or an existing omission leaf can be updated in place.
  // Adding a new registration would shadow a plugin's transport and policy.
  if (
    isRecord(configured) &&
    Object.hasOwn(configured, owner) &&
    (Array.isArray(omitted) ||
      typeof ownerConfig["command"] === "string" ||
      typeof ownerConfig["url"] === "string")
  ) {
    if (omitted != null && !Array.isArray(omitted)) return [];
    const surfaces = omitted ?? [];
    if (surfaces.includes("code_mode") && surfaces.includes("deferred"))
      return [];
    return [
      `mcp_servers.${owner}.omit_tools_from=${inlineToml([...new Set([...surfaces, "code_mode", "deferred"])])}`,
    ];
  }
  const option = features["non_prefixed_mcp_tool_names"];
  const enabled =
    option === true || (isRecord(option) && option["enabled"] === true);
  const selected = isRecord(option) ? option["server_names"] : undefined;
  function namespace(server: string): string {
    const name = server.replace(/[-.:@/]/gu, "_");
    const omitPrefix =
      enabled && (!Array.isArray(selected) || selected.includes(server));
    return omitPrefix || name.startsWith("mcp__") ? name : `mcp__${name}`;
  }
  const occupied = new Set(
    Object.entries(servers)
      .filter(
        ([server, settings]) =>
          server !== owner &&
          isRecord(settings) &&
          settings["enabled"] !== false &&
          (!Array.isArray(settings["enabled_tools"]) ||
            settings["enabled_tools"].length > 0),
      )
      .map(([server]) => namespace(server)),
  );
  const current = namespace(owner);
  if (occupied.has(current)) {
    const excluded = isRecord(mode) ? mode["excluded_tool_namespaces"] : null;
    const routed = Array.isArray(excluded) ? [...direct, ...excluded] : direct;
    // Moving the owner also renames its peers. Keep names that the caller
    // explicitly routed or excluded from Code Mode.
    if (
      current === bare ||
      occupied.has(bare) ||
      routed.some(
        (name) =>
          name === current ||
          (typeof name === "string" &&
            /^mcp__codex_security_[0-9a-f]{12}$/u.test(name)),
      ) ||
      (option != null && !enabled)
    )
      return [];
    overrides.push(
      `features.non_prefixed_mcp_tool_names=${inlineToml({
        enabled: true,
        server_names: [...(Array.isArray(selected) ? selected : []), owner],
      })}`,
    );
    required = [bare];
  } else if (occupied.has(prefixed) || occupied.has(bare)) {
    required = [current];
  }
  if (!required.every((name) => direct.includes(name))) {
    overrides.push(
      `features.code_mode.direct_only_tool_namespaces=${inlineToml([...new Set([...direct, ...required])])}`,
    );
  }
  return overrides;
}

// The direct coordinator records context but never calls a model itself.
export const DIRECT_DEEP_SCAN_CONTROL_USAGE = {
  input_tokens: 0,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 0,
} as const;

/** Run the same coordinator as the plugin, without a parent model turn. */
export async function* runDeepScan(
  options: DirectDeepScanOptions,
): AsyncGenerator<{
  type: string;
  [key: string]: unknown;
}> {
  const native = await import(
    pathToFileURL(
      join(options.pluginRoot, "mcp", "permission-profile-preflight.mjs"),
    ).href
  );
  const profile = await import(
    pathToFileURL(join(options.pluginRoot, "scripts", "codex_profile.mjs")).href
  );
  const configured = options.codexOptions;
  const command = options.preflightCommand;
  const environment = bundledCodexSdkEnvironment(command.command, {
    ...configured.env,
    ...(configured.apiKey === undefined
      ? {}
      : { CODEX_API_KEY: configured.apiKey }),
  });
  const session = (await withCodexPreflightLock(
    environment,
    options.signal,
    () =>
      native.prepareCliDeepScanSession({
        codexPath: command.command,
        commandArgs: command.args,
        cwd: options.scanDir,
        env: environment,
        configOverrides: [
          ...profile.profileConfigOverrides(configured.config ?? {}),
          ...(configured.configOverrides ?? []),
          // This session only records native context; workers keep their own snapshot.
          "features.plugins=false",
        ],
        signal: options.signal,
        prompt:
          options.prompt +
          "\n\nThe host runs this Deep Scan coordinator directly and owns finalization. This saved request supplies context for later follow-up; do not start a replacement scan.",
      }),
  )) as {
    threadId: string;
    model: string;
    reasoningEffort?: string;
    permissionProfile: unknown;
  };
  yield { type: "thread.started", thread_id: session.threadId };
  options.signal.throwIfAborted();
  const node = process.versions["bun"]
    ? await resolveTrustedExecutable("node", environment, [options.repository])
    : undefined;
  if (node === null)
    throw new CodexSecurityError("Node.js is not available on PATH.");
  const output = await runEngine(
    node?.executable ?? process.execPath,
    [join(options.pluginRoot, "mcp", "server.mjs"), "--deep-scan-engine"],
    node?.environment ?? environment,
    JSON.stringify({ scanId: options.scanId, ...session }),
    options.signal,
  );
  const completed = JSON.parse(output);
  if (
    completed.scanId !== options.scanId ||
    completed.manifestPath !== join(options.scanDir, "scan-manifest.json")
  ) {
    throw new CodexSecurityError(
      "Deep Scan engine returned results for a different scan.",
    );
  }
  // The control session makes no model calls. Worker usage is read by the
  // existing scan tracker from the native sessions below this scan directory.
  yield {
    type: "turn.completed",
    usage: { ...DIRECT_DEEP_SCAN_CONTROL_USAGE },
  };
}

function runEngine(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  request: string,
  signal: AbortSignal,
): Promise<string> {
  signal.throwIfAborted();
  const child = spawn(executablePathForSpawn(command), args, {
    env,
    windowsHide: true,
  });
  // EOF requests graceful coordinator/worker cleanup on Windows as well as Unix.
  // Keep the control pipe open until completion or explicit cancellation.
  const cancel = () => child.stdin.end();
  let stdout = "";
  let stderr = "";
  let processError: Error | undefined;
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  child.once("error", (error) => {
    processError = error;
  });
  child.stdin.on("error", (error: NodeJS.ErrnoException) => {
    if (
      !["EPIPE", "ECONNRESET", "EOF", "ERR_STREAM_DESTROYED"].includes(
        error.code ?? "",
      )
    )
      processError = error;
  });
  const result = new Promise<string>((resolve, reject) => {
    child.once("close", (code) => {
      signal.removeEventListener("abort", cancel);
      if (signal.aborted) reject(signal.reason);
      else if (processError) reject(processError);
      else if (code !== 0)
        reject(
          new CodexSecurityError(
            stderr.trim() || `Deep Scan engine exited with code ${code}.`,
          ),
        );
      else resolve(stdout);
    });
  });
  child.stdin.write(request + "\n");
  signal.addEventListener("abort", cancel, { once: true });
  if (signal.aborted) cancel();
  return result;
}
