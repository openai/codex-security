import { constants } from "node:fs";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { resolveCodexProfile, type JsonObject } from "./config.js";
import { CodexSecurityError, IncompleteScanError } from "./errors.js";
import type { NormalizedTarget } from "./targets.js";

export const DEPENDENCY_GRAPH_FILE = "dependency-resolver-output.json";
export const DEPENDENCY_CALCULATION_MODEL = "gpt-5.6-luna";
export const DEPENDENCY_CALCULATION_EFFORT = "low";

export interface DependencyGraphSetup {
  repository: string;
  target: Pick<NormalizedTarget, "kind" | "paths" | "base" | "head">;
  targetRevision: string;
  snapshotDigest: string | null;
}

export function parseDependencyGraphSetup(
  value: unknown,
): DependencyGraphSetup {
  if (
    !isRecord(value) ||
    typeof value["repository"] !== "string" ||
    typeof value["targetRevision"] !== "string" ||
    !(
      value["snapshotDigest"] === null ||
      typeof value["snapshotDigest"] === "string"
    )
  ) {
    throw new CodexSecurityError(
      "Dependency calculation returned an invalid target snapshot.",
    );
  }
  const target = value["target"];
  if (
    !isRecord(target) ||
    !["repository", "paths", "refs", "working_tree"].includes(
      String(target["kind"]),
    ) ||
    !Array.isArray(target["paths"]) ||
    !target["paths"].every(
      (path): path is string => typeof path === "string",
    ) ||
    ((target["kind"] === "refs" || target["kind"] === "working_tree") &&
      (typeof target["base"] !== "string" ||
        typeof target["head"] !== "string"))
  ) {
    throw new CodexSecurityError(
      "Dependency calculation returned an invalid target scope.",
    );
  }
  return {
    repository: value["repository"],
    target: {
      kind: target["kind"] as NormalizedTarget["kind"],
      paths: [...new Set(target["paths"])].sort(),
      ...(typeof target["base"] === "string" ? { base: target["base"] } : {}),
      ...(typeof target["head"] === "string" ? { head: target["head"] } : {}),
    },
    targetRevision: value["targetRevision"],
    snapshotDigest: value["snapshotDigest"],
  };
}

export function sameDependencyGraphSetup(
  left: DependencyGraphSetup,
  right: DependencyGraphSetup,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function parseDependencyDepthCounts(value: unknown): number[] {
  if (
    !isRecord(value) ||
    !Array.isArray(value["depthCounts"]) ||
    !value["depthCounts"].every(
      (count): count is number =>
        typeof count === "number" && Number.isSafeInteger(count) && count >= 0,
    )
  ) {
    throw new IncompleteScanError(
      "Dependency calculation did not return valid depthCounts.",
    );
  }
  return value["depthCounts"];
}

export async function saveDependencyGraphSetup(
  graphPath: string,
  setup: DependencyGraphSetup,
  depthCounts: number[],
  signal: AbortSignal,
): Promise<void> {
  await requireDependencyGraph(graphPath);
  await writeFile(
    `${graphPath}.setup.json`,
    `${JSON.stringify({ ...setup, depthCounts })}\n`,
    {
      mode: 0o600,
      flag: "wx",
      signal,
    },
  );
}

export async function reusableDependencyGraph(
  graphPath: string,
  setup: DependencyGraphSetup,
  signal?: AbortSignal,
): Promise<{ depthCounts: number[]; dependencyGraphPath: string }> {
  const saved: unknown = JSON.parse(
    await readFile(`${graphPath}.setup.json`, { encoding: "utf8", signal }),
  );
  if (!sameDependencyGraphSetup(parseDependencyGraphSetup(saved), setup)) {
    throw new CodexSecurityError(
      "Saved dependency graph no longer matches the repository, scope, or snapshot.",
    );
  }
  await requireDependencyGraph(graphPath);
  signal?.throwIfAborted();
  return {
    depthCounts: parseDependencyDepthCounts(saved),
    dependencyGraphPath: graphPath,
  };
}

export async function stageDependencyGraph(
  graphPath: string,
  scanDir: string,
  repository: string,
  target: NormalizedTarget,
  registration: Record<string, unknown>,
  signal: AbortSignal,
): Promise<void> {
  const contract = registration["contract"];
  const contractTarget = isRecord(contract) ? contract["target"] : undefined;
  const diff = isRecord(contract) ? contract["diffTarget"] : undefined;
  const scope = isRecord(contract) ? contract["scope"] : undefined;
  const isDiff = target.kind === "refs" || target.kind === "working_tree";
  const setup = parseDependencyGraphSetup({
    repository,
    target: {
      kind: target.kind,
      paths: isDiff
        ? []
        : isRecord(scope)
          ? scope["requiredIncludePaths"]
          : undefined,
      ...(isDiff && isRecord(diff)
        ? { base: diff["baseRevision"], head: diff["headRevision"] }
        : {}),
    },
    targetRevision: registration["targetRevision"],
    snapshotDigest: isDiff
      ? isRecord(diff)
        ? (diff["contentDigest"] ?? null)
        : null
      : isRecord(contractTarget)
        ? (contractTarget["requiredSnapshotDigest"] ?? null)
        : null,
  });
  // A repository-wide contract uses ["."]; its normalized CLI target uses [].
  if (setup.target.kind === "repository") setup.target.paths = [];
  await reusableDependencyGraph(graphPath, setup, signal);
  signal.throwIfAborted();
  const destination = join(
    scanDir,
    "artifacts",
    "02_discovery",
    "dependency-update-scan",
    DEPENDENCY_GRAPH_FILE,
  );
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await copyFile(graphPath, destination, constants.COPYFILE_EXCL);
  signal.throwIfAborted();
}

export async function dependencyCalculationPrompt(
  pluginRoot: string,
  setup: DependencyGraphSetup,
  dependencyGraphPath: string,
): Promise<string> {
  const modulePath = join(
    pluginRoot,
    "skills",
    "dependency-resolution",
    "dependency-calculation-prompt.mjs",
  );
  const { buildDependencyCalculationPrompt } = (await import(
    pathToFileURL(modulePath).href
  )) as {
    buildDependencyCalculationPrompt(options: {
      targetPath: string;
      scopePaths: readonly string[];
      setup: Record<string, unknown>;
      dependencyGraphPath: string;
    }): string;
  };
  const target = setup.target;
  const isDiff = target.kind === "refs" || target.kind === "working_tree";
  return buildDependencyCalculationPrompt({
    targetPath: setup.repository,
    scopePaths: target.paths,
    dependencyGraphPath,
    setup: {
      targetPath: setup.repository,
      scope: target.paths.length === 1 ? target.paths[0] : ".",
      mode: isDiff ? "dependency_update" : "full_dependency",
      ...(isDiff
        ? {
            diffTarget: {
              kind: target.kind === "refs" ? "range" : "working_tree",
              baseRevision: target.base,
              headRevision: target.head,
              ...(setup.snapshotDigest === null
                ? {}
                : { contentDigest: setup.snapshotDigest }),
            },
          }
        : {}),
    },
  });
}

export function dependencyCalculationConfig(
  model: string,
  reasoningEffort: string,
  effectiveConfig: JsonObject,
): JsonObject {
  effectiveConfig = resolveCodexProfile(effectiveConfig);
  const disabledFeatures: JsonObject = {
    plugins: false,
    apps: false,
    enable_fanout: false,
    multi_agent: false,
    multi_agent_v2: { enabled: false },
  };
  const mcpServers: JsonObject = {};
  const configuredServers = effectiveConfig["mcp_servers"];
  if (isRecord(configuredServers)) {
    for (const [name, server] of Object.entries(configuredServers)) {
      if (isRecord(server)) {
        mcpServers[name] = { ...(server as JsonObject), enabled: false };
      }
    }
  }
  mcpServers["codex-security"] ??= { command: "node", enabled: false };
  const config: JsonObject = {
    ...effectiveConfig,
    model,
    model_reasoning_effort: reasoningEffort,
    allow_login_shell: false,
    default_permissions: "codex_security_dependency_calculation",
    permissions: {
      ...(isRecord(effectiveConfig["permissions"])
        ? (effectiveConfig["permissions"] as JsonObject)
        : {}),
      codex_security_dependency_calculation: {
        filesystem: { ":root": "read", ":workspace_roots": "write" },
        network: { enabled: false },
      },
    },
    features: {
      ...(isRecord(effectiveConfig["features"])
        ? (effectiveConfig["features"] as JsonObject)
        : {}),
      ...disabledFeatures,
    },
    mcp_servers: mcpServers,
    orchestrator: {
      ...(isRecord(effectiveConfig["orchestrator"])
        ? (effectiveConfig["orchestrator"] as JsonObject)
        : {}),
      mcp: { enabled: false },
      skills: { enabled: false },
    },
    web_search: "disabled",
  };
  delete config["sandbox_mode"];
  return config;
}

export async function requireDependencyGraph(path: string): Promise<void> {
  if (!(await stat(path)).isFile()) {
    throw new IncompleteScanError(
      "Dependency calculation did not save its native resolver output.",
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
