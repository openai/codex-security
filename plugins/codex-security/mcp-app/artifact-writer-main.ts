import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  canonicalDirectory,
  defined,
  type ArtifactContext,
  type DeepReducerContext,
} from "./src/artifact-context.js";
import { CODEX_SANDBOX_STATE_META_CAPABILITY } from "./src/deep-scan/parent-sandbox.js";
import { registerCompactWorkerArtifactTools } from "./src/server/compact-artifact-tools.js";
import { version as MCP_APP_VERSION } from "./package.json";
import { isRecord } from "./src/record.js";

/** Build the narrow worker-only MCP from coordinator-inherited state. */
export async function createCodexSecurityArtifactWriterServer(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<McpServer> {
  const root = requiredEnvironment(environment, "CODEX_SECURITY_ARTIFACT_ROOT");
  const repoRoot = requiredEnvironment(environment, "CODEX_SECURITY_REPO_ROOT");
  const layout = environment.CODEX_SECURITY_ARTIFACT_LAYOUT ?? "worker";
  if (layout !== "worker" && layout !== "reducer") {
    throw new Error(
      "CODEX_SECURITY_ARTIFACT_LAYOUT must be worker or reducer.",
    );
  }

  const deepReducer = environment.CODEX_SECURITY_REDUCER_CONTEXT_JSON
    ? parseReducerContext(environment.CODEX_SECURITY_REDUCER_CONTEXT_JSON)
    : undefined;

  if ((layout === "reducer") !== (deepReducer !== undefined)) {
    throw new Error(
      "A reducer worker requires exactly its coordinator-bound reducer context.",
    );
  }

  /**
   * Bind a lightweight worker to host-supplied state, never model-supplied paths.
   */
  const scanId = environment.CODEX_SECURITY_SCAN_ID
    ? environment.CODEX_SECURITY_SCAN_ID
    : undefined;
  const scope = environment.CODEX_SECURITY_SCOPE
    ? environment.CODEX_SECURITY_SCOPE
    : undefined;
  const pluginRoot = environment.CODEX_SECURITY_PLUGIN_ROOT
    ? environment.CODEX_SECURITY_PLUGIN_ROOT
    : undefined;
  const pythonCommand = environment.CODEX_SECURITY_PYTHON_COMMAND
    ? environment.CODEX_SECURITY_PYTHON_COMMAND
    : undefined;
  // Preserve the asynchronous context boundary before server construction.
  const context: ArtifactContext = await (async () => ({
    root: await canonicalDirectory(root, "Codex Security worker artifact root"),
    repoRoot: await canonicalDirectory(
      repoRoot,
      "Codex Security worker target root",
    ),
    layout,
    ...defined("scanId", scanId),
    ...defined("scope", scope),
    ...defined("pluginRoot", pluginRoot),
    ...defined("pythonCommand", pythonCommand),
    ...defined("deepReducer", deepReducer),
  }))();
  const server = new McpServer(
    { name: "codex-security-artifacts", version: MCP_APP_VERSION },
    {
      capabilities: {
        experimental: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: {} },
      },
    },
  );
  registerCompactWorkerArtifactTools(server, context);
  return server;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = environment[name];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${name} must be bound by the Codex Security coordinator.`);
  }
  return value;
}

function parseReducerContext(value: string): DeepReducerContext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error(
      "The coordinator-bound Deep reducer context is not valid JSON.",
      {
        cause: error,
      },
    );
  }
  if (
    !isRecord(parsed) ||
    typeof parsed.scanRoot !== "string" ||
    !Array.isArray(parsed.claimedWorkers)
  ) {
    throw new Error(
      "The coordinator-bound Deep reducer context is incomplete.",
    );
  }
  return parsed as unknown as DeepReducerContext;
}
