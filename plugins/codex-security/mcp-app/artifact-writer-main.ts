import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  createWorkerArtifactContext,
  type DeepReducerContext
} from "./src/artifact-context.js";
import { CODEX_SANDBOX_STATE_META_CAPABILITY } from "./src/deep-scan/parent-sandbox.js";
import { registerCompactWorkerArtifactTools } from "./src/server/compact-artifact-tools.js";
import { MCP_APP_VERSION } from "./src/version.js";

/** Build the narrow worker-only MCP from coordinator-inherited state. */
export async function createCodexSecurityArtifactWriterServer(
  environment: NodeJS.ProcessEnv = process.env
): Promise<McpServer> {
  const root = requiredEnvironment(environment, "CODEX_SECURITY_ARTIFACT_ROOT");
  const repoRoot = requiredEnvironment(environment, "CODEX_SECURITY_REPO_ROOT");
  const layout = environment.CODEX_SECURITY_ARTIFACT_LAYOUT ?? "worker";
  if (layout !== "worker" && layout !== "reducer") {
    throw new Error("CODEX_SECURITY_ARTIFACT_LAYOUT must be worker or reducer.");
  }

  const deepReducer = environment.CODEX_SECURITY_REDUCER_CONTEXT_JSON
    ? parseReducerContext(environment.CODEX_SECURITY_REDUCER_CONTEXT_JSON)
    : undefined;

  if ((layout === "reducer") !== (deepReducer !== undefined)) {
    throw new Error("A reducer worker requires exactly its coordinator-bound reducer context.");
  }

  const context = await createWorkerArtifactContext({
    root,
    repoRoot,
    layout,
    ...(environment.CODEX_SECURITY_SCAN_ID
      ? { scanId: environment.CODEX_SECURITY_SCAN_ID }
      : {}),
    ...(environment.CODEX_SECURITY_SCOPE
      ? { scope: environment.CODEX_SECURITY_SCOPE }
      : {}),
    ...(environment.CODEX_SECURITY_PLUGIN_ROOT
      ? { pluginRoot: environment.CODEX_SECURITY_PLUGIN_ROOT }
      : {}),
    ...(environment.CODEX_SECURITY_PYTHON_COMMAND
      ? { pythonCommand: environment.CODEX_SECURITY_PYTHON_COMMAND }
      : {}),
    ...(deepReducer ? { deepReducer } : {})
  });
  const server = new McpServer(
    { name: "codex-security-artifacts", version: MCP_APP_VERSION },
    {
      capabilities: {
        experimental: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: {} }
      }
    }
  );
  registerCompactWorkerArtifactTools(server, context);
  return server;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string
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
    throw new Error("The coordinator-bound Deep reducer context is not valid JSON.", {
      cause: error
    });
  }
  if (
    !parsed
    || typeof parsed !== "object"
    || Array.isArray(parsed)
    || typeof (parsed as Record<string, unknown>).scanRoot !== "string"
    || !Array.isArray((parsed as Record<string, unknown>).claimedWorkers)
  ) {
    throw new Error("The coordinator-bound Deep reducer context is incomplete.");
  }
  return parsed as DeepReducerContext;
}
