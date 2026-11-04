import { readFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  canonicalDirectory,
  defined,
  type ArtifactContext,
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
  if (
    environment.CODEX_SECURITY_ARTIFACT_LAYOUT &&
    environment.CODEX_SECURITY_ARTIFACT_LAYOUT !== "worker"
  ) {
    throw new Error("The artifact writer requires a Standard scan worker.");
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
  const scopeInput: unknown =
    environment.CODEX_SECURITY_INCLUDE_PATHS_FILE === undefined
      ? undefined
      : JSON.parse(
          await readFile(environment.CODEX_SECURITY_INCLUDE_PATHS_FILE, "utf8"),
        );
  // Older coordinators sent only the requested paths, with lexical scope matching.
  const includePaths = isRecord(scopeInput) ? scopeInput.paths : scopeInput;
  const filePaths = isRecord(scopeInput) ? scopeInput.filePaths : undefined;
  for (const paths of [includePaths, filePaths]) {
    if (
      paths !== undefined &&
      (!Array.isArray(paths) || paths.some((path) => typeof path !== "string"))
    ) {
      throw new Error(
        "The coordinator-bound include paths must be an array of paths.",
      );
    }
  }
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
    layout: "worker",
    ...defined("scanId", scanId),
    ...defined("scope", scope),
    ...defined("includePaths", includePaths as string[] | undefined),
    ...defined("filePaths", filePaths as string[] | undefined),
    ...defined("pluginRoot", pluginRoot),
    ...defined("pythonCommand", pythonCommand),
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
