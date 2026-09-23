import { createHash, timingSafeEqual } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import { replaceArtifactJson } from "./src/artifact-io.js";
import { MCP_APP_VERSION } from "./src/version.js";

type DependencyAgentRole = "acquisition" | "history";
type JsonRecord = Record<string, unknown>;

const digestPattern = /^sha256:[0-9a-f]{64}$/u;

/** Expose one private, host-bound dependency completion tool over native stdio. */
export async function createCodexSecurityDependencyAgentWriterServer(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<McpServer> {
  const role = requiredEnvironment(
    environment,
    "CODEX_SECURITY_DEPENDENCY_AGENT_ROLE",
  );
  if (role !== "acquisition" && role !== "history") {
    throw new Error(
      "The dependency-agent role must be acquisition or history.",
    );
  }

  const schemaDocument = parseObject(
    requiredEnvironment(
      environment,
      "CODEX_SECURITY_DEPENDENCY_COMPLETION_SCHEMA_JSON",
    ),
    "The host-bound dependency completion schema",
  );
  const schema = z.fromJSONSchema(
    schemaDocument as z.core.JSONSchema.JSONSchema,
  );

  const completionPath = requiredEnvironment(
    environment,
    "CODEX_SECURITY_DEPENDENCY_COMPLETION_PATH",
  );
  if (!isAbsolute(completionPath) || completionPath.includes("\0")) {
    throw new Error(
      "The host-bound dependency completion path must be absolute.",
    );
  }
  const workspaceRoot = await fs.realpath(dirname(completionPath));
  const rootMetadata = await fs.lstat(workspaceRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error(
      "The host-bound dependency workspace is not a safe directory.",
    );
  }

  const expectedVersions = parseStringArray(
    requiredEnvironment(
      environment,
      "CODEX_SECURITY_DEPENDENCY_EXPECTED_VERSIONS_JSON",
    ),
    "The host-bound requested dependency versions",
  );
  const expectedFindingIds = parseStringArray(
    requiredEnvironment(
      environment,
      "CODEX_SECURITY_DEPENDENCY_EXPECTED_FINDING_IDS_JSON",
    ),
    "The host-bound expected dependency finding identifiers",
  );

  const server = new McpServer({
    name: "codex-security-dependency-agent",
    version: MCP_APP_VERSION,
  });
  let accepted = false;
  let accepting = false;
  const toolName =
    role === "acquisition"
      ? "complete_dependency_acquisition"
      : "complete_dependency_history";

  server.registerTool(
    toolName,
    {
      title:
        role === "acquisition"
          ? "Complete Public Dependency Acquisition"
          : "Complete Public Dependency History",
      description:
        role === "acquisition"
          ? "Validate and persist the requested public dependency artifacts and reusable recipe."
          : "Validate and persist exactly one historical result for every seeded upstream finding.",
      inputSchema: schema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
      _meta: { ui: { visibility: ["model"] as const } },
    },
    async (input: unknown) => {
      if (accepted || accepting) {
        return toolError(
          "The dependency-agent completion was already accepted.",
        );
      }
      accepting = true;
      try {
        const completion = schema.parse(input);
        if (!isRecord(completion)) {
          throw new Error(
            "Dependency-agent completion must contain a JSON object.",
          );
        }
        if (role === "acquisition") {
          await validateAcquisition(
            completion,
            expectedVersions,
            workspaceRoot,
          );
        } else {
          validateHistory(completion, expectedFindingIds);
        }
        await validateCompletionDestination(completionPath, workspaceRoot);
        await replaceArtifactJson(completionPath, completion);
        accepted = true;
        return {
          content: [
            {
              type: "text" as const,
              text: "Dependency-agent completion accepted.",
            },
          ],
          structuredContent: { status: "completed" },
        };
      } catch (error: unknown) {
        return toolError(
          error instanceof Error
            ? error.message
            : "The dependency-agent completion was rejected.",
        );
      } finally {
        accepting = false;
      }
    },
  );

  return server;
}

async function validateAcquisition(
  completion: JsonRecord,
  expectedVersions: readonly string[],
  workspaceRoot: string,
): Promise<void> {
  if (typeof completion.recipe !== "string" || !completion.recipe.trim()) {
    throw new Error(
      "Dependency acquisition requires a nonempty public resolution recipe.",
    );
  }
  if (
    !Array.isArray(completion.artifacts) ||
    completion.artifacts.length === 0
  ) {
    throw new Error(
      "Dependency acquisition requires its requested public artifacts.",
    );
  }

  const expected = new Set(expectedVersions);
  const actual = new Set<string>();
  const variants = new Set<string>();
  for (const artifact of completion.artifacts) {
    if (!isRecord(artifact)) {
      throw new Error("Each acquired dependency artifact must be an object.");
    }
    const version = requiredValue(artifact.version, "artifact version");
    const variant = requiredValue(artifact.variant, "artifact variant");
    const artifactPath = safeRelativePath(artifact.path, "artifact path");
    const filename = requiredValue(artifact.filename, "artifact filename");
    if (
      filename !== basename(filename) ||
      filename === "." ||
      filename === ".." ||
      filename.includes("\\") ||
      filename.includes("\0")
    ) {
      throw new Error(
        "The acquired dependency filename must be a safe basename.",
      );
    }
    const expectedDigest = requiredValue(artifact.digest, "artifact digest");
    if (!digestPattern.test(expectedDigest)) {
      throw new Error(
        "The acquired dependency digest must be a canonical SHA-256.",
      );
    }

    const key = JSON.stringify([version, variant]);
    if (variants.has(key)) {
      throw new Error(
        `Duplicate dependency artifact for version ${version}, variant ${variant}.`,
      );
    }
    variants.add(key);
    actual.add(version);
    await verifyArtifactDigest(workspaceRoot, artifactPath, expectedDigest);
  }

  validateExactSeedSet(
    actual,
    expected,
    "requested dependency version",
    "unrequested",
  );
}

async function verifyArtifactDigest(
  workspaceRoot: string,
  relativePath: string,
  expectedDigest: string,
): Promise<void> {
  let current = workspaceRoot;
  const components = relativePath.split("/");
  for (const [index, component] of components.entries()) {
    current = join(current, component);
    const metadata = await fs.lstat(current).catch(() => undefined);
    const final = index === components.length - 1;
    if (
      !metadata ||
      metadata.isSymbolicLink() ||
      (final ? !metadata.isFile() : !metadata.isDirectory())
    ) {
      throw new Error(
        "The acquired dependency artifact is not a safe regular workspace file.",
      );
    }
  }

  const canonical = await fs.realpath(current);
  if (!canonical.startsWith(workspaceRoot + sep)) {
    throw new Error(
      "The acquired dependency artifact escaped its bound workspace.",
    );
  }

  const digest = createHash("sha256");
  for await (const chunk of createReadStream(canonical)) {
    digest.update(chunk);
  }
  const actual = Buffer.from(digest.digest("hex"), "hex");
  const expected = Buffer.from(expectedDigest.slice("sha256:".length), "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error(
      "The acquired dependency artifact does not match its SHA-256 digest.",
    );
  }
}

function validateHistory(
  completion: JsonRecord,
  expectedFindingIds: readonly string[],
): void {
  if (!Array.isArray(completion.results)) {
    throw new Error(
      "Dependency history requires results for its seeded upstream findings.",
    );
  }

  const actual = new Set<string>();
  for (const result of completion.results) {
    if (!isRecord(result)) {
      throw new Error("Each dependency historical result must be an object.");
    }
    const findingId = requiredValue(
      result.upstreamFindingId,
      "upstreamFindingId",
    );
    if (actual.has(findingId)) {
      throw new Error(
        `Duplicate dependency historical result for finding ${findingId}.`,
      );
    }
    actual.add(findingId);

    if (result.status === "found") {
      validateIntroduction(result.introducedIn);
    } else if (result.status === "unknown") {
      requiredValue(result.reason, "unknown historical finding reason");
      if (result.introducedIn !== undefined && result.introducedIn !== null) {
        throw new Error(
          "An unknown dependency finding cannot contain introducedIn.",
        );
      }
    } else {
      throw new Error(
        "Dependency historical results must be found or unknown.",
      );
    }
  }

  validateExactSeedSet(
    actual,
    new Set(expectedFindingIds),
    "seeded upstream finding",
    "unseeded",
  );
}

function validateIntroduction(value: unknown): void {
  if (!isRecord(value)) {
    throw new Error("A found dependency finding requires introducedIn.");
  }
  requiredValue(value.version, "introducedIn version");
  const digest = requiredValue(
    value.artifactDigest,
    "introducedIn artifactDigest",
  );
  if (!digestPattern.test(digest)) {
    throw new Error("introducedIn artifactDigest must be a canonical SHA-256.");
  }
  if (!Array.isArray(value.evidence) || value.evidence.length === 0) {
    throw new Error(
      "A found dependency finding requires nonempty introducedIn evidence.",
    );
  }
  for (const evidence of value.evidence) {
    if (!isRecord(evidence)) {
      throw new Error(
        "Dependency introduction evidence must contain public artifact objects.",
      );
    }
    safeRelativePath(evidence.path, "introduction evidence path");
    const code = requiredValue(evidence.code, "introduction evidence code");
    if (code.includes("\0")) {
      throw new Error(
        "Dependency introduction evidence cannot contain null bytes.",
      );
    }
  }
}

function validateExactSeedSet(
  actual: ReadonlySet<string>,
  expected: ReadonlySet<string>,
  label: string,
  unexpectedLabel: string,
): void {
  const missing = [...expected].filter((value) => !actual.has(value)).sort();
  if (missing.length) {
    throw new Error(`Missing ${label}(s): ${missing.join(", ")}.`);
  }
  const unexpected = [...actual].filter((value) => !expected.has(value)).sort();
  if (unexpected.length) {
    throw new Error(
      `Completion contains ${unexpectedLabel} ${label}(s): ${unexpected.join(", ")}.`,
    );
  }
}

async function validateCompletionDestination(
  destination: string,
  workspaceRoot: string,
): Promise<void> {
  const resolved = resolve(destination);
  if (!resolved.startsWith(workspaceRoot + sep)) {
    const canonicalParent = await fs.realpath(dirname(resolved));
    if (canonicalParent !== workspaceRoot) {
      throw new Error(
        "The dependency completion destination escaped its bound workspace.",
      );
    }
  }
  const metadata = await fs.lstat(resolved).catch(() => undefined);
  if (metadata && (metadata.isSymbolicLink() || !metadata.isFile())) {
    throw new Error(
      "The dependency completion destination is not a safe regular file.",
    );
  }
}

function safeRelativePath(value: unknown, label: string): string {
  const relative = requiredValue(value, label);
  if (
    isAbsolute(relative) ||
    relative.includes("\\") ||
    relative.includes("\0") ||
    relative
      .split("/")
      .some(
        (component) =>
          component === "" || component === "." || component === "..",
      )
  ) {
    throw new Error(
      `The ${label} must be a safe relative public-artifact path.`,
    );
  }
  return relative;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = environment[name];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${name} must be bound by the trusted dependency worker.`);
  }
  return value;
}

function requiredValue(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`The ${label} must be a nonempty string.`);
  }
  return value;
}

function parseObject(value: string, label: string): JsonRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!isRecord(parsed)) {
    throw new Error(`${label} must contain a JSON object.`);
  }
  return parsed;
}

function parseStringArray(value: string, label: string): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (
    !Array.isArray(parsed) ||
    parsed.some((item) => typeof item !== "string" || !item.trim())
  ) {
    throw new Error(`${label} must contain an array of nonempty strings.`);
  }
  return parsed as string[];
}

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toolError(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true,
  };
}
