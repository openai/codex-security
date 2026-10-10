import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { decodeUtf8 } from "./helpers/utf8.js";
import { decodePosixBytes } from "./helpers/posix-path.js";
import { resolvePythonCommand, runPythonWithInput } from "./python_command.js";
import {
  stableJson,
  candidateRelativePath,
  type CandidateNormalizationInput,
  type CandidateSource,
  type normalizeCandidateBatch,
} from "./helpers/normalize-candidates.js";
import type * as z from "zod/v4";
import discoveryCandidateDefinitions from "../../schemas/definitions/discovery-candidate.schema.json";
import discoveryCandidatesToolSchema from "../../schemas/tools/discovery-candidates.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  type ArtifactPage,
  paginateArtifactRows,
  readArtifactJsonl,
  artifactSourcePath,
  replaceArtifactText,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";

const discoveryComponents = ["artifacts", "02_discovery"] as const;
const discoveryLabel = "discovery candidates";
const discoverySchemaDocuments = [
  discoveryCandidateDefinitions,
  discoveryCandidatesToolSchema,
] as SchemaDocument[];

export type RawDiscoveryLocationRole =
  | "entrypoint"
  | "entrypoint/wrapper"
  | "source"
  | "root_control"
  | "sink"
  | "concrete_implementation"
  | "evidence";

export interface RawDiscoveryLocation {
  path: string;
  start_line: number;
  end_line?: number;
  role: RawDiscoveryLocationRole;
}

export interface RawDiscoveryCandidate {
  cwe_ids: string[];
  locations: RawDiscoveryLocation[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

export interface DiscoveryCandidatesInput {
  candidates: RawDiscoveryCandidate[];
}

export type CompactDiscoveryCandidate = z.infer<typeof candidateSchemaV1> &
  Record<string, unknown>;

/** Every exposed validator is derived from the checked-in JSON Schema source. */
export const compactDiscoveryCandidateSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidateDefinitions.$id,
  "discoveryCandidate",
) as z.ZodType<CompactDiscoveryCandidate>;

export const workbenchDiscoveryCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "workbenchRecordDiscoveryCandidatesInput",
) as z.ZodType<DiscoveryCandidatesInput & { scanId: string }>;

export const workbenchListCodexSecurityCandidatesInputSchema =
  loadArtifactZodSchema(
    discoverySchemaDocuments,
    discoveryCandidatesToolSchema.$id,
    "workbenchListCandidatesInput",
  ) as z.ZodType<ArtifactPage & { scanId: string }>;

/**
 * Normalize in memory and replace the bound canonical candidate ledger.
 * The MCP registry validates the request before invoking this writer.
 */
export async function recordCodexSecurityDiscoveryCandidates(
  input: DiscoveryCandidatesInput,
  context: ArtifactContext,
) {
  const { candidates } = input;
  const inventoryComponents = [...discoveryComponents, "in_scope_files.txt"];
  const inventory = await artifactSourcePath(
    context,
    inventoryComponents,
    "discovery review inventory",
  );
  const destination = await artifactDestination(
    context,
    [...discoveryComponents, "candidate_ledger.jsonl"],
    discoveryLabel,
  );
  const workerData: CandidateNormalizationInput = {
    repoRoot: context.repoRoot,
    scopePath: inventory,
    allowMissing: context.mode === "diff",
    sources:
      context.mode === "diff"
        ? await diffCandidateSources(context, inventory, candidates)
        : undefined,
    candidates,
  };
  // Inventory traversal and source reads must not block other MCP requests.
  const rows = await new Promise<ReturnType<typeof normalizeCandidateBatch>>(
    (resolve, reject) => {
      const worker = new Worker(
        createRequire(import.meta.url).resolve("./helpers.mjs"),
        { workerData },
      );
      worker.once("message", resolve);
      worker.once("error", reject);
      worker.once("exit", (code) =>
        reject(new Error(`Candidate normalizer exited with code ${code}.`)),
      );
    },
  );
  await replaceArtifactText(
    destination,
    rows.map((row) => `${stableJson(row)}\n`).join(""),
  );
  return { operation: "replace" as const, candidatesRecorded: rows.length };
}

async function diffCandidateSources(
  context: ArtifactContext,
  inventory: string,
  candidates: RawDiscoveryCandidate[],
): Promise<Map<string, CandidateSource>> {
  const target = context.targetContract?.diffTarget as
    Record<string, unknown> | undefined;
  if (
    !context.pluginRoot ||
    !target ||
    !["working_tree", "commit", "range"].includes(String(target.kind)) ||
    typeof target.baseRevision !== "string" ||
    !target.baseRevision ||
    typeof target.headRevision !== "string" ||
    !target.headRevision
  ) {
    throw new Error(
      "discovery candidates: the diff scan has no authoritative change set.",
    );
  }
  const nativePath = (value: string) =>
    process.platform === "win32" ? value.replaceAll("\\", "/") : value;
  const contents = await readFile(inventory);
  const paths = (
    process.platform === "win32"
      ? decodeUtf8(contents)
      : decodePosixBytes(contents)
  )
    .split(/\r?\n/u)
    .filter(Boolean)
    .map(nativePath);
  const locations = candidates.flatMap((candidate, index) => {
    try {
      return candidate.locations.map((location) =>
        candidateRelativePath(location.path),
      );
    } catch (error) {
      throw new Error(
        `${discoveryLabel}: candidate input row ${index + 1}: ${(error as Error).message}`,
        { cause: error },
      );
    }
  });
  const python = context.pythonCommand ?? (await resolvePythonCommand());
  const output = await runPythonWithInput(
    python,
    [
      "-I",
      "-X",
      "utf8",
      "-c",
      `import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_target import candidate_source_lines
try:
    json.dump(candidate_source_lines(Path(sys.argv[2]), **json.load(sys.stdin)), sys.stdout)
except subprocess.CalledProcessError as error:
    if error.stderr:
        sys.stderr.buffer.write(error.stderr)
    raise`,
      join(context.pluginRoot, "scripts"),
      context.repoRoot,
    ],
    JSON.stringify({
      diff_target: target,
      paths,
      locations,
      case_insensitive: process.platform === "win32",
    }),
    "Diff source reader",
  );
  return new Map(
    Object.entries(JSON.parse(output) as Record<string, CandidateSource>),
  );
}

/** Read the actual compact ledger, including records added by later shared phases. */
export async function listCodexSecurityCandidates(
  input: ArtifactPage,
  context: ArtifactContext,
) {
  // The MCP registry validates paging before invoking this reader.
  const rows = await readArtifactJsonl(
    context,
    [...discoveryComponents, "candidate_ledger.jsonl"],
    discoveryLabel,
    compactDiscoveryCandidateSchema,
  );
  return paginateArtifactRows(rows, input, discoveryLabel);
}
