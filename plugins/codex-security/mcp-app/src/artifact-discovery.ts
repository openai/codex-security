import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { decodeUtf8 } from "./helpers/utf8.js";
import { resolvePythonCommand, runPythonWithInput } from "./python_command.js";
import {
  createCandidateNormalizer,
  stableJson,
  relativeFile,
  pathKey,
  type CandidateSource,
} from "./helpers/normalize-candidates.js";
import type * as z from "zod/v4";
import discoveryCandidateDefinitions from "../../schemas/definitions/discovery-candidate.schema.json";
import discoveryCandidatesToolSchema from "../../schemas/tools/discovery-candidates.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
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

export interface ListCodexSecurityCandidatesInput {
  cursor?: string;
  limit?: number;
}

export type CompactDiscoveryCandidate = z.infer<typeof candidateSchemaV1> &
  Record<string, unknown>;

/** Every exposed validator is derived from the checked-in JSON Schema source. */
export const compactDiscoveryCandidateSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidateDefinitions.$id,
  "discoveryCandidate",
) as z.ZodType<CompactDiscoveryCandidate>;

export const discoveryCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "recordDiscoveryCandidatesInput",
) as z.ZodType<DiscoveryCandidatesInput>;

export const workbenchDiscoveryCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "workbenchRecordDiscoveryCandidatesInput",
) as z.ZodType<DiscoveryCandidatesInput & { scanId: string }>;

export const listCodexSecurityCandidatesInputSchema = loadArtifactZodSchema(
  discoverySchemaDocuments,
  discoveryCandidatesToolSchema.$id,
  "listCandidatesInput",
) as z.ZodType<ListCodexSecurityCandidatesInput>;

export const workbenchListCodexSecurityCandidatesInputSchema =
  loadArtifactZodSchema(
    discoverySchemaDocuments,
    discoveryCandidatesToolSchema.$id,
    "workbenchListCandidatesInput",
  ) as z.ZodType<ListCodexSecurityCandidatesInput & { scanId: string }>;

export interface RecordCodexSecurityDiscoveryCandidatesResult {
  operation: "replace";
  candidatesRecorded: number;
}

export interface ListCodexSecurityCandidatesResult {
  rows: CompactDiscoveryCandidate[];
  nextCursor?: string;
}

/** Normalize in memory and replace the bound canonical candidate ledger. */
export async function recordCodexSecurityDiscoveryCandidates(
  input: DiscoveryCandidatesInput,
  context: ArtifactContext,
): Promise<RecordCodexSecurityDiscoveryCandidatesResult> {
  const { candidates } = discoveryCandidatesInputSchema.parse(input);
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
  const normalizer = createCandidateNormalizer(
    context.repoRoot,
    inventory,
    context.mode === "diff",
    context.mode === "diff"
      ? await diffCandidateSources(context, inventory, candidates)
      : undefined,
  );
  for (const [index, candidate] of candidates.entries()) {
    try {
      normalizer.add(candidate);
    } catch (error) {
      throw new Error(
        `${discoveryLabel}: candidate input row ${index + 1}: ${(error as Error).message}`,
        { cause: error },
      );
    }
  }
  const rows = normalizer.finish();
  await replaceArtifactText(
    destination,
    rows.map((row) => `${stableJson(row)}\n`).join(""),
  );
  return { operation: "replace", candidatesRecorded: rows.length };
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
  const paths = decodeUtf8(await readFile(inventory))
    .split("\n")
    .flatMap((row, index, lines) =>
      row.endsWith("\r") && index < lines.length - 1
        ? process.platform === "win32"
          ? [row.slice(0, -1)]
          : [row, row.slice(0, -1)]
        : [row],
    )
    .filter(Boolean)
    .map(nativePath);
  const locations = candidates.flatMap((candidate) =>
    candidate.locations.map((location) => nativePath(location.path)),
  );
  const aliases = new Map<string, string>();
  if (process.platform === "win32") {
    // Prefer an unambiguous spelling from the selected inventory.
    const selectedPaths = new Map<string, string | null>();
    for (const value of paths) {
      const key = pathKey(value);
      selectedPaths.set(
        key,
        selectedPaths.has(key) && selectedPaths.get(key) !== value
          ? null
          : value,
      );
    }
    for (const value of new Set([...paths, ...locations])) {
      try {
        let name = selectedPaths.get(pathKey(value));
        if (!name) {
          const [currentName] = relativeFile(value, context.repoRoot);
          name = selectedPaths.get(pathKey(currentName)) ?? currentName;
        }
        if (value !== name && pathKey(value) === pathKey(name))
          aliases.set(value, name);
      } catch {
        // The selected revision may contain a file absent from this checkout.
      }
    }
  }
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
      paths: [...paths, ...aliases.values()],
      locations: locations.flatMap((value) =>
        aliases.has(value) ? [value, aliases.get(value)!] : [value],
      ),
    }),
    "Diff source reader",
  );
  const sources = new Map(
    Object.entries(JSON.parse(output) as Record<string, CandidateSource>),
  );
  for (const [value, name] of aliases) {
    const source = sources.get(value);
    if (
      (!source || ("error" in source && source.error === "missing")) &&
      sources.has(name)
    )
      sources.set(value, sources.get(name)!);
  }
  return sources;
}

/** Read the actual compact ledger, including records added by later shared phases. */
export async function listCodexSecurityCandidates(
  input: ListCodexSecurityCandidatesInput,
  context: ArtifactContext,
): Promise<ListCodexSecurityCandidatesResult> {
  const page = listCodexSecurityCandidatesInputSchema.parse(input);
  const rows = await readArtifactJsonl(
    context,
    [...discoveryComponents, "candidate_ledger.jsonl"],
    discoveryLabel,
    compactDiscoveryCandidateSchema,
  );
  return paginateArtifactRows(rows, page, discoveryLabel);
}
