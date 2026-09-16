import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import attackPathSchema from "../../schemas/tools/candidate-attack-paths.schema.json";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";
import {
  artifactDestination,
  readArtifactJsonl,
  replaceArtifactJsonl
} from "./artifact-io.js";
import type { ArtifactContext } from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument
} from "./artifact-schema-loader.js";

const documents = [commonSchema, attackPathSchema] as SchemaDocument[];

type ImpactLevel = "high" | "medium" | "low" | "ignore" | "unknown";
type ReportableSeverity = "critical" | "high" | "medium" | "low";

interface CandidateAttackPathFields {
  dataflow: string;
  reachability: string;
  counterevidence: string;
  impact: ImpactLevel;
  likelihood: ImpactLevel;
  severity_rationale: string;
  change_conditions: string;
  [field: string]: unknown;
}

export type CandidateAttackPathRecord = CandidateAttackPathFields & (
  | { decision: "reportable"; severity: ReportableSeverity }
  | { decision: "ignore"; severity: "ignore" }
  | { decision: "deferred"; severity: ReportableSeverity | "unknown"; proof_gap: string }
);

interface CandidateAttackPathUpdate {
  candidateId: string;
  attackPath: CandidateAttackPathRecord;
}

interface CandidateAttackPathsPayload {
  attackPaths: CandidateAttackPathUpdate[];
}

/** The stored JSON Schema is the sole source of the nested attack-path contract. */
export const candidateAttackPathSchema = loadArtifactZodSchema(
  documents,
  attackPathSchema.$id,
  "attackPath"
) as z.ZodType<CandidateAttackPathRecord>;

const candidateAttackPathsPayloadSchema = loadArtifactZodSchema(
  documents,
  attackPathSchema.$id,
  "updatesPayload"
) as z.ZodType<CandidateAttackPathsPayload>;

/** The checked-in public schema controls both tools/list and call validation. */
export const candidateAttackPathsInputSchema = loadArtifactZodSchema(
  documents,
  attackPathSchema.$id,
  "input"
) as z.ZodType<CandidateAttackPathsPayload & { scanId: string }>;

const candidateLedgerRowSchema = candidateSchemaV1.passthrough();

const candidateLedgerComponents = [
  "artifacts",
  "02_discovery",
  "candidate_ledger.jsonl"
] as const;

/** Add attack-path judgments to eligible canonical Deep candidate rows. */
export async function recordCodexSecurityCandidateAttackPaths(
  context: ArtifactContext,
  input: CandidateAttackPathsPayload
): Promise<{
  kind: "candidate_attack_paths";
  operation: "replace";
  rowsWritten: number;
}> {
  if (context.layout !== "scan") {
    throw new Error("Candidate attack-path analysis requires a scan-bound artifact context.");
  }

  const { attackPaths } = candidateAttackPathsPayloadSchema.parse(input);
  const updates = new Map<string, CandidateAttackPathRecord>();
  for (const update of attackPaths) {
    if (updates.has(update.candidateId)) {
      throw new Error(
        `Candidate attack-path update repeats candidate ${update.candidateId}.`
      );
    }
    updates.set(update.candidateId, update.attackPath);
  }

  const rows = await readArtifactJsonl(
    context,
    candidateLedgerComponents,
    "Compact candidate ledger",
    candidateLedgerRowSchema
  );
  const candidates = new Map<string, (typeof rows)[number]>();
  for (const row of rows) {
    if (candidates.has(row.candidate_id)) {
      throw new Error(
        `Candidate ledger repeats candidate ${row.candidate_id}.`
      );
    }
    candidates.set(row.candidate_id, row);
  }

  for (const candidateId of updates.keys()) {
    const candidate = candidates.get(candidateId);
    if (!candidate) {
      throw new Error(
        `Candidate attack-path update refers to unknown candidate ${candidateId}.`
      );
    }
    if (!isAttackPathEligible(candidate)) {
      throw new Error(
        `Candidate ${candidateId} must have a reportable or deferred validation before attack-path analysis.`
      );
    }
  }

  const missing = [...candidates.values()]
    .filter(isAttackPathEligible)
    .map((candidate) => candidate.candidate_id)
    .filter((candidateId) => !updates.has(candidateId));
  if (missing.length > 0) {
    throw new Error(
      `Attack-path analysis must include every reportable or deferred candidate; missing ${missing.join(", ")}.`
    );
  }

  const updatedRows = rows.map((row) => {
    const attackPath = updates.get(row.candidate_id);
    return attackPath ? { ...row, attack_path: attackPath } : row;
  });
  const destination = await artifactDestination(
    context,
    candidateLedgerComponents,
    "Compact candidate ledger"
  );
  await replaceArtifactJsonl(destination, updatedRows);

  return {
    kind: "candidate_attack_paths",
    operation: "replace",
    rowsWritten: updates.size
  };
}

function isAttackPathEligible(
  candidate: Record<string, unknown>
): boolean {
  const validation = candidate.validation;
  if (!validation || typeof validation !== "object" || Array.isArray(validation)) {
    return false;
  }
  const disposition = (validation as Record<string, unknown>).disposition;
  return disposition === "reportable" || disposition === "deferred";
}
