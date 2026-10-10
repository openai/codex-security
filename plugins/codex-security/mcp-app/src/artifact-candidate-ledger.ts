import { asRecord } from "./record.js";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import validationSchema from "../../schemas/tools/candidate-validations.schema.json";
import attackPathSchema from "../../schemas/tools/candidate-attack-paths.schema.json";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";
import {
  artifactDestination,
  readArtifactJsonl,
  replaceArtifactJsonl,
  type ArtifactContext,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

const documents = [
  commonSchema,
  validationSchema,
  attackPathSchema,
] as SchemaDocument[];

export interface CandidateValidationRecord {
  disposition: "reportable" | "suppressed" | "not_applicable" | "deferred";
  method: string;
  confidence: "high" | "medium" | "low";
  confidence_rationale: string;
  rubric:
    string | Record<string, unknown> | Array<string | Record<string, unknown>>;
  evidence: string | string[];
  counterevidence_or_proof_gap: string;
  remaining_uncertainty: string;
  artifact_paths?: string[];
  source?: string;
  control?: string;
  sink?: string;
  preconditions?: string | string[];
  [field: string]: unknown;
}

interface CandidateValidationUpdates {
  validations: {
    candidateId: string;
    validation: CandidateValidationRecord;
  }[];
}

/** Public workbench input; the bound context, never the caller, selects the artifact. */
export const candidateValidationsInputSchema = loadArtifactZodSchema(
  documents,
  validationSchema.$id,
  "input",
) as z.ZodType<CandidateValidationUpdates & { scanId: string }>;

/** Complete one existing validation phase without changing discovery or attack-path data. */
export async function recordCodexSecurityCandidateValidations(
  context: ArtifactContext,
  input: CandidateValidationUpdates,
): Promise<{
  kind: "candidate_validations";
  operation: "replace";
  rowsWritten: number;
}> {
  if (context.layout !== "scan") {
    throw new Error(
      "Candidate validation requires a scan-bound artifact context.",
    );
  }

  // The MCP registry validates this request before invoking the writer.
  const { validations } = input;
  const candidates = await readCandidateLedger(
    context,
    "Compact candidate ledger",
  );

  const validationByCandidateId = new Map<string, CandidateValidationRecord>();
  for (const update of validations) {
    if (!candidates.has(update.candidateId)) {
      throw new Error(
        `Validation names unknown candidate ${update.candidateId}.`,
      );
    }
    if (validationByCandidateId.has(update.candidateId)) {
      throw new Error(`Validation repeats candidate ${update.candidateId}.`);
    }
    validationByCandidateId.set(update.candidateId, update.validation);
  }

  const missing = [...candidates.keys()].filter(
    (candidateId) => !validationByCandidateId.has(candidateId),
  );
  if (missing.length > 0) {
    throw new Error(
      `Validation must include every existing candidate; missing ${missing.join(", ")}.`,
    );
  }

  const updatedRows = [...candidates.values()].map((row) => ({
    ...row,
    validation: validationByCandidateId.get(row.candidate_id)!,
  }));
  await replaceCandidateLedger(context, updatedRows);
  return {
    kind: "candidate_validations",
    operation: "replace",
    rowsWritten: updatedRows.length,
  };
}

type ImpactLevel = "high" | "medium" | "low" | "ignore" | "unknown";
type ReportableSeverity = "critical" | "high" | "medium" | "low";

export type CandidateAttackPathRecord = {
  dataflow: string;
  reachability: string;
  counterevidence: string;
  impact: ImpactLevel;
  likelihood: ImpactLevel;
  severity_rationale: string;
  change_conditions: string;
  [field: string]: unknown;
} & (
  | { decision: "reportable"; severity: ReportableSeverity }
  | { decision: "ignore"; severity: "ignore" }
  | {
      decision: "deferred";
      severity: ReportableSeverity | "unknown";
      proof_gap: string;
    }
);

interface CandidateAttackPathsPayload {
  attackPaths: {
    candidateId: string;
    attackPath: CandidateAttackPathRecord;
  }[];
}

/** The checked-in public schema controls both tools/list and call validation. */
export const candidateAttackPathsInputSchema = loadArtifactZodSchema(
  documents,
  attackPathSchema.$id,
  "input",
) as z.ZodType<CandidateAttackPathsPayload & { scanId: string }>;

/** Add attack-path judgments to eligible canonical Deep candidate rows. */
export async function recordCodexSecurityCandidateAttackPaths(
  context: ArtifactContext,
  input: CandidateAttackPathsPayload,
): Promise<{
  kind: "candidate_attack_paths";
  operation: "replace";
  rowsWritten: number;
}> {
  if (context.layout !== "scan") {
    throw new Error(
      "Candidate attack-path analysis requires a scan-bound artifact context.",
    );
  }

  // The MCP registry validates this request before invoking the writer.
  const { attackPaths } = input;
  const updates = new Map<string, CandidateAttackPathRecord>();
  for (const update of attackPaths) {
    if (updates.has(update.candidateId)) {
      throw new Error(
        `Candidate attack-path update repeats candidate ${update.candidateId}.`,
      );
    }
    updates.set(update.candidateId, update.attackPath);
  }

  const candidates = await readCandidateLedger(context, "Candidate ledger");

  for (const candidateId of updates.keys()) {
    const candidate = candidates.get(candidateId);
    if (!candidate) {
      throw new Error(
        `Candidate attack-path update refers to unknown candidate ${candidateId}.`,
      );
    }
    if (!isAttackPathEligible(candidate)) {
      throw new Error(
        `Candidate ${candidateId} must have a reportable or deferred validation before attack-path analysis.`,
      );
    }
  }

  const missing = [...candidates.values()]
    .filter(isAttackPathEligible)
    .map((candidate) => candidate.candidate_id)
    .filter((candidateId) => !updates.has(candidateId));
  if (missing.length > 0) {
    throw new Error(
      `Attack-path analysis must include every reportable or deferred candidate; missing ${missing.join(", ")}.`,
    );
  }

  const updatedRows = [...candidates.values()].map((row) => {
    const attackPath = updates.get(row.candidate_id);
    return attackPath ? { ...row, attack_path: attackPath } : row;
  });
  await replaceCandidateLedger(context, updatedRows);

  return {
    kind: "candidate_attack_paths",
    operation: "replace",
    rowsWritten: updates.size,
  };
}

function isAttackPathEligible(candidate: Record<string, unknown>): boolean {
  const disposition = asRecord(candidate.validation)?.disposition;
  return disposition === "reportable" || disposition === "deferred";
}

const components = [
  "artifacts",
  "02_discovery",
  "candidate_ledger.jsonl",
] as const;
const rowSchema = candidateSchemaV1.passthrough();

async function readCandidateLedger(
  context: ArtifactContext,
  duplicateLabel: string,
) {
  const rows = await readArtifactJsonl(
    context,
    components,
    "Compact candidate ledger",
    rowSchema,
  );
  const candidates = new Map<string, (typeof rows)[number]>();
  for (const row of rows) {
    if (candidates.has(row.candidate_id))
      throw new Error(
        `${duplicateLabel} repeats candidate ${row.candidate_id}.`,
      );
    candidates.set(row.candidate_id, row);
  }
  return candidates;
}

async function replaceCandidateLedger(
  context: ArtifactContext,
  rows: Record<string, unknown>[],
): Promise<void> {
  const destination = await artifactDestination(
    context,
    components,
    "Compact candidate ledger",
  );
  await replaceArtifactJsonl(destination, rows);
}
