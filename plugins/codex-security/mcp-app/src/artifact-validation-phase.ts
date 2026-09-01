import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import validationSchema from "../../schemas/tools/candidate-validations.schema.json";
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

const documents = [commonSchema, validationSchema] as SchemaDocument[];

export interface CandidateValidationRecord {
  disposition: "reportable" | "suppressed" | "not_applicable" | "deferred";
  method: string;
  confidence: "high" | "medium" | "low";
  confidence_rationale: string;
  rubric: string | Record<string, unknown> | Array<string | Record<string, unknown>>;
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

interface CandidateValidationUpdate {
  candidateId: string;
  validation: CandidateValidationRecord;
}

interface CandidateValidationUpdates {
  validations: CandidateValidationUpdate[];
}

/** The nested validation record used by compact Deep candidate validation. */
export const candidateValidationRecordSchema = loadArtifactZodSchema(
  documents,
  validationSchema.$id,
  "validationRecord"
) as z.ZodType<CandidateValidationRecord>;

const candidateValidationUpdatesSchema = loadArtifactZodSchema(
  documents,
  validationSchema.$id,
  "updatesPayload"
) as z.ZodType<CandidateValidationUpdates>;

/** Public workbench input; the bound context, never the caller, selects the artifact. */
export const candidateValidationsInputSchema = loadArtifactZodSchema(
  documents,
  validationSchema.$id,
  "input"
) as z.ZodType<CandidateValidationUpdates & { scanId: string }>;

const compactCandidateLedgerRowSchema = candidateSchemaV1.passthrough();
const candidateLedgerComponents = [
  "artifacts",
  "02_discovery",
  "candidate_ledger.jsonl"
] as const;

/** Complete one existing validation phase without changing discovery or attack-path data. */
export async function recordCodexSecurityCandidateValidations(
  context: ArtifactContext,
  input: CandidateValidationUpdates
): Promise<{
  kind: "candidate_validations";
  operation: "replace";
  rowsWritten: number;
}> {
  if (context.layout !== "scan") {
    throw new Error("Candidate validation requires a scan-bound artifact context.");
  }

  const { validations } = candidateValidationUpdatesSchema.parse(input);
  const rows = await readArtifactJsonl(
    context,
    candidateLedgerComponents,
    "Compact candidate ledger",
    compactCandidateLedgerRowSchema
  );
  const candidateIds = new Set<string>();
  for (const row of rows) {
    if (candidateIds.has(row.candidate_id)) {
      throw new Error(`Compact candidate ledger repeats candidate ${row.candidate_id}.`);
    }
    candidateIds.add(row.candidate_id);
  }

  const validationByCandidateId = new Map<string, CandidateValidationRecord>();
  for (const update of validations) {
    if (!candidateIds.has(update.candidateId)) {
      throw new Error(`Validation names unknown candidate ${update.candidateId}.`);
    }
    if (validationByCandidateId.has(update.candidateId)) {
      throw new Error(`Validation repeats candidate ${update.candidateId}.`);
    }
    validationByCandidateId.set(update.candidateId, update.validation);
  }

  const missing = [...candidateIds].filter((candidateId) => (
    !validationByCandidateId.has(candidateId)
  ));
  if (missing.length > 0) {
    throw new Error(
      `Validation must include every existing candidate; missing ${missing.join(", ")}.`
    );
  }

  const updatedRows = rows.map((row) => ({
    ...row,
    validation: validationByCandidateId.get(row.candidate_id)!
  }));
  const destination = await artifactDestination(
    context,
    candidateLedgerComponents,
    "Compact candidate ledger"
  );
  await replaceArtifactJsonl(destination, updatedRows);
  return {
    kind: "candidate_validations",
    operation: "replace",
    rowsWritten: updatedRows.length
  };
}
