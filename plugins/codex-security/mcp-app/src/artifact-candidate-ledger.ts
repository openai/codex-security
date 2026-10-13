import { asRecord } from "./record.js";
import type * as z from "zod/v4";
import { candidateLedgerRowSchema } from "./artifact-candidate.js";
import {
  artifactDestination,
  readArtifactJsonl,
  replaceArtifactJsonl,
  type ArtifactContext,
} from "./artifact-io.js";
import { artifactSchemaDocuments } from "./artifact-contracts.js";

const validationDefinitions =
  artifactSchemaDocuments["tools/candidate-validations"].$defs;
export const candidateValidationsInputSchema = validationDefinitions.input;
export type CandidateValidationRecord = z.infer<
  typeof validationDefinitions.validationRecord
>;
type CandidateValidationUpdates = Pick<
  z.infer<typeof candidateValidationsInputSchema>,
  "validations"
>;

/** Complete one existing validation phase without changing discovery or attack-path data. */
export async function recordCodexSecurityCandidateValidations(
  context: ArtifactContext,
  input: CandidateValidationUpdates,
): Promise<{
  kind: "candidate_validations";
  operation: "replace";
  rowsWritten: number;
}> {
  if (!context.scanId) {
    throw new Error(
      "Candidate validation requires a scan-bound artifact context.",
    );
  }

  // The MCP registry validates this request before invoking the writer.
  const { validations } = candidateValidationsInputSchema.parse({
    ...input,
    scanId: context.scanId,
  });
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

const attackPathDefinitions =
  artifactSchemaDocuments["tools/candidate-attack-paths"].$defs;
export const candidateAttackPathsInputSchema = attackPathDefinitions.input;
export type CandidateAttackPathRecord = z.infer<
  typeof attackPathDefinitions.attackPath
>;
type CandidateAttackPathsPayload = Pick<
  z.infer<typeof candidateAttackPathsInputSchema>,
  "attackPaths"
>;

/** Add attack-path judgments to eligible canonical Deep candidate rows. */
export async function recordCodexSecurityCandidateAttackPaths(
  context: ArtifactContext,
  input: CandidateAttackPathsPayload,
): Promise<{
  kind: "candidate_attack_paths";
  operation: "replace";
  rowsWritten: number;
}> {
  if (!context.scanId) {
    throw new Error(
      "Candidate attack-path analysis requires a scan-bound artifact context.",
    );
  }

  // The MCP registry validates this request before invoking the writer.
  const { attackPaths } = candidateAttackPathsInputSchema.parse({
    ...input,
    scanId: context.scanId,
  });
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
const rowSchema = candidateLedgerRowSchema;

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
