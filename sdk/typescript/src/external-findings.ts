import { CodexSecurityError } from "./errors.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";

/** A provider occurrence and its evidence, independent of a Codex assessment. */
export interface ExternalFinding {
  source_finding_id: string;
  evidence: ExternalFindingEvidence;
}

/** Repository provenance retained by a reader outside the published evidence. */
export interface ExternalSourceRepository {
  url: string;
  platform?: "github";
}

export interface ExternalFindings {
  read: number;
  /** Reader-retained run metadata, including diagnostics for empty reports. */
  report?: Record<string, unknown>;
  findings: ExternalFinding[];
  excluded: {
    position: number;
    source_finding_id: string | null;
    reason: string;
  }[];
}

export function hasScannerDiagnostics(input: ExternalFindings): boolean {
  const errors = input.report?.["errors"];
  return Array.isArray(errors) && errors.length > 0;
}

export function hasNoExternalRecords(input: ExternalFindings): boolean {
  return input.read === 0 && !input.findings.length && !input.excluded.length;
}

export function isEmptyExternalReport(input: ExternalFindings): boolean {
  return hasNoExternalRecords(input) && !hasScannerDiagnostics(input);
}

/** No findings can be imported. The selection retains every reader exclusion and diagnostic. */
export class NoPublishableFindingsError extends CodexSecurityError {
  constructor(public readonly selection: ExternalFindings) {
    const diagnostics = reportForJson(selection.report)?.["errors"];
    super(
      isEmptyExternalReport(selection)
        ? "No supported findings are ready to publish: the report is empty."
        : `No supported findings are ready to publish (${selection.read} read, ${selection.excluded.length} excluded).${Array.isArray(diagnostics) && diagnostics.length ? ` Scanner diagnostics: ${JSON.stringify(diagnostics)}` : ""}`,
    );
  }
}

export function reportForJson(report: ExternalFindings["report"]) {
  const errors = report?.["errors"];
  if (!Array.isArray(errors)) return report;
  const json = JSON.stringify(errors, (_key, entry: unknown) =>
    entry instanceof Error ? { message: entry.message } : entry,
  );
  return { ...report, errors: JSON.parse(json) as unknown[] };
}

/** @internal Keep earlier provider projections only for immutable request replay. */
export interface ExternalPublicationInput {
  current: ExternalFindings;
  legacy: ExternalFindings;
  currentIdentity: unknown;
  legacyIdentity: unknown;
}

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  sourceRepositoryUrl,
  inspectorProjectMap,
}: ExternalPublicationOptions & { provider: P }) {
  if (inspectorProjectMap !== undefined && provider !== "inspector")
    throw new CodexSecurityError(
      "An Inspector project map requires the inspector provider.",
    );
  return {
    repository,
    provider,
    sourceKey,
    sourceRepositoryUrl,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}
