import { CodexSecurityError } from "./errors.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import { isRecord } from "./record.js";
import {
  identifiesTrivyReport,
  isTrivyReportHeader,
  retainedTrivyReport,
} from "./trivy-findings.js";
import { isWizOccurrence } from "./wiz-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type {
  Provider,
  ExternalFindingEvidence,
} from "./external-import-models.js";

/** A provider occurrence and its evidence, independent of a Codex assessment. */
export interface ExternalFinding {
  source_finding_id: string;
  evidence: ExternalFindingEvidence;
}

/** Repository provenance retained by a reader outside the published evidence. */
export interface ExternalSourceRepository {
  url: string;
  platform?: "github" | "gitlab";
}

export function snapshotSourceRepositories(
  references: readonly ExternalSourceRepository[] = [],
): ExternalSourceRepository[] {
  return references.map(({ url, platform }) => ({ url, platform }));
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

/** @internal Keep earlier provider projections only for immutable request replay. */
export interface ExternalPublicationInput {
  current: ExternalFindings;
  legacy: ExternalFindings;
  currentIdentity: unknown;
  legacyIdentity: unknown;
}

function isRetainedTrivyFinding(finding: ExternalFinding) {
  const data = finding.evidence.source_data;
  if (!data) return false;
  const report = retainedTrivyReport(finding);
  if (identifiesTrivyReport(report)) return true;
  const metadata = isRecord(report) ? report["Metadata"] : undefined;
  const nativeReport =
    isRecord(report) &&
    report["SchemaVersion"] === 2 &&
    (isTrivyReportHeader(report) ||
      (isRecord(metadata) && typeof metadata["RepoURL"] === "string"));
  const result = data["result"];
  const vulnerability = data["vulnerability"];
  const nativeRow =
    isRecord(result) &&
    result["Class"] === "lang-pkgs" &&
    isRecord(vulnerability) &&
    typeof vulnerability["VulnerabilityID"] === "string" &&
    typeof vulnerability["PkgName"] === "string";
  return (
    (nativeReport && finding.source_finding_id.startsWith("trivy:")) ||
    (nativeRow && (nativeReport || typeof data["scanRoot"] === "string"))
  );
}

/** Retained rows keep their scanner identity even if the report header is projected out. */
export function checkRetainedTrivyProvider(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget = "cloud",
): void {
  if (
    provider !== "trivy" &&
    isRetainedTrivyFinding(finding) &&
    !(provider === "wiz" && isWizOccurrence(finding, target))
  )
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
}

export function checkTrivyReportProvider(
  provider: Provider,
  report: unknown,
): void {
  if (provider !== "trivy" && identifiesTrivyReport(report))
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
}

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  sourceRepositoryUrl,
  trivyScanRoot,
  inspectorProjectMap,
}: ExternalPublicationOptions & { provider: P }) {
  if (trivyScanRoot !== undefined && provider !== "trivy")
    throw new CodexSecurityError(
      "--trivy-scan-root applies only to --provider trivy.",
    );
  if (inspectorProjectMap !== undefined && provider !== "inspector")
    throw new CodexSecurityError(
      "An Inspector project map requires the inspector provider.",
    );
  return {
    repository,
    provider,
    sourceKey,
    sourceRepositoryUrl,
    trivyScanRoot,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}
