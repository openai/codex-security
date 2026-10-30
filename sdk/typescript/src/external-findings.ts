import {
  hostedRepositoryUrl,
  validateHostedRepositoryUrl,
} from "./hosted-scanner-http.js";
import { CodexSecurityError } from "./errors.js";
import { isRecord } from "./record.js";
import {
  identifiesTrivyReport,
  isTrivyReportHeader,
  retainedTrivyReport,
} from "./trivy-findings.js";
import { isWizOccurrence } from "./wiz-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { requiredText } from "./scanner-import.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "./external-import-models.js";

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

/** A Snyk or Semgrep report bound to one source repository, even when it has no findings. */
export interface HostedExternalFindings extends ExternalFindings {
  sourceRepositoryUrl?: string;
  /** "other" requires exact repository path casing on custom hosts. */
  sourceRepositoryPlatform?: "github" | "other";
  /** Native project and target that verify an empty Snyk REST report. */
  snykRestContext?: Record<string, unknown>;
}

export type NormalizedFindingsFor<P extends Provider> = P extends
  "snyk" | "semgrep"
  ? HostedExternalFindings
  : ExternalFindings;

export const HOSTED_FINDINGS_FORMATS = {
  snyk: "snyk-rest-issues/v1",
  semgrep: "semgrep-platform-findings/v1",
} as const;

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
export function checkRetainedFindingProvider(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget = "cloud",
): void {
  const data = finding.evidence.source_data;
  if (
    provider !== "trivy" &&
    isRetainedTrivyFinding(finding) &&
    !(provider === "wiz" && isWizOccurrence(finding, target))
  )
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
  const format = data?.["format"];
  const native =
    format === HOSTED_FINDINGS_FORMATS.snyk
      ? "snyk"
      : format === HOSTED_FINDINGS_FORMATS.semgrep
        ? "semgrep"
        : undefined;
  if (native && native !== provider)
    throw new CodexSecurityError(
      `Retained ${native} evidence requires the ${native} provider.`,
    );
}

/** Capture the public SDK fields once, including class accessors, before any asynchronous work. */
export function snapshotExternalFindings(
  input: HostedExternalFindings,
  provider: Provider,
): HostedExternalFindings {
  const {
    read,
    findings,
    excluded,
    report,
    sourceRepositoryUrl,
    sourceRepositoryPlatform,
    snykRestContext,
    ...rest
  } = input;
  if (provider !== "trivy" && identifiesTrivyReport(report))
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
  if (
    (sourceRepositoryUrl !== undefined ||
      sourceRepositoryPlatform !== undefined) &&
    provider !== "snyk" &&
    provider !== "semgrep"
  )
    throw new CodexSecurityError(
      "Normalized report repository declarations require the Snyk or Semgrep provider.",
    );
  if (snykRestContext !== undefined && provider !== "snyk")
    throw new CodexSecurityError(
      "Retained snyk evidence requires the snyk provider.",
    );
  if (typeof sourceRepositoryUrl === "string") {
    const label = "Source repository URL";
    if (/^https?:\/\//iu.test(sourceRepositoryUrl))
      hostedRepositoryUrl(sourceRepositoryUrl, label);
    else validateHostedRepositoryUrl(requiredText(sourceRepositoryUrl, label));
  }
  const current: HostedExternalFindings = structuredClone({
    ...rest,
    read,
    findings,
    excluded,
    ...(snykRestContext !== undefined && { snykRestContext }),
    ...((sourceRepositoryUrl !== undefined ||
      "sourceRepositoryUrl" in input) && { sourceRepositoryUrl }),
    ...((sourceRepositoryPlatform !== undefined ||
      "sourceRepositoryPlatform" in input) && { sourceRepositoryPlatform }),
  });
  // Report metadata may alias evidence that receives Cloud defaults.
  if (report !== undefined) current.report = structuredClone(report);
  return current;
}

/** @internal Keep earlier provider projections only for immutable request replay. */
export interface ExternalPublicationInput {
  current: HostedExternalFindings;
  legacy: HostedExternalFindings;
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
  trivyScanRoot,
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
    trivyScanRoot,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}
