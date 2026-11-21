import type { Finding } from "./models.js";

export interface ValidationProvenance {
  provider: string;
  providerVersion: string;
  referenceId?: string;
  referenceUrl?: string;
  validatedAt?: string;
}

/** Known provenance categories, or a future category preserved as reported. */
export type ValidationBasis =
  "GRAPH" | "CODE" | "FINDING" | "INFERRED" | (string & {});
export type ValidationResultScope = "finding" | "issue";
export type ValidationClaimMatch =
  "on_target" | "on_target_escalated" | "different_flaw" | "unknown";

/** Conclusions only. Proof bodies and console output are not report fields. */
export interface ValidationItemRecord {
  itemId: string;
  /** External identities for an accepted submission, including while validation is pending. */
  findingId?: string;
  findingArn?: string;
  issueId?: string;
  issueArn?: string;
  validationArtifactId?: string;
  scoringArtifactId?: string;
  /** Selected provider conclusion for a matched, current finding. */
  proofObservation?: {
    kind: "execution" | "source_analysis";
    effect?: string;
    summary?: string;
  };
  submittedAt?: string;
  provider: string;
  verdict: string;
  /** How the external validation run ended, independently of its verdict. */
  terminalStatus?: string;
  /** Provider explanation when it declined the submission. */
  statusMessage?: string;
  severityBefore: string;
  severityAfter: string;
  providerSeverity?: string;
  /** Scope of the verdict and provider severity, not the sealed Codex finding. */
  resultScope?: ValidationResultScope;
  issueFindingCount?: number;
  /** Structured attacker reachability at resultScope; absent means unknown. */
  reachableFromAttacker?: boolean;
  /** Issue validation evidence existed before this finding was submitted. */
  joinedValidatedIssue?: boolean;
  reasons: Array<{ basis: ValidationBasis; reason: string }>;
  claimMatch: ValidationClaimMatch;
  issueUrl?: string;
  freshness: {
    /** Creation time of the returned validation artifact, including inconclusive results. */
    evidenceCreatedAt?: string;
    validatedAt?: string;
    stale: boolean;
    reasons: string[];
  };
  unavailable?: string;
}

export interface ValidationProviderAssessment {
  disposition: "reportable" | "suppressed" | "not_applicable" | "deferred";
  report: string;
  provenance: ValidationProvenance;
  unavailable?: string;
  record?: ValidationItemRecord;
}

export interface ValidationProviderContext {
  repositoryPath: string;
  signal?: AbortSignal;
  /** Use the hosting plugin's path protection instead of locating an SDK bundle. */
  resolveHostPaths?: (
    cwd: string,
    roots: readonly string[],
  ) =>
    | ((path: string) => string | null)
    | Promise<(path: string) => string | null>;
}

/** Host-side extension point for supplemental finding validation. */
export interface ValidationProvider {
  readonly name: string;
  readonly version: string;
  validate(
    finding: Finding | Record<string, unknown> | string,
    context: ValidationProviderContext,
  ): Promise<ValidationProviderAssessment>;
  /** Submit a complete validation scope before waiting for any result. */
  validateBatch?(
    findings: readonly (Finding | Record<string, unknown> | string)[],
    context: ValidationProviderContext,
  ): Promise<ValidationProviderAssessment[]>;
}

export type ValidationProviderConfiguration = {
  provider: string;
  [provider: string]: unknown;
};

export function supplementalValidationStatus(
  provider: ValidationProvider | undefined,
  assessments: readonly ValidationProviderAssessment[] | undefined,
): "complete" | "incomplete" {
  return provider?.name === "continuum" &&
    assessments?.some((item) => item.disposition === "deferred")
    ? "incomplete"
    : "complete";
}

export function unavailableAssessment(
  provider: Pick<ValidationProvider, "name" | "version">,
  reason: unknown,
): ValidationProviderAssessment {
  const message =
    reason instanceof Error
      ? reason.message
      : String(reason || "unknown error");
  return {
    disposition: "deferred",
    unavailable: message,
    provenance: {
      provider: provider.name,
      providerVersion: provider.version,
    },
    report: `Unavailable: ${message}`,
  };
}
