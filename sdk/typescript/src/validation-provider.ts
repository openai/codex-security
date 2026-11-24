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
  /** Membership was lost. Any reported issue ID is unconfirmed. */
  issueUnlinked?: true;
  validationArtifactId?: string;
  scoringArtifactId?: string;
  /** True when a completed validation is still waiting for a linked issue score. */
  scoringPending?: boolean;
  /** The local serializer rejected the input before any upload. */
  invalidInput?: boolean;
  disposition?: ValidationProviderAssessment["disposition"];
  submittedAt?: string;
  provider: string;
  verdict: string;
  /** How the external validation run ended, independently of its verdict. */
  terminalStatus?: string;
  /** Provider explanation when it declined the submission. */
  statusMessage?: string;
  severityBefore: string;
  severityAfter: string;
  /** Issue-level severity, independent of the local finding's severity. */
  providerSeverity?: string;
  /** Overall verdict on the same validation artifact as an explicit member result. */
  issueVerdict?: string;
  /** Scope of the provider verdict. */
  resultScope?: ValidationResultScope;
  issueFindingCount?: number;
  /** Structured attacker reachability from the provider's scoring evidence. */
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
    /** Creation time of the linked issue score, if available. */
    scoredAt?: string;
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
  /** Verify a saved scan's target before a new external submission. */
  checkSubmissionTarget?: (signal?: AbortSignal) => Promise<void>;
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

/** Failed validation runs are terminal. A missing score or transport failure can resume. */
export function retryableAssessment(
  item: ValidationProviderAssessment,
): boolean {
  if (item.record?.invalidInput) return false;
  return Boolean(
    item.record?.scoringPending ||
    (item.unavailable && !item.record?.terminalStatus),
  );
}

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
