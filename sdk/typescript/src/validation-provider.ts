import type { Finding } from "./models.js";

export interface ValidationProvenance {
  provider: string;
  providerVersion: string;
  referenceId?: string;
  referenceUrl?: string;
  validatedAt: string;
}

export type ValidationBasis = "GRAPH" | "CODE" | "INFERRED";
export type ValidationClaimMatch =
  "on_target" | "on_target_escalated" | "different_flaw" | "unknown";

/** Conclusions only. Proof bodies and console output are not report fields. */
export interface ValidationItemRecord {
  itemId: string;
  provider: string;
  verdict: string;
  severityBefore: string;
  severityAfter: string;
  providerSeverity?: string;
  reasons: Array<{ basis: ValidationBasis; reason: string }>;
  claimMatch: ValidationClaimMatch;
  issueUrl?: string;
  freshness: {
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
      validatedAt: new Date().toISOString(),
    },
    report: `Unavailable: ${message}`,
  };
}
