import { formatScanCost, formatUsd, type ScanCost } from "./cost-model.js";

/** Returns the original error message without altering its contents. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

/** Base error for Codex Security SDK failures. */
export class CodexSecurityError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export type DeduplicationReviewStage = "screening" | "pair-review";
export type DeduplicationReviewFailureCategory =
  "validation" | "no-submission" | "model" | "transport" | "refusal";

export interface DeduplicationReviewFailureMetadata {
  stage: DeduplicationReviewStage;
  model: string;
  category: DeduplicationReviewFailureCategory;
  attempts: number;
  reason: string;
}

export class DeduplicationReviewError extends CodexSecurityError {
  public constructor(
    public readonly metadata: Readonly<DeduplicationReviewFailureMetadata>,
    displayReason: string = metadata.reason,
  ) {
    super(
      `Codex did not complete a validated deduplication review. Findings are unchanged; retry the command. Reason: ${displayReason}`,
    );
  }
}

export class CodexConnectionError extends CodexSecurityError {}
export class ConfigurationError extends CodexSecurityError {}
export class AuthenticationRequiredError extends CodexSecurityError {}
export class PluginBootstrapError extends CodexSecurityError {}
export class LocalPluginBootstrapError extends PluginBootstrapError {}
export class PluginPythonUnavailableError extends PluginBootstrapError {}
export class SandboxUnavailableError extends CodexSecurityError {}
export class InvalidTargetError extends CodexSecurityError {}
export class OutputDirectoryError extends CodexSecurityError {}
export class OutputDirectoryNotEmptyError extends OutputDirectoryError {
  public constructor(
    public readonly directory: string,
    operation: "scan" | "policy" | "component" = "scan",
  ) {
    super(
      operation === "component"
        ? `Component output directory is not empty: ${directory}. Choose a new or empty directory with --output-dir.`
        : operation === "policy"
          ? `Policy output directory is not empty: ${directory}. Choose a new or empty directory.`
          : `Scan output directory is not empty: ${directory}. To keep the existing results and start a new scan, add --archive-existing.`,
    );
  }
}
export type ProtectedScanPathKind =
  "output" | "state" | "temporary" | "runtime";

export class OutputInsideProtectedRootError extends OutputDirectoryError {
  public constructor(
    public readonly outputDirectory: string,
    public readonly protectedRoot: string,
    public readonly pathKind: ProtectedScanPathKind = "output",
  ) {
    super(
      pathKind === "state"
        ? [
            "Codex Security state directory must be outside the protected scan root and cannot contain it.",
            `  Resolved path:  ${outputDirectory}`,
            `  Protected root: ${protectedRoot}`,
            "Set CODEX_SECURITY_STATE_DIR to a private directory that does not overlap the protected root. For hosted scans, set stateDirectory on the request.",
          ].join("\n")
        : `Scan ${pathKind} directory must be outside the protected scan root: ${outputDirectory}`,
    );
  }
}
export class IncompleteScanError extends CodexSecurityError {}
export class ContractValidationError extends CodexSecurityError {}
export class ScanInterruptedError extends CodexSecurityError {
  public readonly scanDir: string;

  public constructor(message: string, scanDir: string, options?: ErrorOptions) {
    super(message, options);
    this.scanDir = scanDir;
  }
}

/**
 * A Standard scan stopped by a model policy refusal. The refusal is terminal
 * for the turn, but the scan's retained work is preserved as a stopped
 * (incomplete) bundle instead of being discarded: `bundlePreserved` reports
 * whether the sealed bundle was produced, and `phase` is the last phase the
 * SDK observed before the turn failed.
 */
export class ScanPolicyRefusalError extends CodexSecurityError {
  public readonly scanDir: string;
  public readonly scanId: string;
  public readonly phase: string;
  public readonly bundlePreserved: boolean;

  public constructor(
    message: string,
    scanDir: string,
    scanId: string,
    phase: string,
    bundlePreserved: boolean,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.scanDir = scanDir;
    this.scanId = scanId;
    this.phase = phase;
    this.bundlePreserved = bundlePreserved;
  }
}

export class ScanCostLimitExceededError extends ScanInterruptedError {
  public readonly maxCostUsd: number;
  public readonly cost: Readonly<ScanCost>;

  public constructor(
    maxCostUsd: number,
    cost: Readonly<ScanCost>,
    scanDir: string,
  ) {
    super(
      `Scan stopped: short-context budget baseline ${formatUsd(cost.estimatedUsd)} exceeded the ${formatUsd(maxCostUsd)} limit; estimated cost ${formatScanCost(cost)}; scan output directory: ${scanDir}.`,
      scanDir,
    );
    this.maxCostUsd = maxCostUsd;
    this.cost = cost;
  }
}
