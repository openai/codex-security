import { formatScanCost, formatUsd, type ScanCost } from "./cost-model.js";

/** Returns the original error message without altering its contents. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const USAGE_LIMIT_MESSAGES = new Set([
  "Quota exceeded. Check your plan and billing details.",
  "To use Codex with your ChatGPT plan, upgrade to Plus: https://chatgpt.com/explore/plus.",
  "Your workspace is out of credits. Add credits to continue.",
  "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
  "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
  "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
]);

/** Codex reports native quota failures as text, sometimes during compaction. */
export function isCodexUsageLimit(message: string): boolean {
  const reason = message.replace(/^Error running remote compact task: /, "");
  return (
    USAGE_LIMIT_MESSAGES.has(reason) ||
    reason.startsWith("You’ve hit your usage limit.") ||
    reason.startsWith("You’ve hit your usage limit for ")
  );
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
    operation: "scan" | "policy" = "scan",
  ) {
    super(
      operation === "policy"
        ? `Policy output directory is not empty: ${directory}. Choose a new or empty directory.`
        : `Scan output directory is not empty: ${directory}. To keep the existing results and start a new scan, add --archive-existing.`,
    );
  }
}
export type ProtectedScanPathKind = "output" | "temporary" | "runtime";

export class OutputInsideProtectedRootError extends OutputDirectoryError {
  public constructor(
    public readonly outputDirectory: string,
    public readonly protectedRoot: string,
    public readonly pathKind: ProtectedScanPathKind = "output",
  ) {
    super(
      `Scan ${pathKind} directory must be outside the protected scan root: ${outputDirectory}`,
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
