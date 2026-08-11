import { formatUsd, type ScanCost } from "./cost.js";

/** Returns the original error message without altering its contents. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Omit credential-bearing messages at persistence and display boundaries. */
export function safeErrorMessage(error: unknown): string {
  const message = errorMessage(error);
  return /(?:\b(?:sk-(?:proj-)?|github_pat_|gh[pousr]_|npm_)\S+|\b(?:bearer|basic|token)(?:\s|%20|\+)+\S+|(?:api(?:[_-]|%5f|%2d)?key|access(?:[_-]|%5f|%2d)?key(?:[_-]?id)?|private(?:[_-]|%5f|%2d)?key|auth(?:orization)?|token|secret|credential|signature|sig|password|passwd)(?:(?:[_-]|%5f|%2d)?(?:value|data|token|secret|credential|password|header|field|id|key))?(?:\]|%5d)*(?:\\*["'])?\s*(?::|=|%3d)|(?:https?|ssh|git\+ssh):\/\/[^\s/@]+@|-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)/iu.test(
    message,
  )
    ? "[redacted]"
    : message;
}

/** Base error for Codex Security SDK failures. */
export class CodexSecurityError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class ConfigurationError extends CodexSecurityError {}
export class AuthenticationRequiredError extends CodexSecurityError {}
export class PluginBootstrapError extends CodexSecurityError {}
export class PluginPythonUnavailableError extends PluginBootstrapError {}
export class InvalidTargetError extends CodexSecurityError {}
export class OutputDirectoryError extends CodexSecurityError {}
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
      `Scan stopped: estimated cost ${formatUsd(cost.estimatedUsd)} exceeded the ${formatUsd(maxCostUsd)} limit; partial output remains at ${scanDir}.`,
      scanDir,
    );
    this.maxCostUsd = maxCostUsd;
    this.cost = cost;
  }
}
