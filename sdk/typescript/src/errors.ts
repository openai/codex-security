import { formatUsd, type ScanCost } from "./cost.js";

/** Returns an error message with credential-shaped substrings redacted. */
export function redactedErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const withoutPrivateKeys = message
    .replaceAll(
      /(\b[A-Za-z0-9_-]{0,64}private[_-]?key(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\?["'])?\s*[:=]\s*)(?:\\?["'])?-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----(?:\\?["'])?|$)/giu,
      "$1[redacted]",
    )
    .replaceAll(
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/giu,
      "[redacted]",
    );
  return redactQuotedCredentialValues(withoutPrivateKeys)
    .replaceAll(
      /(\b(?:authorization|auth)\b(?:\\?["'])?\s*[:=]\s*)([A-Za-z][A-Za-z0-9._~-]{0,63})((?:\s|%20|\+)+)[A-Za-z_][A-Za-z0-9_-]{0,64}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_-]{0,64}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s,;]+))*/giu,
      "$1$2$3[redacted]",
    )
    .replaceAll(
      /(\b[A-Za-z0-9_-]{0,64}(?:authorization|auth)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\?["'])?\s*[:=]\s*)([A-Za-z][A-Za-z0-9._~-]{0,63})((?:\s|%20|\+)+)(?!\[redacted\]|(?!key\s*=)[A-Za-z_][A-Za-z0-9_-]{0,64}\s*[:=]\s*(?=[^=\s"',;}&\\\]]))[^\s"',;}&\\\]]+/giu,
      "$1$2$3[redacted]",
    )
    .replaceAll(
      /(\b[A-Za-z0-9_-]{0,64}(?:api[_-]?keys?|access[_-]?key(?:[_-]?id)?|private[_-]?key|authorization|auth|token|secret|credentials?|signature|sig|password|passwd)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)(?!\[redacted\]|[A-Za-z][A-Za-z0-9._~-]{0,63}(?:\s|%20|\+)+\[redacted\])[^\s"',;}&\\\]]+/giu,
      "$1[redacted]",
    )
    .replaceAll(/sk-(?:proj-)?[A-Za-z0-9_*=-]{8,}/gu, "[redacted]")
    .replaceAll(/(?:github_pat_|gh[pousr]_)[A-Za-z0-9_-]{8,}/giu, "[redacted]")
    .replaceAll(/npm_[A-Za-z0-9_-]{8,}/giu, "[redacted]")
    .replaceAll(
      /(^|%20|[^A-Za-z0-9_])(Bearer|Basic|Token)((?:\s|%20|\+)+)[A-Za-z0-9.%_~+/*=-]+/giu,
      "$1$2$3[redacted]",
    )
    .replaceAll(/((?:https?|ssh|git\+ssh):\/\/)[^\s/@]+@/giu, "$1[redacted]@")
    .replaceAll(
      /((?:[?&]|%3F|%26)(?:(?!%3F|%26|%3D)(?:[A-Za-z0-9_.%-]|\[|\])){0,64}(?:api(?:[_-]|%5F|%2D)?keys?|access(?:[_-]|%5F|%2D)?key(?:(?:[_-]|%5F|%2D)?id)?|private(?:[_-]|%5F|%2D)?key|authorization|auth|token|secret|credentials?|signature|sig|password|passwd)(?:(?:[_-]|%5F|%2D)[A-Za-z0-9_.%-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_.%-]{0,48})?(?:\]|%5D)?(?:=|%3D))(?:(?!%26)[^&\s])+/giu,
      "$1[redacted]",
    );
}

function redactQuotedCredentialValues(message: string): string {
  const assignment =
    /(\b[A-Za-z0-9_-]{0,64}(?:api[_-]?keys?|access[_-]?key(?:[_-]?id)?|private[_-]?key|authorization|auth|token|secret|credentials?|signature|sig|password|passwd)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\*["'])?\s*[:=]\s*)(\\*)(["'])/giu;
  let output = "";
  let consumed = 0;
  for (
    let match = assignment.exec(message);
    match !== null;
    match = assignment.exec(message)
  ) {
    const openingSlashes = match[2]!.length;
    const quote = match[3]!;
    let position = assignment.lastIndex;
    let closed = false;
    while (position < message.length) {
      const delimiter = message.indexOf(quote, position);
      if (delimiter < 0) break;
      let preceding = delimiter;
      while (preceding > position && message[preceding - 1] === "\\") {
        preceding -= 1;
      }
      if (delimiter - preceding === openingSlashes) {
        output += `${message.slice(consumed, assignment.lastIndex)}[redacted]${message.slice(preceding, delimiter + 1)}`;
        consumed = delimiter + 1;
        assignment.lastIndex = consumed;
        closed = true;
        break;
      }
      position = delimiter + 1;
    }
    if (!closed) {
      output += `${message.slice(consumed, assignment.lastIndex)}[redacted]`;
      consumed = message.length;
      break;
    }
  }
  return output + message.slice(consumed);
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
