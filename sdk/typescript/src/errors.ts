import { formatUsd, type ScanCost } from "./cost.js";

/** Returns an error message with credential-shaped substrings redacted. */
export function redactedErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const sensitiveRanges: Array<[number, number]> = [];
  const privateKeys = new Map<string, number[]>();
  const lineStart = /(?:$|[\r\n]|\\+[nr])/uy;
  const lineEnd =
    /(?:$|[\r\n]|\\+[nr]|\\*["'](?=$|[,}\]\r\n])|[ \t]+[A-Za-z][A-Za-z0-9_-]*=)/uy;
  for (const match of message.matchAll(
    /-----(BEGIN|END) ([A-Z0-9 ]*PRIVATE KEY)-----/giu,
  )) {
    const label = match[2]!;
    if (match[1]!.toUpperCase() === "BEGIN") {
      lineStart.lastIndex = match.index + match[0].length;
      if (!lineStart.test(message)) {
        let previous = match.index - 1;
        while (message[previous] === " " || message[previous] === "\t") {
          previous -= 1;
        }
        if (message[previous] !== "=" && message[previous] !== ":") continue;
      }
      const starts = privateKeys.get(label) ?? [];
      starts.push(match.index);
      privateKeys.set(label, starts);
      continue;
    }

    const previous = message[match.index - 1];
    if (
      previous !== "\n" &&
      previous !== "\r" &&
      !(
        (previous === "n" || previous === "r") &&
        message[match.index - 2] === "\\"
      )
    ) {
      continue;
    }
    const end = match.index + match[0].length;
    lineEnd.lastIndex = end;
    if (!lineEnd.test(message)) continue;
    const start = privateKeys.get(label)?.pop();
    if (start !== undefined) sensitiveRanges.push([start, end]);
  }
  for (const starts of privateKeys.values()) {
    for (const start of starts) sensitiveRanges.push([start, message.length]);
  }
  return redactQuotedCredentialValues(message, sensitiveRanges)
    .replaceAll(
      /(\b[A-Za-z0-9_-]{0,64}(?:authorization|auth)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\?["'])?\s*[:=]\s*)([A-Za-z][A-Za-z0-9._~-]{0,63})((?:\s|%20|\+)+)(?!\[redacted\]|(?!key\s*=)[A-Za-z_][A-Za-z0-9_-]{0,64}\s*[:=]\s*(?=[^=\s"',;}&\\\]]))[^\s"',;}&\\\]]+/giu,
      "$1$2$3[redacted]",
    )
    .replaceAll(
      /(\b[A-Za-z0-9_-]{0,64}(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|private[_-]?key|authorization|auth|token|secret|credential|signature|sig|password|passwd)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)(?!\[redacted\]|[A-Za-z][A-Za-z0-9._~-]{0,63}(?:\s|%20|\+)+\[redacted\])[^\s"',;}&\\\]]+/giu,
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
      /((?:[?&]|%3F|%26)(?:(?!%3F|%26|%3D)(?:[A-Za-z0-9_.%-]|\[|\])){0,64}(?:api[_-]?key|access(?:[_-]|%5F|%2D)?key(?:(?:[_-]|%5F|%2D)?id)?|private(?:[_-]|%5F|%2D)?key|authorization|auth|token|secret|credential|signature|sig|password|passwd)(?:(?:[_-]|%5F|%2D)[A-Za-z0-9_.%-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_.%-]{0,48})?(?:\]|%5D)?(?:=|%3D))(?:(?!%26)[^&\s])+/giu,
      "$1[redacted]",
    );
}

function redactQuotedCredentialValues(
  message: string,
  ranges: Array<[number, number]>,
): string {
  const assignment =
    /(\b[A-Za-z0-9_-]{0,64}(?:api[_-]?key|access[_-]?key(?:[_-]?id)?|private[_-]?key|authorization|auth|token|secret|credential|signature|sig|password|passwd)(?:[_-][A-Za-z0-9_-]{1,64}|(?:value|data|token|secret|credential|password|header|field|id|key)[A-Za-z0-9_-]{0,48})?\b(?:\\*["'])?\s*[:=]\s*)(\\*)(["'])/giu;
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
        ranges.push([assignment.lastIndex, preceding]);
        assignment.lastIndex = delimiter + 1;
        closed = true;
        break;
      }
      position = delimiter + 1;
    }
    if (!closed) {
      ranges.push([assignment.lastIndex, message.length]);
      break;
    }
  }

  const merged: Array<[number, number]> = [];
  for (const [start, end] of ranges.sort(
    ([leftStart], [rightStart]) => leftStart - rightStart,
  )) {
    const previous = merged.at(-1);
    if (previous !== undefined && start <= previous[1]) {
      previous[1] = Math.max(previous[1], end);
    } else {
      merged.push([start, end]);
    }
  }

  let output = "";
  let consumed = 0;
  for (const [start, end] of merged) {
    output += `${message.slice(consumed, start)}[redacted]`;
    consumed = end;
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
