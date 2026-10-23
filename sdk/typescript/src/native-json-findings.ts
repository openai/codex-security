import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";
import {
  record,
  relativePath,
  requiredText,
  strings,
  text,
} from "./scanner-import.js";

export function sourceRepositoryUrl(value: unknown, origin: string): string {
  const supplied = requiredText(
    value,
    `${origin} sourceRepositoryUrl (--source-repository-url)`,
  );
  const url = new URL(supplied);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new Error(
      "Use an HTTP(S) source repository URL without credentials.",
    );
  return supplied;
}

export function ungatedText(value: unknown): string | null {
  const supplied = text(value);
  // Semgrep CE emits this placeholder for gated fields.
  return supplied === "requires login" ? null : supplied;
}

export function messageText(value: unknown, origin: string): string | null {
  if (typeof value !== "string")
    throw new Error(`Expected a ${origin} message string.`);
  return text(value);
}

export function weaknessIds(value: unknown): string[] {
  const labels = typeof value === "string" ? [value] : strings(value);
  return [
    ...new Set(
      labels.flatMap((label) => {
        const match = /^(CWE-\d+)(?::|$)/u.exec(label);
        return match ? [match[1]!] : [];
      }),
    ),
  ];
}

export function position(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new Error(`${label} must be a positive integer.`);
  return value;
}

/** Parse the native code-result fields shared by Semgrep and OpenGrep. */
export function parseNativeJsonResult(value: unknown, origin: string) {
  const result = record(value, `${origin} result`);
  const extra = record(result["extra"], `${origin} extra`);
  const metadata = record(extra["metadata"] ?? {}, `${origin} metadata`);
  const product = metadata["product"];
  const validation = extra["validation_state"];
  if (
    (product != null && product !== "sast") ||
    extra["sca_info"] != null ||
    extra["historical_info"] != null ||
    (validation != null && validation !== "NO_VALIDATOR")
  )
    throw new Error(
      `This adapter supports ${origin} SAST; Supply Chain and Secrets reports need separate qualification.`,
    );
  const rule = requiredText(result["check_id"], `${origin} check_id`);
  const rawPath = requiredText(result["path"], `${origin} path`);
  const start = record(result["start"], `${origin} start`);
  const end = record(result["end"], `${origin} end`);
  const line = position(start["line"], "Start line");
  const column = position(start["col"], "Start column");
  const endLine = position(end["line"], "End line");
  const endColumn = position(end["col"], "End column");
  if (endLine < line || (endLine === line && endColumn < column))
    throw new Error(`${origin} source range ends before it starts.`);
  return {
    result,
    extra,
    metadata,
    rule,
    rawPath,
    path: relativePath(rawPath),
    line,
    column,
    endLine,
    endColumn,
  };
}

export function projectNativeJsonResult(
  parsed: ReturnType<typeof parseNativeJsonResult>,
  options: {
    origin: string;
    repositoryUrl: string;
    severity: (value: unknown) => string;
    reportContext: Record<string, unknown>;
    scanErrorCount?: number;
    observations?: Record<string, unknown>[];
  },
): ExternalFindingEvidence {
  const { result, extra, metadata, rule, path, line, endLine } = parsed;
  return validateExternalEvidence({
    title: rule,
    description: messageText(extra["message"], options.origin),
    severity: options.severity(extra["severity"]),
    locations: path ? [{ path, line }] : [],
    details: {
      kind: "sast",
      repository: { url: options.repositoryUrl },
      scanner_origin: options.origin,
      rule: { id: rule },
      weakness_ids: weaknessIds(metadata["cwe"]),
      code: {
        end_line: path ? endLine : null,
        snippet: ungatedText(extra["lines"]),
      },
      source_status:
        typeof extra["is_ignored"] === "boolean"
          ? extra["is_ignored"]
            ? "ignored"
            : "open"
          : null,
    },
    source_data: structuredClone({
      report: options.reportContext,
      ...(options.scanErrorCount === undefined
        ? {}
        : { scan_error_count: options.scanErrorCount }),
      ...(options.observations
        ? { results: options.observations }
        : { result }),
    }),
  });
}
