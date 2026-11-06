import { isNativeError, isNumberObject } from "node:util/types";
import { CodexSecurityError } from "./errors.js";
import type { LocalExternalImportOptions } from "./external-findings-import.js";
import {
  checkEmittedJsonNumber,
  checkReportNumber,
  requireCloudEvidenceDepth,
  requireJsonNumber,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";

/** A provider occurrence and its evidence, independent of a Codex assessment. */
export interface ExternalFinding {
  source_finding_id: string;
  evidence: ExternalFindingEvidence;
}

/** Repository provenance retained by a reader outside the published evidence. */
export interface ExternalSourceRepository {
  url: string;
  platform?: "github" | "gitlab";
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

export function hasNoExternalRecords(input: ExternalFindings): boolean {
  return input.read === 0 && !input.findings.length && !input.excluded.length;
}

/** Classify a reader selection before deciding whether to store, publish, or report it. */
export function externalImportDisposition(
  input: ExternalFindings,
): "ready" | "empty" | "excluded" | "failed" {
  if (input.findings.length) return "ready";
  const errors = input.report?.["errors"];
  if (Array.isArray(errors) && errors.length) return "failed";
  if (hasNoExternalRecords(input)) return "empty";
  return input.read === input.excluded.length ? "excluded" : "failed";
}

/** No findings can be imported. The selection retains every reader exclusion and diagnostic. */
export class NoPublishableFindingsError extends CodexSecurityError {
  readonly summary: string;

  constructor(public readonly selection: ExternalFindings) {
    const diagnostics = reportForJson(selection.report)?.["errors"];
    const summary =
      externalImportDisposition(selection) === "empty"
        ? "No supported findings are ready to publish: the report is empty."
        : `No supported findings are ready to publish (${selection.read} read, ${selection.excluded.length} excluded).${Array.isArray(diagnostics) && diagnostics.length ? ` Scanner diagnostics: ${JSON.stringify(diagnostics)}` : ""}`;
    const reasons = selection.excluded.map(
      (item) => `Item ${item.position}: ${item.reason}`,
    );
    super([summary, ...reasons].join(" "));
    this.summary = summary;
  }
}

export function reportForJson(report: ExternalFindings["report"]) {
  const errors = report?.["errors"];
  if (!Array.isArray(errors)) return report;
  const json = JSON.stringify(errors, (_key, entry: unknown) =>
    entry instanceof Error ? { ...entry, message: entry.message } : entry,
  );
  return { ...report, errors: JSON.parse(json) as unknown[] };
}

const isScannerError = Error.isError ?? isNativeError;
export const nativeErrorStackGetter = Object.getOwnPropertyDescriptor(
  new Error(),
  "stack",
)?.get;

function cloneScannerDiagnostic(source: Error): Error {
  const message = Object.getOwnPropertyDescriptor(source, "message");
  const stack = Object.getOwnPropertyDescriptor(source, "stack");
  try {
    if (
      (!message || Object.hasOwn(message, "value")) &&
      (!stack?.get || stack.get === nativeErrorStackGetter)
    )
      return structuredClone(source);
    // Keep the native error type and data-valued cause without running a
    // caller-supplied message or stack getter while restoring diagnostics.
    const cause = Object.getOwnPropertyDescriptor(source, "cause");
    const clean = new Error(message?.value, { cause: cause?.value });
    const name = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(source),
      "name",
    )?.value;
    if (typeof name === "string") clean.name = name;
    if (!message?.get && nativeErrorStackGetter) {
      const nativeStack: unknown = nativeErrorStackGetter.call(source);
      if (typeof nativeStack === "string") clean.stack = nativeStack;
    }
    return structuredClone(clean);
  } catch {
    // A noncloneable cause does not prevent JSON export.
    return new Error(message?.value);
  }
}

/** @internal Capture fresh input once, so preview, limits and storage use the same JSON. */
export function snapshotNormalizedFindings<T extends Partial<ExternalFindings>>(
  input: T,
  checkEvidenceNumber = (value: number) => requireJsonNumber(value, "Evidence"),
  target: ExternalImportTarget = "local",
): T {
  const fields = new Map<string, unknown>();
  const errors: { path: string[]; error: Error }[] = [];
  let root: unknown;

  function captureField(field: string, observed: unknown): string | undefined {
    const parents: { key: string; value: object }[] = [];
    // The outer traversal already called this field's toJSON with its real key.
    // Returning that value from the wrapper keeps JSON from calling it twice.
    return JSON.stringify(
      { toJSON: () => observed },
      function (this: object, key, value: unknown) {
        while (parents.length && parents.at(-1)!.value !== this) parents.pop();
        const evidence = field === "findings" && parents[2]?.key === "evidence";
        if (evidence && target === "cloud")
          requireCloudEvidenceDepth(parents.length - 2, this, value);
        if (isNumberObject(value)) value = +value;
        if (field === "report") checkReportNumber(value);
        if (evidence) checkEmittedJsonNumber(value, checkEvidenceNumber);
        if (value !== null && typeof value === "object") {
          if (value === root) {
            const path = [field, ...parents.slice(1).map((p) => p.key)];
            if (parents.length) path.push(key);
            throw new TypeError(
              `Converting circular structure to JSON at ${JSON.stringify(path)}`,
            );
          }
          if (
            field === "report" &&
            parents[1]?.key === "errors" &&
            Array.isArray(parents[1].value) &&
            isScannerError(value)
          ) {
            errors.push({
              path: [field, ...parents.slice(1).map((p) => p.key), key],
              error: value,
            });
          }
          parents.push({ key, value });
        }
        return value;
      },
    );
  }

  // Capture each member in native property order. A report and a findings
  // payload can each fit in a string while their combined JSON does not.
  const envelope = JSON.stringify(
    input,
    function (this: object, field, value: unknown) {
      if (this !== root) {
        root = value;
        return value;
      }
      const json = captureField(field, value);
      if (json === undefined) return undefined;
      fields.set(field, JSON.parse(json));
      return null;
    },
  );
  const result = JSON.parse(envelope);
  for (const [key, value] of fields) result[key] = value;
  for (const { path, error: source } of errors) {
    const key = path.pop()!;
    let parent = result as unknown as Record<string, unknown>;
    for (const field of path) parent = parent[field] as Record<string, unknown>;
    const error = cloneScannerDiagnostic(source);
    Object.defineProperties(
      error,
      Object.getOwnPropertyDescriptors(parent[key] as object),
    );
    parent[key] = error;
  }
  return result;
}

/** @internal Clone owned values without serializing the evidence again in every preview view. */
export function cloneImportPreview<T extends ExternalFindings>(input: T): T {
  if (input.report === undefined) return structuredClone(input);
  return {
    ...structuredClone({ ...input, report: undefined }),
    ...snapshotNormalizedFindings({ report: input.report }),
  };
}

/** @internal Keep earlier provider projections only for immutable request replay. */
export interface ExternalPublicationInput {
  current: ExternalFindings;
  legacy: ExternalFindings;
  currentIdentity: unknown;
  legacyIdentity: unknown;
}

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends LocalExternalImportOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  sourceRepositoryUrl,
  trivyScanRoot,
  inspectorProjectMap,
}: LocalExternalImportOptions & { provider: P }) {
  if (provider === "trivy" && sourceRepositoryUrl !== undefined)
    throw new CodexSecurityError(
      "Trivy reads repository provenance from the report; do not supply --source-repository-url.",
    );
  if (trivyScanRoot !== undefined && provider !== "trivy")
    throw new CodexSecurityError(
      "--trivy-scan-root applies only to --provider trivy.",
    );
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
