import { isNativeError, isNumberObject } from "node:util/types";
import { CodexSecurityError } from "./errors.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import {
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
  platform?: "github";
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
  const parents: { key: string; value: object }[] = [];
  const errors: { path: string[]; error: Error }[] = [];
  const json = JSON.stringify(
    input,
    function (this: object, key, value: unknown) {
      while (parents.length && parents.at(-1)!.value !== this) parents.pop();
      if (
        target === "cloud" &&
        parents[1]?.key === "findings" &&
        parents[3]?.key === "evidence"
      )
        requireCloudEvidenceDepth(parents.length - 3, this, value);
      if (isNumberObject(value)) value = +value;
      if (typeof value === "number") {
        if (
          parents[1]?.key === "report" ||
          (parents.length === 1 && key === "report")
        )
          requireJsonNumber(value, "Scanner report");
        if (parents[1]?.key === "findings" && parents[3]?.key === "evidence")
          checkEvidenceNumber(value);
      }
      if (value !== null && typeof value === "object") {
        // The SDK exposes native Errors in report.errors and renders their messages
        // in saved receipts. Remember only those paths during the actual JSON read.
        if (
          isScannerError(value) &&
          parents[1]?.key === "report" &&
          parents[2]?.key === "errors" &&
          Array.isArray(parents[2].value)
        ) {
          errors.push({
            path: [...parents.slice(1).map((p) => p.key), key],
            error: value,
          });
        }
        parents.push({ key, value });
      }
      return value;
    },
  );
  const result = JSON.parse(json) as T;
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
  const copy = structuredClone(input);
  if (input.report !== undefined)
    copy.report = snapshotNormalizedFindings({ report: input.report }).report;
  return copy;
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
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  sourceRepositoryUrl,
  inspectorProjectMap,
}: ExternalPublicationOptions & { provider: P }) {
  if (inspectorProjectMap !== undefined && provider !== "inspector")
    throw new CodexSecurityError(
      "An Inspector project map requires the inspector provider.",
    );
  return {
    repository,
    provider,
    sourceKey,
    sourceRepositoryUrl,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}
