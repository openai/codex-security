import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { isBoxedPrimitive, isProxy } from "node:util/types";
import type { ExternalFindings } from "./external-findings.js";
import { canSnapshotWithoutGetters, canonicalJson } from "./record.js";

export interface LegacyReaderSelection {
  sourceFindingIds: string[];
  snapshot?: ExternalFindings;
  unprovenIdPrefixes?: string[];
  uncertainFindingIds?: string[];
  unprovenOccurrenceCount?: number;
  knownFindings?: ExternalFindings["findings"];
}
const previousSelections = new WeakMap<
  object,
  {
    exported?: string;
    native?: ExternalFindings;
    previous: LegacyReaderSelection;
  }
>();

function nativeSelection(
  value: ExternalFindings,
): ExternalFindings | undefined {
  if (!canSnapshotWithoutGetters(value, true)) return;
  try {
    return structuredClone(value);
  } catch {
    return;
  }
}

// The registry digest is process-local. Frame both ordered lists separately so a
// local import never needs one JSON string containing all its findings.
function exportedSelectionDigest(
  result: ExternalFindings,
  preserveScalar?: (value: object) => boolean,
): string {
  const { findings, excluded, ...metadata } = result;
  const digest = createHash("sha256");
  digest.update(canonicalJson(metadata, undefined, preserveScalar));
  for (const rows of [excluded, findings]) {
    digest.update("[");
    for (let index = 0; index < rows.length; index++) {
      // Keep the array index supplied to toJSON. An omitted entry in an array
      // is JSON null, just like an explicit null or a hole.
      const entry = canonicalJson(
        { [index]: rows[index] },
        undefined,
        preserveScalar,
      );
      digest.update(entry === "{}" ? `{"${index}":null}` : entry);
    }
    digest.update("]");
  }
  return digest.digest("hex");
}

export function rememberPreviousSelection(
  result: ExternalFindings,
  prior: LegacyReaderSelection,
): void {
  // Stop-only hints do not require hashing unbounded local evidence.
  const exported =
    prior.snapshot || prior.knownFindings
      ? exportedSelectionDigest(result, isBoxedPrimitive)
      : undefined;
  const selection = {
    exported,
    native: exported ? nativeSelection(result) : undefined,
    previous: prior,
  };
  previousSelections.set(result, selection);
  previousSelections.set(result.findings, selection);
}

/** Only unchanged SDK output can identify an older, differently serialized selection. */
export function previousReaderSelection(
  input: ExternalFindings,
  current: ExternalFindings,
  native?: ExternalFindings | null,
): LegacyReaderSelection | undefined {
  const selection =
    previousSelections.get(input) ??
    (!isProxy(input) &&
      previousSelections.get(
        Object.getOwnPropertyDescriptor(input, "findings")?.value,
      ));
  if (!selection) return undefined;
  const observed = native === undefined ? nativeSelection(input) : native;
  if (selection.native && observed && selection.exported) {
    // Callers can attach a report after normalizing rows. Historical validation
    // and the saved approval still bind the independently captured report.
    const attachedReport =
      !Object.hasOwn(selection.native, "report") &&
      !Object.hasOwn(selection.previous.snapshot ?? {}, "report") &&
      observed.report !== undefined;
    const rows = (value: ExternalFindings) => {
      if (!attachedReport) return value;
      const { report: _report, ...readerOutput } = value;
      return readerOutput;
    };
    if (
      isDeepStrictEqual(selection.native, rows(observed)) &&
      exportedSelectionDigest(rows(current)) === selection.exported
    ) {
      const prior = selection.previous;
      return attachedReport && prior.snapshot
        ? { ...prior, snapshot: { ...prior.snapshot, report: observed.report } }
        : prior;
    }
  }
  // Without a verified snapshot these IDs can only stop a retry. Preserve
  // the caller's order when they rearranged the same known occurrences.
  let sourceFindingIds = selection.previous.sourceFindingIds;
  if (current.findings.length === sourceFindingIds.length) {
    const members = new Set(sourceFindingIds);
    const ordered = current.findings.map((row) => row.source_finding_id);
    if (ordered.every((id) => members.has(id))) sourceFindingIds = ordered;
  }
  return {
    sourceFindingIds,
    unprovenIdPrefixes: selection.previous.unprovenIdPrefixes,
    uncertainFindingIds: selection.previous.uncertainFindingIds,
    unprovenOccurrenceCount: selection.previous.unprovenOccurrenceCount,
  };
}
