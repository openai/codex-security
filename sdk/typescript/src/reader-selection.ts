import { hash } from "node:crypto";
import { isBoxedPrimitive, isProxy } from "node:util/types";
import type { ExternalFindings } from "./external-findings.js";
import { canonicalJson } from "./record.js";

export interface LegacyReaderSelection {
  sourceFindingIds: string[];
  snapshot?: ExternalFindings;
  unprovenIdPrefixes?: string[];
  uncertainFindingIds?: string[];
  knownFindings?: ExternalFindings["findings"];
}
const previousSelections = new WeakMap<
  object,
  { exported?: string; previous: LegacyReaderSelection }
>();

export function rememberPreviousSelection(
  result: ExternalFindings,
  prior: LegacyReaderSelection,
): void {
  // Stop-only hints do not require hashing unbounded local evidence.
  const exported =
    prior.snapshot || prior.knownFindings
      ? hash("sha256", canonicalJson(result, undefined, isBoxedPrimitive))
      : undefined;
  const selection = { exported, previous: prior };
  previousSelections.set(result, selection);
  previousSelections.set(result.findings, selection);
}

/** Only unchanged SDK output can identify an older, differently serialized selection. */
export function previousReaderSelection(
  input: ExternalFindings,
  current: ExternalFindings,
): LegacyReaderSelection | undefined {
  const selection =
    previousSelections.get(input) ??
    (!isProxy(input) &&
      previousSelections.get(
        Object.getOwnPropertyDescriptor(input, "findings")?.value,
      ));
  if (!selection) return undefined;
  return selection.exported &&
    hash("sha256", canonicalJson(current)) === selection.exported
    ? selection.previous
    : {
        sourceFindingIds: selection.previous.sourceFindingIds,
        unprovenIdPrefixes: selection.previous.unprovenIdPrefixes,
        uncertainFindingIds: selection.previous.uncertainFindingIds,
      };
}
