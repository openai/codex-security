import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { readRegularInputFile } from "./prompt-files.js";
import { resolveInputPath, type ProcessEnvironment } from "./runtime.js";
import { CodexSecurityError } from "./errors.js";
import { isRecord as isJsonObject } from "./record.js";

/** Canonical finding identity used to pair issues across saved scans. */
export const SCAN_DIFF_IDENTITY_FIELD = "findingId" as const;

/**
 * `findingId` is derived from the scan target, `ruleId`, `identity.anchor`,
 * and optional `identity.instance`. Title, summary, and other description
 * fields are not part of the identity, so rewriting a description does not
 * count as a new finding.
 */
export const SCAN_DIFF_IDENTITY_RULE =
  "Findings are the same issue when they share findingId. That ID is derived from the scan target, ruleId, identity.anchor, and optional identity.instance. Title and summary are not part of the identity.";

export type ScanDiffStatus = "new" | "resolved" | "unchanged";

export type ScanDiffFinding = {
  findingId?: unknown;
  occurrenceId?: unknown;
  title?: unknown;
  severity?: unknown;
  path?: unknown;
  locations?: unknown;
} & Record<string, unknown>;

export interface ScanDiffInput {
  scanId: string;
  findings: readonly ScanDiffFinding[];
}

export interface ScanDiffEntry {
  status: ScanDiffStatus;
  findingId: string;
  title: string;
  severity?: string;
  path?: string;
  beforeOccurrenceId?: string;
  afterOccurrenceId?: string;
  beforeOccurrenceIds?: string[];
  afterOccurrenceIds?: string[];
}

export interface ScanDiffResult {
  beforeScanId: string;
  afterScanId: string;
  identity: {
    field: typeof SCAN_DIFF_IDENTITY_FIELD;
    rule: typeof SCAN_DIFF_IDENTITY_RULE;
  };
  summary: Record<ScanDiffStatus, number>;
  findings: ScanDiffEntry[];
}

const STATUS_ORDER: readonly ScanDiffStatus[] = [
  "new",
  "resolved",
  "unchanged",
];

export function findingIdentityKey(
  finding: ScanDiffFinding,
): string | undefined {
  const id = finding.findingId;
  return typeof id === "string" && id.trim().length > 0 ? id.trim() : undefined;
}

export function diffScanFindings(
  before: ScanDiffInput,
  after: ScanDiffInput,
): ScanDiffResult {
  if (before.scanId === after.scanId) {
    throw new CodexSecurityError("Select two different scans to diff.");
  }
  const beforeGroups = groupByIdentity(before.findings);
  const afterGroups = groupByIdentity(after.findings);
  const identities = new Set([...beforeGroups.keys(), ...afterGroups.keys()]);
  const findings: ScanDiffEntry[] = [];
  const summary: Record<ScanDiffStatus, number> = {
    new: 0,
    resolved: 0,
    unchanged: 0,
  };
  for (const identity of identities) {
    const previous = beforeGroups.get(identity) ?? [];
    const current = afterGroups.get(identity) ?? [];
    const status: ScanDiffStatus =
      previous.length > 0 && current.length > 0
        ? "unchanged"
        : current.length > 0
          ? "new"
          : "resolved";
    const selected = (current[0] ?? previous[0])!;
    const entry: ScanDiffEntry = {
      status,
      findingId:
        findingIdentityKey(selected) ??
        occurrenceId(selected) ??
        "(unidentified)",
      title: findingTitle(selected),
    };
    const severity = findingSeverity(selected);
    const path = findingPath(selected);
    if (severity !== undefined) entry.severity = severity;
    if (path !== undefined) entry.path = path;
    assignOccurrenceIds(entry, "before", previous);
    assignOccurrenceIds(entry, "after", current);
    findings.push(entry);
    summary[status] += 1;
  }
  findings.sort(
    (left, right) =>
      STATUS_ORDER.indexOf(left.status) - STATUS_ORDER.indexOf(right.status) ||
      left.findingId.localeCompare(right.findingId),
  );
  return {
    beforeScanId: before.scanId,
    afterScanId: after.scanId,
    identity: {
      field: SCAN_DIFF_IDENTITY_FIELD,
      rule: SCAN_DIFF_IDENTITY_RULE,
    },
    summary,
    findings,
  };
}

export async function tryLoadScanDiffFromPath(
  reference: string,
  cwd: string,
  environment?: ProcessEnvironment,
): Promise<ScanDiffInput | undefined> {
  const path = resolveInputPath(reference, cwd, environment);
  const stats = await lstat(path, { bigint: true }).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      if (looksLikeFilesystemReference(reference)) {
        throw new CodexSecurityError(
          `Saved scan ${reference} was not found at ${path}.`,
          { cause: error },
        );
      }
      return undefined;
    },
  );
  if (!stats) return undefined;
  const directory = stats.isDirectory();
  if (!directory && (!stats.isFile() || !isFindingsFileName(path))) {
    throw new CodexSecurityError(
      `Saved scan ${reference} is not a findings.json file or scan directory.`,
    );
  }
  const findingsPath = directory ? join(path, "findings.json") : path;
  const text = await readRegularInputFile(
    findingsPath,
    cwd,
    directory ? undefined : stats,
  ).catch((error: NodeJS.ErrnoException) => {
    if (directory && error.code === "ENOENT") {
      throw new CodexSecurityError(
        `Scan directory ${path} does not contain findings.json.`,
        { cause: error },
      );
    }
    throw error;
  });
  return parseSavedScanFindings(text, findingsPath);
}

export function parseSavedScanFindings(
  text: string,
  source: string,
): ScanDiffInput {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new CodexSecurityError(`Could not parse findings from ${source}.`, {
      cause: error,
    });
  }
  if (!isJsonObject(document) || !Array.isArray(document["findings"])) {
    throw new CodexSecurityError(
      `Saved scan ${source} does not contain a findings list.`,
    );
  }
  const findings = document["findings"].map((finding, index) => {
    if (!isJsonObject(finding)) {
      throw new CodexSecurityError(
        `Saved scan ${source} has an invalid finding at index ${index}.`,
      );
    }
    return finding;
  });
  const recordedId = document["scanId"];
  if (typeof recordedId !== "string" || !recordedId.trim()) {
    throw new CodexSecurityError(
      `Saved scan ${source} does not contain a scan ID.`,
    );
  }
  return { scanId: recordedId, findings };
}

function groupByIdentity(
  findings: readonly ScanDiffFinding[],
): Map<string | symbol, ScanDiffFinding[]> {
  // A finding without a stable ID stays unmatched, even when occurrence IDs overlap.
  return Map.groupBy(
    findings,
    (finding) => findingIdentityKey(finding) ?? Symbol(),
  );
}

function assignOccurrenceIds(
  entry: ScanDiffEntry,
  side: "before" | "after",
  findings: readonly ScanDiffFinding[],
): void {
  const ids = findings.flatMap((finding) => {
    const id = occurrenceId(finding);
    return id === undefined ? [] : [id];
  });
  if (ids.length === 1) {
    entry[`${side}OccurrenceId`] = ids[0];
  } else if (ids.length > 1) {
    entry[`${side}OccurrenceIds`] = ids;
  }
}

function occurrenceId(finding: ScanDiffFinding): string | undefined {
  return typeof finding.occurrenceId === "string" &&
    finding.occurrenceId.trim().length > 0
    ? finding.occurrenceId
    : undefined;
}

function findingTitle(finding: ScanDiffFinding): string {
  return typeof finding.title === "string" && finding.title.trim().length > 0
    ? finding.title
    : "Untitled finding";
}

function findingSeverity(finding: ScanDiffFinding): string | undefined {
  const severity = finding.severity;
  if (typeof severity === "string" && severity.trim().length > 0)
    return severity;
  if (isJsonObject(severity) && typeof severity["level"] === "string")
    return severity["level"];
}

function findingPath(finding: ScanDiffFinding): string | undefined {
  if (typeof finding.path === "string" && finding.path.trim().length > 0)
    return finding.path;
  const locations = finding.locations;
  if (!Array.isArray(locations)) return;
  const location = locations.find(isJsonObject);
  return typeof location?.["path"] === "string" ? location["path"] : undefined;
}

function looksLikeFilesystemReference(value: string): boolean {
  return (
    value === "~" ||
    value.startsWith("~/") ||
    value.startsWith("~\\") ||
    value.startsWith(".") ||
    value.includes("/") ||
    value.includes("\\") ||
    isFindingsFileName(value)
  );
}

function isFindingsFileName(value: string): boolean {
  return /(^|[/\\])findings\.json$/iu.test(value);
}
