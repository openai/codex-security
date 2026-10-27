import { findingEntry } from "./value.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  loadContractWithScanDirectory,
  type LoadedContract,
} from "./contract.js";
import type {
  Finding,
  FindingCodeEvidence,
  FindingLocation,
  ScanTargetRecord,
  SeverityLevel,
} from "./models.js";
import { bundledPluginRoot } from "./runtime.js";
import { CodexSecurityError } from "./errors.js";
import {
  severityClassificationSchema,
  validateSeverityClassification,
  type SeverityClassification,
  type SeverityAssessment,
} from "./classify-severity.js";
import {
  readScanSeverityClassification,
  selectClassificationFindings,
  type ScanSeverityClassification,
} from "./classify-scan-severity.js";

export interface LinearPublicationDestination {
  type: "linear";
  teamId: string;
  projectId?: string;
}

export interface PrepareScanPublicationOptions {
  destination: "linear";
  teamId: string;
  projectId?: string;
  uploadedAt?: string;
  environment?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  expectedScanId?: string;
  /** Publish only these finding IDs from the supplied scan; dedupe representatives may belong to other scans. */
  findingIds?: readonly string[];
  /** Use this assessment; otherwise use the scan's saved classification when present. */
  classification?: SeverityClassification | ScanSeverityClassification;
}

export interface PreparedPublicationIssue {
  findingId: string;
  occurrenceId: string;
  title: string;
  description: string;
  priority?: 1 | 2 | 3 | 4;
}

export interface PreparedScanPublication {
  scanId: string;
  scanDirectory: string;
  destination: LinearPublicationDestination;
  issues: PreparedPublicationIssue[];
}

export function linearPublicationArguments(
  destination: LinearPublicationDestination,
  issue: PreparedPublicationIssue,
): Pick<PreparedPublicationIssue, "title" | "description" | "priority"> & {
  team: string;
  project?: string;
} {
  return {
    team: destination.teamId,
    ...(destination.projectId === undefined
      ? {}
      : { project: destination.projectId }),
    title: issue.title,
    description: issue.description,
    ...(issue.priority === undefined ? {} : { priority: issue.priority }),
  };
}

const LINEAR_PRIORITIES = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  informational: undefined,
} as const satisfies Record<SeverityLevel, 1 | 2 | 3 | 4 | undefined>;

export async function prepareScanPublication(
  scanDirectory: string,
  options: PrepareScanPublicationOptions,
): Promise<PreparedScanPublication> {
  const { contract, scanDirectory: canonicalScanDirectory } =
    await loadContractWithScanDirectory(scanDirectory, {
      pluginRoot: await bundledPluginRoot(),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      expectedScanId: options.expectedScanId,
    });
  const uploadedAt = options.uploadedAt ?? new Date().toISOString();
  const scanId = contract.manifest.scan.id;
  let classification: SeverityClassification | undefined;
  if (options.classification !== undefined) {
    const { scanId: assessedScanId, ...assessment } =
      options.classification as ScanSeverityClassification;
    if (assessedScanId !== undefined && assessedScanId !== scanId) {
      throw new CodexSecurityError(
        "Severity classification belongs to a different scan.",
      );
    }
    classification = validateSeverityClassification(
      severityClassificationSchema.parse(assessment),
      contract.findings.findings,
    );
  } else {
    classification = await readScanSeverityClassification(
      canonicalScanDirectory,
      scanId,
      contract.findings.findings,
      options.signal,
      options.environment,
    );
  }
  const assessments = new Map(classification?.assessments.map(findingEntry));
  const selected = selectClassificationFindings(
    contract.findings.findings,
    options.findingIds ??
      classification?.assessments.map(({ findingId }) => findingId),
  );
  if (
    classification &&
    selected.some(({ findingId }) => !assessments.has(findingId))
  ) {
    throw new CodexSecurityError(
      "Selected findings are missing from the severity classification. Classify the selection before publishing.",
    );
  }

  return {
    scanId,
    scanDirectory: canonicalScanDirectory,
    destination: {
      type: options.destination,
      teamId: options.teamId,
      ...(options.projectId === undefined
        ? {}
        : { projectId: options.projectId }),
    },
    issues: selected.flatMap((finding) => {
      const assessment = assessments.get(finding.findingId);
      if (assessment?.decision === "excluded") return [];
      const level = assessment?.level ?? finding.severity.level;
      const priority = LINEAR_PRIORITIES[level];
      return {
        findingId: finding.findingId,
        occurrenceId: finding.occurrenceId,
        title: `[Codex Security][${level.toUpperCase()}] ${finding.title}`,
        description: renderFindingDescription(
          contract,
          finding,
          uploadedAt,
          assessment,
        ),
        ...(priority === undefined ? {} : { priority }),
      };
    }),
  };
}

function renderFindingDescription(
  contract: LoadedContract,
  finding: Finding,
  uploadedAt: string,
  assessment?: SeverityAssessment,
): string {
  const { scan } = contract.manifest;
  const lines = ["## Summary", "", finding.summary];
  if (assessment?.source === "rubric") {
    lines.push(
      "",
      "",
      "## Severity classification",
      "",
      `**Assessed severity:** ${assessment.level}`,
      `**Rubric label:** ${assessment.rubricLabel}`,
      "",
      assessment.rationale,
    );
    if (assessment.confidence !== null)
      lines.push("", `**Classification confidence:** ${assessment.confidence}`);
    if (assessment.reviewTrigger !== null)
      lines.push("", `**Review trigger:** ${assessment.reviewTrigger}`);
  }

  if (finding.attackPath?.summary !== undefined) {
    lines.push("", "## Reproduction summary", "", finding.attackPath.summary);
  }

  const rootCause = publicationRootCause(finding);
  if (typeof rootCause === "string") {
    lines.push("", "## Root cause", "", rootCause);
  } else if (
    rootCause !== undefined &&
    (rootCause.summary !== undefined || rootCause.code !== undefined)
  ) {
    lines.push("", "## Root cause");
    if (rootCause.summary !== undefined) lines.push("", rootCause.summary);
    if (rootCause.code !== undefined) {
      lines.push("", fencedCode(rootCause.code, rootCause.language));
    }
  }

  lines.push("", "## Remediation", "", finding.remediation);

  const validation = finding.validation;
  const limits = [
    ...new Set([
      ...(validation?.limitations ?? []),
      ...(validation?.counterEvidence ?? []),
      ...(finding.attackPath?.limitations ?? []),
    ]),
  ];
  if (validation?.summary || validation?.method || limits.length > 0) {
    lines.push("", "## Validation", "");
    if (validation?.summary) lines.push(validation.summary, "");
    if (validation?.method) lines.push(`**Method:** ${validation.method}`, "");
    lines.push(...limits.map((limit) => `- ${limit}`));
  }

  const codeEvidence = publicationCodeEvidence(finding);
  if (codeEvidence.length > 0) {
    lines.push("", "## Source-code evidence");
    for (const [index, evidence] of codeEvidence.entries()) {
      lines.push("", ...renderCodeEvidence(scan.target, evidence, index));
    }
  }

  lines.push(
    "",
    "---",
    "",
    "## Codex Security finding",
    "",
    `**Scan ID:** ${scan.id}`,
    `**Finding ID:** ${finding.findingId}`,
    `**Occurrence ID:** ${finding.occurrenceId}`,
    `**Fingerprint:** ${finding.fingerprints.primary}`,
    `**Severity:** ${finding.severity.level.toUpperCase()}`,
    `**Confidence:** ${finding.confidence.level.toUpperCase()}`,
    ...(finding.taxonomy.cwe.length === 0
      ? []
      : [`**CWE:** ${finding.taxonomy.cwe.join(", ")}`]),
    "",
    "## Scanned code",
    "",
    `**Repository:** ${scan.target.displayName}`,
    ...(scan.target.remote === undefined
      ? []
      : [`**Remote:** ${scan.target.remote}`]),
    ...renderTargetIdentity(scan.target),
    `**Scanned scope:** ${scan.scope.includePaths.join(", ") || "entire repository"}`,
    ...(scan.scope.excludePaths.length === 0
      ? []
      : [`**Excluded scope:** ${scan.scope.excludePaths.join(", ")}`]),
    `**Scan mode:** ${scanMode(contract.mode)}`,
    `**Started:** ${scan.startedAt}`,
    `**Completed:** ${scan.completedAt}`,
    `**Uploaded:** ${uploadedAt}`,
    "",
    "### Affected locations",
    "",
    ...finding.locations.map((location) =>
      renderLocation(scan.target, location),
    ),
  );
  return `${lines.join("\n")}\n`;
}

function renderTargetIdentity(target: ScanTargetRecord): string[] {
  const lines: string[] = [];
  if (target.revision !== undefined) {
    const label = target.kind === "git_revision" ? "Revision" : "Base revision";
    lines.push(`**${label}:** ${target.revision}`);
  }
  if (target.baseRevision !== undefined) {
    lines.push(`**Diff base revision:** ${target.baseRevision}`);
  }
  if (target.headRevision !== undefined) {
    lines.push(`**Diff head revision:** ${target.headRevision}`);
  }
  if (target.snapshotDigest !== undefined) {
    lines.push(`**Snapshot digest:** ${target.snapshotDigest}`);
  }
  return lines;
}

function scanMode(mode: LoadedContract["mode"]): string {
  if (mode === "deep_repository") return "deep";
  if (mode === "repository") return "standard";
  return mode;
}

function renderLocation(
  target: ScanTargetRecord,
  location: FindingLocation,
): string {
  const role =
    location.role === undefined ? "Location" : humanizeRole(location.role);
  const label = `${location.path}:${location.startLine}${
    location.endLine === undefined || location.endLine === location.startLine
      ? ""
      : `-${location.endLine}`
  }`;
  const sourceUrl = immutableSourceUrl(target, location);
  const formattedLabel = inlineCode(label);
  return `- **${role}:** ${sourceUrl === undefined ? formattedLabel : `[${formattedLabel}](${sourceUrl})`}`;
}

function renderCodeEvidence(
  target: ScanTargetRecord,
  evidence: PublicationCodeEvidence,
  index: number,
): string[] {
  const lines = [`### ${evidence.label ?? `Code evidence ${index + 1}`}`, ""];
  if (typeof evidence["location"] === "string") {
    lines.push(
      `- **${evidence.role === undefined ? "Location" : humanizeRole(evidence.role)}:** ${inlineCode(evidence["location"])}`,
      "",
    );
  } else if (evidence.path !== undefined) {
    lines.push(
      evidence.startLine === undefined
        ? `- **${evidence.role === undefined ? "Location" : humanizeRole(evidence.role)}:** ${inlineCode(evidence.path)}`
        : renderLocation(target, {
            ...evidence,
            path: evidence.path,
            startLine: evidence.startLine,
          }),
      "",
    );
  }
  lines.push(fencedCode(evidence.code, evidence.language));
  if (evidence.explanation !== undefined) lines.push("", evidence.explanation);
  return lines;
}

function publicationRootCause(finding: Finding) {
  const canonical = finding.rootCause;
  const legacy = finding.root_cause;
  if (canonical === undefined) return legacy ?? undefined;
  if (legacy === undefined || legacy === null) return canonical;
  const details: Array<{ summary?: string; code?: string; language?: string }> =
    [canonical, legacy].map((detail) =>
      typeof detail === "string" ? { summary: detail } : detail,
    );
  const summary = details.find((detail) => detail.summary?.trim())?.summary;
  const code = details.find((detail) => detail.code?.trim())?.code;
  const language = details.find(
    (detail) => detail.code === code && detail.language?.trim(),
  )?.language;
  return summary === undefined && code === undefined
    ? undefined
    : { summary, code, language };
}

type PublicationCodeEvidence = Partial<FindingCodeEvidence> &
  Pick<FindingCodeEvidence, "code">;

function publicationCodeEvidence(finding: Finding): PublicationCodeEvidence[] {
  const evidence: PublicationCodeEvidence[] = (finding.codeEvidence ?? []).map(
    (item) =>
      typeof item["location"] === "string" || isRecord(item["location"])
        ? publicationEvidenceEntry(item, item.code)
        : item,
  );
  const ids = new Set(
    evidence.filter((item) => item.code.trim()).map((item) => item.id),
  );
  for (const item of finding.code_evidence ?? []) {
    if (ids.has(item.id)) continue;
    if (item.code.trim()) ids.add(item.id);
    evidence.push(publicationEvidenceEntry(item, item.code));
  }
  const snippets = new Set(
    evidence.map((item) => JSON.stringify([item.id ?? "", item.code])),
  );
  const attackPath = finding.attackPath;
  for (const section of [
    finding.rootCause,
    finding.root_cause,
    finding.validation,
    attackPath,
    attackPath?.dataFlow,
    attackPath?.["dataflow"],
    attackPath?.data_flow,
    attackPath?.reachability,
  ]) {
    if (!isRecord(section)) continue;
    for (const key of ["codeEvidence", "code_evidence"]) {
      const embedded = section[key];
      if (!Array.isArray(embedded)) continue;
      for (const item of embedded) {
        if (!isRecord(item)) continue;
        const code = item["code"];
        if (typeof code !== "string" || !code.trim()) continue;
        const identity = JSON.stringify([item["id"] ?? "", code]);
        if (snippets.has(identity)) continue;
        snippets.add(identity);
        evidence.push(publicationEvidenceEntry(item, code));
      }
    }
  }
  return evidence;
}

function publicationEvidenceEntry(
  item: Record<string, unknown>,
  code: string,
): PublicationCodeEvidence {
  const entry: PublicationCodeEvidence = { code };
  for (const key of [
    "id",
    "label",
    "language",
    "role",
    "explanation",
  ] as const) {
    const value = item[key];
    if (typeof value === "string" && value.length > 0) entry[key] = value;
  }
  if (typeof item["location"] === "string") {
    const label = item["location"].trim().replace(/\s+/g, " ");
    if (label) entry["location"] = label;
    return entry;
  }
  const location = isRecord(item["location"]) ? item["location"] : item;
  const path = location["path"];
  if (typeof path === "string" && path.length > 0) entry.path = path;
  const start = location["startLine"];
  if (typeof start === "number" && Number.isInteger(start) && start > 0) {
    entry.startLine = start;
    const end = location["endLine"];
    if (typeof end === "number" && Number.isInteger(end) && end >= start)
      entry.endLine = end;
  }
  return entry;
}

function humanizeRole(role: string): string {
  const words = role.replaceAll("_", " ");
  return `${words.slice(0, 1).toUpperCase()}${words.slice(1)}`;
}

function inlineCode(label: string): string {
  let fenceLength = 1;
  for (const match of label.matchAll(/`+/g)) {
    fenceLength = Math.max(fenceLength, match[0].length + 1);
  }
  const fence = "`".repeat(fenceLength);
  const padding = label.startsWith("`") || label.endsWith("`") ? " " : "";
  return `${fence}${padding}${label}${padding}${fence}`;
}

function fencedCode(code: string, language?: string): string {
  let fenceLength = 3;
  for (const match of code.matchAll(/`+/g)) {
    fenceLength = Math.max(fenceLength, match[0].length + 1);
  }
  const fence = "`".repeat(fenceLength);
  const tag =
    language !== undefined && /^[A-Za-z0-9_+.-]+$/.test(language)
      ? language
      : "";
  return `${fence}${tag}\n${code}\n${fence}`;
}

function immutableSourceUrl(
  target: ScanTargetRecord,
  location: FindingLocation,
): string | undefined {
  if (
    target.kind !== "git_revision" ||
    target.remote === undefined ||
    target.revision === undefined ||
    !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(target.revision) ||
    !isSafeRepositoryPath(location.path)
  ) {
    return undefined;
  }

  let remote: URL;
  try {
    remote = new URL(target.remote);
  } catch {
    return undefined;
  }
  if (remote.protocol !== "https:" || !isGitHubCloudHost(remote.hostname)) {
    return undefined;
  }

  const repository = remote.pathname
    .replace(/\.git\/?$/, "")
    .replace(/\/$/, "");
  const path = location.path.split("/").map(encodeURIComponent).join("/");
  remote.pathname = `${repository}/blob/${target.revision}/${path}`;
  remote.hash = `L${location.startLine}${
    location.endLine === undefined || location.endLine === location.startLine
      ? ""
      : `-L${location.endLine}`
  }`;
  return remote.toString();
}

function isSafeRepositoryPath(path: string): boolean {
  if (
    path.includes("\\") ||
    /^[A-Za-z]:/.test(path) ||
    /[\u0000-\u001f\u007f]/.test(path)
  ) {
    return false;
  }

  return path
    .split("/")
    .every(
      (segment) =>
        segment.length > 0 &&
        segment !== "." &&
        segment !== ".." &&
        !/%(?:2e|2f|5c)/i.test(segment),
    );
}
