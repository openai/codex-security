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
  /** Publish only these finding IDs (for example dedupe's uniqueFindingIds). */
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
  uploadId: string;
  scanDirectory: string;
  destination: LinearPublicationDestination;
  issues: PreparedPublicationIssue[];
  /** Complete sealed membership, retained when only some findings become issues. */
  sourceFindings?: Pick<
    PreparedPublicationIssue,
    "findingId" | "occurrenceId"
  >[];
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
  const assessments = new Map(
    classification?.assessments.map((assessment) => [
      assessment.findingId,
      assessment,
    ]),
  );
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
    uploadId: scanId,
    scanDirectory: canonicalScanDirectory,
    ...(classification === undefined && options.findingIds === undefined
      ? {}
      : {
          sourceFindings: contract.findings.findings.map(
            ({ findingId, occurrenceId }) => ({ findingId, occurrenceId }),
          ),
        }),
    destination: {
      type: options.destination,
      teamId: options.teamId,
      ...(options.projectId === undefined
        ? {}
        : { projectId: options.projectId }),
    },
    issues: selected
      .filter(
        ({ findingId }) => assessments.get(findingId)?.decision !== "excluded",
      )
      .map((finding) => {
        const assessment = assessments.get(finding.findingId);
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
  const { coverage } = contract;
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

  const rootCause = finding.rootCause;
  if (typeof rootCause === "string") {
    lines.push("", "## Root cause", "", rootCause);
  } else if (rootCause !== undefined) {
    lines.push("", "## Root cause", "", rootCause.summary);
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

  if (finding.codeEvidence !== undefined && finding.codeEvidence.length > 0) {
    lines.push("", "## Source-code evidence");
    for (const evidence of finding.codeEvidence) {
      lines.push("", ...renderCodeEvidence(scan.target, evidence));
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
    `**Coverage:** ${coverage.completeness}`,
    `**Coverage mode:** ${coverage.mode}`,
    `**Scan mode:** ${scanMode(coverage.mode)}`,
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

function scanMode(mode: LoadedContract["coverage"]["mode"]): string {
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
  return `- **${role}:** ${sourceUrl === undefined ? `\`${label}\`` : `[\`${label}\`](${sourceUrl})`}`;
}

function renderCodeEvidence(
  target: ScanTargetRecord,
  evidence: FindingCodeEvidence,
): string[] {
  const location: FindingLocation = {
    path: evidence.path,
    startLine: evidence.startLine,
    ...(evidence.endLine === undefined ? {} : { endLine: evidence.endLine }),
    ...(evidence.role === undefined ? {} : { role: evidence.role }),
  };
  return [
    `### ${evidence.label}`,
    "",
    renderLocation(target, location),
    "",
    fencedCode(evidence.code, evidence.language),
    "",
    evidence.explanation,
  ];
}

function humanizeRole(role: string): string {
  const words = role.replaceAll("_", " ");
  return `${words.slice(0, 1).toUpperCase()}${words.slice(1)}`;
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
  if (
    remote.protocol !== "https:" ||
    (remote.hostname !== "github.com" && !remote.hostname.endsWith(".ghe.com"))
  ) {
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
