import { promises as fs } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import dependencyResultSchema from "../../schemas/tools/dependency-artifact-result.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  listCodexSecurityCandidates,
  recordCodexSecurityDiscoveryCandidates,
  type RawDiscoveryCandidate,
  type RawDiscoveryLocationRole,
} from "./artifact-discovery.js";
import { prepareCodexSecurityReviewItems } from "./artifact-inventory.js";
import {
  artifactDestination,
  readArtifactText,
  replaceArtifactJson,
} from "./artifact-io.js";
import {
  recordCodexSecurityCandidateValidations,
  type CandidateValidationRecord,
} from "./artifact-validation-phase.js";
import {
  recordCodexSecurityCandidateAttackPaths,
  type CandidateAttackPathRecord,
} from "./artifact-attack-path.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

const documents = [commonSchema, dependencyResultSchema] as SchemaDocument[];
const inventoryComponents = ["artifacts", "02_discovery", "in_scope_files.txt"];

type FindingSeverity = "critical" | "high" | "medium" | "low" | "informational";
type FindingConfidence = "high" | "medium" | "low";

interface DependencyFindingLocation {
  path: string;
  startLine: number;
  endLine?: number;
  role?: RawDiscoveryLocationRole;
}

interface DependencyFindingEvidence {
  id: string;
  label: string;
  path: string;
  startLine: number;
  endLine?: number;
  code: string;
  explanation: string;
  role?: string;
  language?: string;
}

interface DependencyArtifactFinding {
  ruleId: string;
  identity: { anchor: string; instance?: string };
  title: string;
  summary: string;
  severity: {
    level: FindingSeverity;
    rationale?: string;
    score?: number;
    scoringSystem?: string;
    vector?: string;
    changeConditions?: string;
  };
  confidence: { level: FindingConfidence; rationale: string };
  taxonomy: { category: string; cwe: string[] };
  locations: DependencyFindingLocation[];
  codeEvidence?: DependencyFindingEvidence[];
  rootCause?: string | { summary: string; evidenceRefs?: string[] };
  remediation: string;
  remediationTests?: string[];
  preventiveControls?: string[];
}

interface PriorFindingAssessment {
  upstreamFindingId: string;
  status: "present" | "fixed" | "unknown";
  reason: string;
  evidence?: DependencyFindingEvidence[];
}

export interface DependencyArtifactResultInput {
  scanId: string;
  findings: DependencyArtifactFinding[];
  priorFindingAssessments?: PriorFindingAssessment[];
}

/** Keep the exposed tool schema derived solely from its checked-in JSON Schema. */
export const dependencyArtifactResultInputSchema = loadArtifactZodSchema(
  documents,
  dependencyResultSchema.$id,
  "input",
) as z.ZodType<DependencyArtifactResultInput>;

/** Record one package analysis using the existing trusted compact phase ledger. */
export async function recordCodexSecurityDependencyArtifactResult(
  context: ArtifactContext,
  input: DependencyArtifactResultInput,
): Promise<{
  scanId: string;
  findingsRecorded: number;
  operation: "replace";
  status: "recorded";
}> {
  if (process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN !== "1") {
    throw new Error(
      "Dependency artifact results require the trusted dependency artifact mode.",
    );
  }
  if (context.layout !== "scan") {
    throw new Error(
      "Dependency artifact results require a scan-bound artifact context.",
    );
  }

  const parsed = dependencyArtifactResultInputSchema.parse(input);
  if (context.scanId !== parsed.scanId) {
    throw new Error(
      "Dependency artifact results must match the trusted scan identity.",
    );
  }
  validatePriorFindingAssessments(
    await trustedPriorFindingIds(),
    parsed.priorFindingAssessments ?? [],
  );

  const findingsByInstance = new Map<string, DependencyArtifactFinding>();
  for (const finding of parsed.findings) {
    validateSemanticFinding(finding);
    await verifyPublishedEvidence(context, finding.codeEvidence ?? []);
    const instance = findingInstance(finding);
    if (findingsByInstance.has(instance)) {
      throw new Error(
        "Dependency artifact results repeat a stable package finding identity.",
      );
    }
    findingsByInstance.set(instance, finding);
  }
  for (const assessment of parsed.priorFindingAssessments ?? []) {
    validateSourceEvidence(assessment.evidence ?? []);
    await verifyPublishedEvidence(context, assessment.evidence ?? []);
  }

  await prepareCodexSecurityReviewItems({ ...context, mode: "standard" });
  const inventory = new Set(
    (
      await readArtifactText(
        context,
        inventoryComponents,
        "dependency artifact inventory",
      )
    )
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((path) => (path.startsWith("./") ? path.slice(2) : path)),
  );
  for (const finding of parsed.findings) {
    for (const location of finding.locations) {
      requireInventoriedPath(inventory, location.path, "finding location");
    }
    for (const evidence of finding.codeEvidence ?? []) {
      requireInventoriedPath(inventory, evidence.path, "code evidence");
    }
  }
  for (const assessment of parsed.priorFindingAssessments ?? []) {
    for (const evidence of assessment.evidence ?? []) {
      requireInventoriedPath(inventory, evidence.path, "assessment evidence");
    }
  }

  const rawCandidates = parsed.findings.map(rawDiscoveryCandidate);
  await recordCodexSecurityDiscoveryCandidates(
    { candidates: rawCandidates },
    context,
  );
  const candidates = [];
  let cursor: string | undefined;
  do {
    const page = await listCodexSecurityCandidates(
      cursor === undefined ? {} : { cursor },
      context,
    );
    candidates.push(...page.rows);
    cursor = page.nextCursor;
  } while (cursor !== undefined);

  if (candidates.length !== parsed.findings.length) {
    throw new Error(
      "Dependency artifact findings do not match the normalized compact candidates.",
    );
  }

  const validations: Array<{
    candidateId: string;
    validation: CandidateValidationRecord;
  }> = [];
  const attackPaths: Array<{
    candidateId: string;
    attackPath: CandidateAttackPathRecord;
  }> = [];
  for (const candidate of candidates) {
    const finding =
      typeof candidate.instance === "string"
        ? findingsByInstance.get(candidate.instance)
        : undefined;
    if (!finding) {
      throw new Error(
        "A normalized dependency candidate lost its trusted semantic identity.",
      );
    }
    validations.push({
      candidateId: candidate.candidate_id,
      validation: validationRecord(finding),
    });
    attackPaths.push({
      candidateId: candidate.candidate_id,
      attackPath: attackPathRecord(finding),
    });
  }

  await recordCodexSecurityCandidateValidations(context, { validations });
  await recordCodexSecurityCandidateAttackPaths(context, { attackPaths });
  await replaceArtifactJson(
    await artifactDestination(
      context,
      ["dependency-prior-finding-assessments.json"],
      "dependency prior finding assessments",
    ),
    { priorFindingAssessments: parsed.priorFindingAssessments ?? [] },
  );
  return {
    scanId: parsed.scanId,
    findingsRecorded: candidates.length,
    operation: "replace",
    status: "recorded",
  };
}

async function trustedPriorFindingIds(): Promise<Set<string>> {
  const directory = process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
  if (directory === undefined) return new Set();
  if (!isAbsolute(directory)) {
    throw new Error(
      "Dependency artifact trusted prior knowledge base is not an absolute directory.",
    );
  }

  const directoryMetadata = await fs.lstat(directory).catch(() => undefined);
  if (
    !directoryMetadata ||
    directoryMetadata.isSymbolicLink() ||
    !directoryMetadata.isDirectory()
  ) {
    throw new Error(
      "Dependency artifact trusted prior knowledge base is not a safe directory.",
    );
  }
  const canonicalDirectory = await fs
    .realpath(directory)
    .catch(() => undefined);
  if (!canonicalDirectory) {
    throw new Error(
      "Dependency artifact trusted prior knowledge base cannot be resolved.",
    );
  }

  const document = join(canonicalDirectory, "0-prior-findings.md.txt");
  const metadata = await fs.lstat(document).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(
      "Dependency artifact trusted prior document is not a safe regular file.",
    );
  }
  const canonicalDocument = await fs.realpath(document).catch(() => undefined);
  if (canonicalDocument !== document) {
    throw new Error(
      "Dependency artifact trusted prior document escaped its knowledge base.",
    );
  }
  const source = await fs.readFile(canonicalDocument, "utf8").catch(() => {
    throw new Error(
      "Dependency artifact trusted prior document cannot be read.",
    );
  });
  const match = source.match(/```json\n([\s\S]*?)\n```/u);
  if (
    !source.startsWith("# Trusted dependency finding assessment context\n") ||
    !match
  ) {
    throw new Error(
      "Dependency artifact trusted prior document does not contain its finding context.",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(match[1]);
  } catch {
    throw new Error("Dependency artifact trusted prior document is malformed.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      "Dependency artifact trusted prior document has an invalid finding context.",
    );
  }
  const findings = (parsed as Record<string, unknown>).findings;
  if (!findings || typeof findings !== "object" || Array.isArray(findings)) {
    throw new Error(
      "Dependency artifact trusted prior document has an invalid finding index.",
    );
  }

  const identifiers = new Set<string>();
  for (const [identifier, finding] of Object.entries(findings)) {
    if (
      !identifier.trim() ||
      !finding ||
      typeof finding !== "object" ||
      Array.isArray(finding)
    ) {
      throw new Error(
        "Dependency artifact trusted prior document contains an invalid finding.",
      );
    }
    identifiers.add(identifier);
  }
  return identifiers;
}

function validatePriorFindingAssessments(
  seededFindingIds: ReadonlySet<string>,
  assessments: readonly PriorFindingAssessment[],
): void {
  const assessedFindingIds = new Set<string>();
  for (const assessment of assessments) {
    if (!seededFindingIds.has(assessment.upstreamFindingId)) {
      throw new Error(
        "Dependency artifact assessment references an unseeded prior finding.",
      );
    }
    if (assessedFindingIds.has(assessment.upstreamFindingId)) {
      throw new Error(
        "Dependency artifact assessments repeat a seeded prior finding.",
      );
    }
    assessedFindingIds.add(assessment.upstreamFindingId);
  }
  if (assessedFindingIds.size !== seededFindingIds.size) {
    throw new Error(
      "Dependency artifact results are missing an assessment for a seeded prior finding.",
    );
  }
}

function validateSemanticFinding(finding: DependencyArtifactFinding): void {
  if (finding.severity.score !== undefined && !finding.severity.scoringSystem) {
    throw new Error(
      "Dependency artifact severity scoringSystem is required with severity score.",
    );
  }
  for (const location of [
    ...finding.locations,
    ...(finding.codeEvidence ?? []),
  ]) {
    if (
      location.endLine !== undefined &&
      location.endLine < location.startLine
    ) {
      throw new Error(
        "Dependency artifact source evidence has an invalid line range.",
      );
    }
  }
  const evidenceIds = validateSourceEvidence(finding.codeEvidence ?? []);
  const rootCause = finding.rootCause;
  if (rootCause && typeof rootCause === "object") {
    for (const reference of rootCause.evidenceRefs ?? []) {
      if (!evidenceIds.has(reference)) {
        throw new Error(
          "Dependency artifact root cause references missing source evidence.",
        );
      }
    }
  }
}

function validateSourceEvidence(
  evidence: readonly DependencyFindingEvidence[],
): Set<string> {
  const evidenceIds = new Set<string>();
  for (const item of evidence) {
    if (item.endLine !== undefined && item.endLine < item.startLine) {
      throw new Error(
        "Dependency artifact source evidence has an invalid line range.",
      );
    }
    if (evidenceIds.has(item.id)) {
      throw new Error(
        "Dependency artifact source evidence repeats an evidence identity.",
      );
    }
    evidenceIds.add(item.id);
  }
  return evidenceIds;
}

async function verifyPublishedEvidence(
  context: ArtifactContext,
  evidence: readonly DependencyFindingEvidence[],
): Promise<void> {
  for (const item of evidence) {
    const source = await publishedSource(context, item.path);
    const code = normalizeLines(item.code).replace(/\n$/u, "");
    const lineCount = code.split("\n").length;
    const expectedEnd = item.startLine + lineCount - 1;
    if (item.endLine !== undefined && item.endLine !== expectedEnd) {
      throw new Error(
        "Dependency artifact code evidence has an inconsistent source line range.",
      );
    }
    const actual = source
      .split("\n")
      .slice(item.startLine - 1, expectedEnd)
      .join("\n");
    if (!actual.includes(code)) {
      throw new Error(
        "Dependency artifact code evidence does not match the published artifact.",
      );
    }
  }
}

async function publishedSource(
  context: ArtifactContext,
  relativePath: string,
): Promise<string> {
  if (isAbsolute(relativePath)) {
    throw new Error(
      "Dependency artifact source must use a package-relative path.",
    );
  }
  const requested = resolve(context.repoRoot, relativePath);
  const metadata = await fs.lstat(requested).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(
      "Dependency artifact source must be a regular published file.",
    );
  }
  const canonical = await fs.realpath(requested).catch(() => undefined);
  if (!canonical || !canonical.startsWith(context.repoRoot + sep)) {
    throw new Error(
      "Dependency artifact source escaped the trusted published package.",
    );
  }
  const source = await fs.readFile(canonical, "utf8");
  if (source.includes("\0")) {
    throw new Error(
      "Dependency artifact source must contain published text, not binary data.",
    );
  }
  return normalizeLines(source);
}

function normalizeLines(source: string): string {
  return source.replace(/\r\n?/gu, "\n");
}

function requireInventoriedPath(
  inventory: Set<string>,
  path: string,
  label: string,
): void {
  if (!inventory.has(path)) {
    throw new Error(
      `Dependency artifact ${label} is outside the trusted published inventory.`,
    );
  }
}

function findingInstance(finding: DependencyArtifactFinding): string {
  return `${finding.ruleId}:${finding.identity.anchor}:${finding.identity.instance ?? ""}`;
}

function rawDiscoveryCandidate(
  finding: DependencyArtifactFinding,
): RawDiscoveryCandidate {
  return {
    cwe_ids: finding.taxonomy.cwe,
    locations: finding.locations.map((location) => ({
      path: location.path,
      start_line: location.startLine,
      ...(location.endLine === undefined ? {} : { end_line: location.endLine }),
      role: location.role ?? "evidence",
    })),
    summary: finding.summary,
    evidence: finding.codeEvidence?.[0]?.code ?? finding.summary,
    instance: findingInstance(finding),
  };
}

function validationRecord(
  finding: DependencyArtifactFinding,
): CandidateValidationRecord {
  return {
    disposition: "reportable",
    method:
      "Static inspection of verified published dependency artifact contents.",
    confidence: finding.confidence.level,
    confidence_rationale: finding.confidence.rationale,
    rubric: [finding.taxonomy.category],
    evidence: finding.codeEvidence?.length
      ? finding.codeEvidence.map((evidence) => evidence.code)
      : [finding.summary],
    counterevidence_or_proof_gap:
      "No contradictory published-artifact evidence was identified.",
    remaining_uncertainty: "",
    dependencyFinding: finding,
  };
}

function attackPathRecord(
  finding: DependencyArtifactFinding,
): CandidateAttackPathRecord {
  const severity =
    finding.severity.level === "informational" ? "low" : finding.severity.level;
  const impact = severity === "critical" ? "high" : severity;
  const report: Record<string, unknown> = {
    category: finding.taxonomy.category,
    remediation: finding.remediation,
    title: finding.title,
    ruleId: finding.ruleId,
    summary: finding.summary,
    ...(finding.identity.instance
      ? { instance: finding.identity.instance }
      : {}),
    ...(finding.rootCause
      ? {
          rootCause:
            typeof finding.rootCause === "string"
              ? finding.rootCause
              : finding.rootCause.summary,
        }
      : {}),
    ...(finding.remediationTests
      ? { remediationTests: finding.remediationTests }
      : {}),
    ...(finding.preventiveControls
      ? { preventiveControls: finding.preventiveControls }
      : {}),
  };
  return {
    decision: "reportable",
    dataflow: finding.summary,
    reachability: `Published package source ${finding.locations[0]!.path} is distributed to users.`,
    counterevidence:
      "No contradictory published-artifact evidence was identified.",
    impact,
    likelihood: finding.confidence.level,
    severity,
    severity_rationale: finding.severity.rationale ?? finding.summary,
    change_conditions: finding.severity.changeConditions ?? finding.remediation,
    reports: [report],
  };
}
