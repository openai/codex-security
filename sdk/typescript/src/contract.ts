import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import { ContractValidationError } from "./errors.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import type { NormalizedTarget, ScanMode } from "./targets.js";

const DOCUMENTS = {
  "scan-manifest.json": "scan-manifest.schema.json",
  "findings.json": "findings.schema.json",
  "coverage.json": "coverage.schema.json",
} as const;
const PRODUCER_NAME = "codex-security-plugin";

interface CheckedScanFile {
  path: string;
  metadata: Stats;
  parents: Array<{ path: string; metadata: Stats }>;
}

interface ScanRoot {
  path: string;
  metadata: Stats;
}

export interface ScanExpectation {
  repository: string;
  repositoryRevision: string | null;
  target: NormalizedTarget;
  mode: ScanMode;
  pluginVersion: string;
}

export interface LoadedContract {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
}

export async function loadContract(
  scanDirectory: string,
  options: {
    pluginRoot: string;
    expectation?: ScanExpectation;
    signal?: AbortSignal;
  },
): Promise<LoadedContract> {
  const scanRoot = await requireScanRoot(scanDirectory, options.signal);
  const scanDir = scanRoot.path;
  const documentDigests = new Map<string, string>();
  const payloads = {
    "scan-manifest.json": await readScanJson(
      scanDir,
      "scan-manifest.json",
      documentDigests,
      options.signal,
      scanRoot,
    ),
    "findings.json": await readScanJson(
      scanDir,
      "findings.json",
      documentDigests,
      options.signal,
      scanRoot,
    ),
    "coverage.json": await readScanJson(
      scanDir,
      "coverage.json",
      documentDigests,
      options.signal,
      scanRoot,
    ),
  };
  validateRawArtifactPaths(payloads["scan-manifest.json"]);
  throwIfAborted(options.signal);

  const ajv = createValidator();
  for (const [filename, schemaName] of Object.entries(DOCUMENTS)) {
    const schema = await readJson(
      join(options.pluginRoot, "schemas", schemaName),
      options.signal,
    );
    let validate: ReturnType<typeof ajv.compile>;
    try {
      validate = ajv.compile(schema);
    } catch (error) {
      throw new ContractValidationError(
        `${schemaName}: invalid JSON Schema: ${String(error)}`,
        {
          cause: error,
        },
      );
    }
    const payload = payloads[filename as keyof typeof payloads];
    if (!validate(payload)) {
      throw schemaError(filename, validate.errors ?? []);
    }
    throwIfAborted(options.signal);
  }
  validateCanonicalShape(
    payloads["scan-manifest.json"],
    payloads["findings.json"],
    payloads["coverage.json"],
  );
  validateFindingDetails(payloads["findings.json"]);

  const manifest = payloads["scan-manifest.json"] as unknown as ScanManifest;
  const findings = payloads["findings.json"] as unknown as FindingsDocument;
  const coverage = payloads["coverage.json"] as unknown as CoverageDocument;
  if (
    findings.scanId !== manifest.scan.id ||
    coverage.scanId !== manifest.scan.id
  ) {
    throw new ContractValidationError(
      "Canonical contract scan IDs do not match.",
    );
  }
  if (!sameArray(coverage.includePaths, manifest.scan.scope.includePaths)) {
    throw new ContractValidationError(
      "Coverage include paths do not match the manifest scope.",
    );
  }
  if (!sameArray(coverage.excludePaths, manifest.scan.scope.excludePaths)) {
    throw new ContractValidationError(
      "Coverage exclude paths do not match the manifest scope.",
    );
  }

  validateCanonicalContract(manifest, findings, coverage);

  await validateSeal(
    scanDir,
    manifest,
    findings,
    coverage,
    documentDigests,
    options.signal,
    scanRoot,
  );
  if (options.expectation !== undefined) {
    validateExpectation(manifest, coverage, options.expectation);
  }
  await verifyScanRoot(scanRoot, options.signal);
  return { manifest, findings, coverage };
}

function validateCanonicalShape(
  manifest: Record<string, unknown>,
  findings: Record<string, unknown>,
  coverage: Record<string, unknown>,
): void {
  requireCanonicalConstant(
    manifest["documentType"],
    "codex-security.scan-manifest",
    "manifest.documentType",
  );
  requireCanonicalConstant(
    manifest["schemaVersion"],
    "1.0",
    "manifest.schemaVersion",
  );
  const scan = requireCanonicalObject(manifest["scan"], "manifest.scan");
  requireCanonicalString(scan["id"], "manifest.scan.id");
  requireCanonicalConstant(scan["status"], "completed", "manifest.scan.status");
  for (const field of ["startedAt", "completedAt", "sealedAt"] as const) {
    const value = requireCanonicalString(scan[field], `manifest.scan.${field}`);
    if (!validRfc3339DateTime(value)) {
      throw new ContractValidationError(
        `manifest.scan.${field}: expected an RFC 3339 timestamp.`,
      );
    }
  }
  requireCanonicalConstant(
    scan["coverageRef"],
    "coverage.json",
    "manifest.scan.coverageRef",
  );
  requireCanonicalConstant(
    scan["findingsRef"],
    "findings.json",
    "manifest.scan.findingsRef",
  );
  const producer = requireCanonicalObject(
    scan["producer"],
    "manifest.scan.producer",
  );
  requireCanonicalString(producer["name"], "manifest.scan.producer.name");
  requireCanonicalString(producer["version"], "manifest.scan.producer.version");
  const target = requireCanonicalObject(scan["target"], "manifest.scan.target");
  requireCanonicalEnum(
    target["kind"],
    ["git_revision", "git_worktree", "git_diff", "directory_snapshot"],
    "manifest.scan.target.kind",
  );
  requireCanonicalString(target["targetId"], "manifest.scan.target.targetId");
  requireCanonicalString(
    target["displayName"],
    "manifest.scan.target.displayName",
  );
  if (target["kind"] === "git_revision") {
    requireCanonicalString(target["revision"], "manifest.scan.target.revision");
  }
  if (
    target["kind"] !== "git_revision" ||
    target["snapshotDigest"] !== undefined
  ) {
    const digest = requireCanonicalString(
      target["snapshotDigest"],
      "manifest.scan.target.snapshotDigest",
    );
    if (!/^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/.test(digest)) {
      throw new ContractValidationError(
        "manifest.scan.target.snapshotDigest: expected a canonical snapshot digest.",
      );
    }
  }
  for (const field of ["revision", "baseRevision", "headRevision"] as const) {
    if (target[field] !== undefined) {
      requireSchemaString(target[field], `manifest.scan.target.${field}`);
    }
  }
  if (target["remote"] !== undefined) {
    requireCanonicalString(target["remote"], "manifest.scan.target.remote");
  }
  const scope = requireCanonicalObject(scan["scope"], "manifest.scan.scope");
  requireSchemaStringArray(
    scope["includePaths"],
    "manifest.scan.scope.includePaths",
  );
  requireSchemaStringArray(
    scope["excludePaths"],
    "manifest.scan.scope.excludePaths",
  );
  for (const field of [
    "summary",
    "runtimeStatus",
    "validationMode",
    "context",
  ] as const) {
    if (scope[field] !== undefined) {
      requireSchemaString(scope[field], `manifest.scan.scope.${field}`);
    }
  }
  for (const field of ["artifactsReviewed", "limitations"] as const) {
    if (scope[field] !== undefined) {
      requireSchemaStringArray(scope[field], `manifest.scan.scope.${field}`);
    }
  }
  if (scan["threatModel"] !== undefined) {
    const threatModel = requireCanonicalObject(
      scan["threatModel"],
      "manifest.scan.threatModel",
    );
    requireSchemaString(
      threatModel["summary"],
      "manifest.scan.threatModel.summary",
    );
    for (const field of [
      "assets",
      "trustBoundaries",
      "attackerCapabilities",
      "securityObjectives",
      "assumptions",
    ] as const) {
      if (threatModel[field] !== undefined) {
        requireSchemaStringArray(
          threatModel[field],
          `manifest.scan.threatModel.${field}`,
        );
      }
    }
  }
  if (scan["hardening"] !== undefined) {
    const hardening = requireCanonicalObject(
      scan["hardening"],
      "manifest.scan.hardening",
    );
    requireCanonicalConstant(
      hardening["portfolioPath"],
      "hardening/hardening.md",
      "manifest.scan.hardening.portfolioPath",
    );
  }
  const artifacts = requireCanonicalArray(
    scan["artifacts"],
    "manifest.scan.artifacts",
  );
  if (artifacts.length === 0) {
    throw new ContractValidationError(
      "manifest.scan.artifacts: expected generated artifact records.",
    );
  }
  const artifactPaths = new Set<string>();
  for (const [index, value] of artifacts.entries()) {
    const artifact = requireCanonicalObject(
      value,
      `manifest.scan.artifacts[${index}]`,
    );
    artifactPaths.add(
      requireCanonicalString(
        artifact["path"],
        `manifest.scan.artifacts[${index}].path`,
      ),
    );
    requireCanonicalString(
      artifact["sha256"],
      `manifest.scan.artifacts[${index}].sha256`,
    );
    requireCanonicalString(
      artifact["mediaType"],
      `manifest.scan.artifacts[${index}].mediaType`,
    );
  }
  for (const requiredPath of ["findings.json", "coverage.json"] as const) {
    if (!artifactPaths.has(requiredPath)) {
      throw new ContractValidationError(
        `manifest.scan.artifacts: missing required artifact: ${requiredPath}.`,
      );
    }
  }

  requireCanonicalConstant(
    findings["documentType"],
    "codex-security.findings",
    "findings.documentType",
  );
  requireCanonicalConstant(
    findings["schemaVersion"],
    "1.0",
    "findings.schemaVersion",
  );
  requireCanonicalString(findings["scanId"], "findings.scanId");
  const findingValues = requireCanonicalArray(
    findings["findings"],
    "findings.findings",
  );
  for (const [index, value] of findingValues.entries()) {
    const context = `findings.findings[${index}]`;
    const finding = requireCanonicalObject(value, context);
    for (const field of [
      "findingId",
      "occurrenceId",
      "title",
      "summary",
      "remediation",
    ] as const) {
      requireCanonicalString(finding[field], `${context}.${field}`);
    }
    requireCanonicalSlug(finding["ruleId"], `${context}.ruleId`);
    const identity = requireCanonicalObject(
      finding["identity"],
      `${context}.identity`,
    );
    requireCanonicalSlug(identity["anchor"], `${context}.identity.anchor`);
    if (identity["instance"] !== undefined) {
      requireCanonicalSlug(
        identity["instance"],
        `${context}.identity.instance`,
      );
    }
    const fingerprints = requireCanonicalObject(
      finding["fingerprints"],
      `${context}.fingerprints`,
    );
    requireCanonicalConstant(
      fingerprints["algorithm"],
      "codex-security/v1",
      `${context}.fingerprints.algorithm`,
    );
    requireCanonicalString(
      fingerprints["primary"],
      `${context}.fingerprints.primary`,
    );
    const severity = requireCanonicalObject(
      finding["severity"],
      `${context}.severity`,
    );
    requireCanonicalEnum(
      severity["level"],
      ["critical", "high", "medium", "low", "informational"],
      `${context}.severity.level`,
    );
    if (
      severity["score"] !== undefined &&
      (typeof severity["score"] !== "number" ||
        !Number.isFinite(severity["score"]) ||
        severity["score"] < 0 ||
        severity["score"] > 10)
    ) {
      throw new ContractValidationError(
        `${context}.severity.score: expected a number from 0 through 10.`,
      );
    }
    for (const field of ["vector", "rationale", "changeConditions"] as const) {
      if (severity[field] !== undefined) {
        requireSchemaString(severity[field], `${context}.severity.${field}`);
      }
    }
    if (severity["score"] !== undefined) {
      requireCanonicalString(
        severity["scoringSystem"],
        `${context}.severity.scoringSystem`,
      );
    } else if (severity["scoringSystem"] !== undefined) {
      requireSchemaString(
        severity["scoringSystem"],
        `${context}.severity.scoringSystem`,
      );
    }
    if (finding["writeup"] !== undefined) {
      const writeup = requireCanonicalObject(
        finding["writeup"],
        `${context}.writeup`,
      );
      const reportPath = requireCanonicalString(
        writeup["reportPath"],
        `${context}.writeup.reportPath`,
      );
      if (!/^findings\/([a-z0-9][a-z0-9._-]*)\/\1\.md$/.test(reportPath)) {
        throw new ContractValidationError(
          `${context}.writeup.reportPath: expected a canonical finding report path.`,
        );
      }
    }
    const confidence = requireCanonicalObject(
      finding["confidence"],
      `${context}.confidence`,
    );
    requireCanonicalEnum(
      confidence["level"],
      ["high", "medium", "low"],
      `${context}.confidence.level`,
    );
    requireCanonicalString(
      confidence["rationale"],
      `${context}.confidence.rationale`,
    );
    const taxonomy = requireCanonicalObject(
      finding["taxonomy"],
      `${context}.taxonomy`,
    );
    requireCanonicalString(
      taxonomy["category"],
      `${context}.taxonomy.category`,
    );
    requireSchemaStringArray(taxonomy["cwe"], `${context}.taxonomy.cwe`);
    const locations = requireCanonicalArray(
      finding["locations"],
      `${context}.locations`,
    );
    if (locations.length === 0) {
      throw new ContractValidationError(
        `${context}.locations: expected at least one location.`,
      );
    }
    for (const [locationIndex, locationValue] of locations.entries()) {
      const locationContext = `${context}.locations[${locationIndex}]`;
      const location = requireCanonicalObject(locationValue, locationContext);
      requireCanonicalString(location["path"], `${locationContext}.path`);
      if (
        typeof location["startLine"] !== "number" ||
        !Number.isSafeInteger(location["startLine"]) ||
        location["startLine"] < 1
      ) {
        throw new ContractValidationError(
          `${locationContext}.startLine: expected a positive integer.`,
        );
      }
      if (
        location["endLine"] !== undefined &&
        (typeof location["endLine"] !== "number" ||
          !Number.isSafeInteger(location["endLine"]) ||
          location["endLine"] < 1)
      ) {
        throw new ContractValidationError(
          `${locationContext}.endLine: expected a positive integer.`,
        );
      }
      if (location["role"] !== undefined) {
        requireSchemaString(location["role"], `${locationContext}.role`);
      }
    }
    if (finding["codeEvidence"] !== undefined) {
      const evidenceValues = requireCanonicalArray(
        finding["codeEvidence"],
        `${context}.codeEvidence`,
      );
      for (const [evidenceIndex, evidenceValue] of evidenceValues.entries()) {
        const evidenceContext = `${context}.codeEvidence[${evidenceIndex}]`;
        const evidence = requireCanonicalObject(evidenceValue, evidenceContext);
        requireCanonicalSlug(evidence["id"], `${evidenceContext}.id`);
        for (const field of ["label", "path", "explanation"] as const) {
          requireSchemaString(evidence[field], `${evidenceContext}.${field}`);
        }
        requireCanonicalString(evidence["code"], `${evidenceContext}.code`);
        if (
          typeof evidence["startLine"] !== "number" ||
          !Number.isSafeInteger(evidence["startLine"]) ||
          evidence["startLine"] < 1
        ) {
          throw new ContractValidationError(
            `${evidenceContext}.startLine: expected a positive integer.`,
          );
        }
        if (
          evidence["endLine"] !== undefined &&
          (typeof evidence["endLine"] !== "number" ||
            !Number.isSafeInteger(evidence["endLine"]) ||
            evidence["endLine"] < 1)
        ) {
          throw new ContractValidationError(
            `${evidenceContext}.endLine: expected a positive integer.`,
          );
        }
        for (const field of ["language", "role"] as const) {
          if (evidence[field] !== undefined) {
            requireSchemaString(evidence[field], `${evidenceContext}.${field}`);
          }
        }
      }
    }
    for (const field of ["validation", "attackPath"] as const) {
      if (finding[field] !== undefined && finding[field] !== null) {
        requireCanonicalObject(finding[field], `${context}.${field}`);
      }
    }
    for (const field of ["remediationTests", "preventiveControls"] as const) {
      if (finding[field] !== undefined) {
        requireSchemaStringArray(finding[field], `${context}.${field}`);
      }
    }
    if (finding["rootCause"] !== undefined) {
      const rootCause = finding["rootCause"];
      if (typeof rootCause === "string") {
        requireSchemaString(rootCause, `${context}.rootCause`);
      } else {
        const cause = requireCanonicalObject(rootCause, `${context}.rootCause`);
        requireSchemaString(cause["summary"], `${context}.rootCause.summary`);
        if (cause["evidenceRefs"] !== undefined) {
          requireSchemaStringArray(
            cause["evidenceRefs"],
            `${context}.rootCause.evidenceRefs`,
          );
        }
        for (const field of ["code", "language"] as const) {
          if (cause[field] !== undefined) {
            requireSchemaString(cause[field], `${context}.rootCause.${field}`);
          }
        }
      }
    }
    if (finding["extensions"] !== undefined) {
      const extensions = requireCanonicalObject(
        finding["extensions"],
        `${context}.extensions`,
      );
      for (const field of ["candidateId", "ledgerRowId", "reportId"] as const) {
        if (extensions[field] !== undefined) {
          requireSchemaString(
            extensions[field],
            `${context}.extensions.${field}`,
          );
        }
      }
    }
    const provenance = requireCanonicalObject(
      finding["provenance"],
      `${context}.provenance`,
    );
    requireCanonicalString(
      provenance["source"],
      `${context}.provenance.source`,
    );
  }

  requireCanonicalConstant(
    coverage["documentType"],
    "codex-security.coverage",
    "coverage.documentType",
  );
  requireCanonicalConstant(
    coverage["schemaVersion"],
    "1.0",
    "coverage.schemaVersion",
  );
  requireCanonicalString(coverage["scanId"], "coverage.scanId");
  requireCanonicalEnum(
    coverage["mode"],
    [
      "repository",
      "scoped_path",
      "diff",
      "commit",
      "branch_diff",
      "working_tree",
      "deep_repository",
    ],
    "coverage.mode",
  );
  requireCanonicalEnum(
    coverage["completeness"],
    ["complete", "partial", "unknown"],
    "coverage.completeness",
  );
  requireCanonicalEnum(
    coverage["inventoryStrategy"],
    ["repository", "scoped_path", "diff", "directory", "custom"],
    "coverage.inventoryStrategy",
  );
  requireSchemaStringArray(coverage["includePaths"], "coverage.includePaths");
  requireSchemaStringArray(coverage["excludePaths"], "coverage.excludePaths");
  const surfaces = requireCanonicalArray(
    coverage["surfaces"],
    "coverage.surfaces",
  );
  for (const [index, value] of surfaces.entries()) {
    const context = `coverage.surfaces[${index}]`;
    const surface = requireCanonicalObject(value, context);
    requireCanonicalString(surface["id"], `${context}.id`);
    requireCanonicalString(surface["label"], `${context}.label`);
    requireCanonicalEnum(
      surface["disposition"],
      [
        "reported",
        "no_issue_found",
        "rejected",
        "not_applicable",
        "needs_follow_up",
      ],
      `${context}.disposition`,
    );
    requireSchemaStringArray(surface["receiptRefs"], `${context}.receiptRefs`);
    for (const field of ["riskArea", "notes"] as const) {
      if (surface[field] !== undefined) {
        requireSchemaString(surface[field], `${context}.${field}`);
      }
    }
  }
  const explicitExclusions = requireCanonicalArray(
    coverage["explicitExclusions"],
    "coverage.explicitExclusions",
  );
  for (const [index, value] of explicitExclusions.entries()) {
    const context = `coverage.explicitExclusions[${index}]`;
    const exclusion = requireCanonicalObject(value, context);
    requireSchemaString(exclusion["pattern"], `${context}.pattern`);
    requireSchemaString(exclusion["reason"], `${context}.reason`);
  }
  const deferred = requireCanonicalArray(
    coverage["deferred"],
    "coverage.deferred",
  );
  for (const [index, value] of deferred.entries()) {
    const context = `coverage.deferred[${index}]`;
    const item = requireCanonicalObject(value, context);
    requireSchemaString(item["id"], `${context}.id`);
    requireSchemaString(item["reason"], `${context}.reason`);
    for (const field of ["paths", "surfaceIds"] as const) {
      if (item[field] !== undefined) {
        requireSchemaStringArray(item[field], `${context}.${field}`);
      }
    }
  }
  if (coverage["openQuestions"] !== undefined) {
    const openQuestions = requireCanonicalArray(
      coverage["openQuestions"],
      "coverage.openQuestions",
    );
    for (const [index, value] of openQuestions.entries()) {
      const context = `coverage.openQuestions[${index}]`;
      const question = requireCanonicalObject(value, context);
      requireSchemaString(question["question"], `${context}.question`);
      if (question["followUpPrompt"] !== undefined) {
        requireSchemaString(
          question["followUpPrompt"],
          `${context}.followUpPrompt`,
        );
      }
    }
  }
}

function requireCanonicalObject(
  value: unknown,
  context: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ContractValidationError(`${context}: expected an object.`);
  }
  return value;
}

function requireCanonicalArray(value: unknown, context: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ContractValidationError(`${context}: expected an array.`);
  }
  return value;
}

function requireCanonicalString(value: unknown, context: string): string {
  if (
    typeof value !== "string" ||
    /^(?:\p{White_Space}|[\u001c-\u001f])*$/u.test(value) ||
    !isWellFormedUnicode(value)
  ) {
    throw new ContractValidationError(
      `${context}: expected a non-empty string.`,
    );
  }
  return value;
}

function requireSchemaString(value: unknown, context: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !isWellFormedUnicode(value)
  ) {
    throw new ContractValidationError(
      `${context}: expected a non-empty string.`,
    );
  }
  return value;
}

function requireCanonicalSlug(value: unknown, context: string): string {
  const slug = requireCanonicalString(value, context);
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(slug)) {
    throw new ContractValidationError(`${context}: expected a canonical slug.`);
  }
  return slug;
}

function requireSchemaStringArray(value: unknown, context: string): string[] {
  const values = requireCanonicalArray(value, context);
  for (const [index, item] of values.entries()) {
    requireSchemaString(item, `${context}[${index}]`);
  }
  return values as string[];
}

function requireCanonicalConstant(
  value: unknown,
  expected: string,
  context: string,
): void {
  if (value !== expected) {
    throw new ContractValidationError(`${context}: expected ${expected}.`);
  }
}

function requireCanonicalEnum(
  value: unknown,
  allowed: readonly string[],
  context: string,
): void {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new ContractValidationError(`${context}: unsupported value.`);
  }
}

function validateCanonicalContract(
  manifest: ScanManifest,
  findings: FindingsDocument,
  coverage: CoverageDocument,
): void {
  const remote = manifest.scan.target.remote;
  if (remote !== undefined) {
    const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]+)/.exec(
      remote,
    )?.[1];
    if (remote.includes("\\") || authority === undefined) {
      throw new ContractValidationError(
        "scan.target.remote: expected a sanitized canonical absolute URL.",
      );
    }
    if (authority.includes("@")) {
      throw new ContractValidationError(
        "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(remote);
    } catch (error) {
      throw new ContractValidationError(
        "scan.target.remote: expected a sanitized canonical absolute URL.",
        { cause: error },
      );
    }
    if (parsed.protocol.length === 0 || parsed.host.length === 0) {
      throw new ContractValidationError(
        "scan.target.remote: expected a sanitized canonical absolute URL.",
      );
    }
    if (
      parsed.username.length > 0 ||
      parsed.password.length > 0 ||
      parsed.search.length > 0 ||
      parsed.hash.length > 0
    ) {
      throw new ContractValidationError(
        "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
      );
    }
  }

  for (const field of ["includePaths", "excludePaths"] as const) {
    for (const [index, value] of manifest.scan.scope[field].entries()) {
      try {
        safeScopePath(value);
      } catch (error) {
        throw new ContractValidationError(
          `manifest.scan.scope.${field}[${index}]: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
    }
  }

  const surfaceIds = new Set<string>();
  for (const [index, surface] of coverage.surfaces.entries()) {
    requireNonBlank(surface.id, `coverage.surfaces[${index}].id`);
    requireNonBlank(surface.label, `coverage.surfaces[${index}].label`);
    if (surfaceIds.has(surface.id)) {
      throw new ContractValidationError(
        `coverage.surfaces[${index}].id: duplicate surface id.`,
      );
    }
    surfaceIds.add(surface.id);
  }
  if (
    coverage.completeness === "complete" &&
    (coverage.deferred.length > 0 ||
      coverage.surfaces.some(
        (surface) => surface.disposition === "needs_follow_up",
      ))
  ) {
    throw new ContractValidationError(
      "coverage.completeness: complete coverage cannot have deferred work.",
    );
  }

  const occurrenceIds = new Set<string>();
  for (const [findingIndex, finding] of findings.findings.entries()) {
    const context = `findings.findings[${findingIndex}]`;
    for (const key of [
      "findingId",
      "occurrenceId",
      "ruleId",
      "title",
      "summary",
      "remediation",
    ] as const) {
      requireNonBlank(finding[key], `${context}.${key}`);
    }
    requireNonBlank(finding.identity.anchor, `${context}.identity.anchor`);
    requireNonBlank(
      finding.fingerprints.primary,
      `${context}.fingerprints.primary`,
    );
    requireNonBlank(
      finding.confidence.rationale,
      `${context}.confidence.rationale`,
    );
    requireNonBlank(finding.taxonomy.category, `${context}.taxonomy.category`);
    requireNonBlank(finding.provenance.source, `${context}.provenance.source`);
    for (const [locationIndex, location] of finding.locations.entries()) {
      const locationContext = `${context}.locations[${locationIndex}]`;
      try {
        safeRelativePath(location.path, `${locationContext}.path`);
      } catch (error) {
        throw new ContractValidationError(
          `${locationContext}.path: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
      if (
        location.endLine !== undefined &&
        location.endLine < location.startLine
      ) {
        throw new ContractValidationError(
          `${locationContext}.endLine: expected an integer >= startLine.`,
        );
      }
    }

    if (
      finding.severity.score !== undefined &&
      (typeof finding.severity.scoringSystem !== "string" ||
        finding.severity.scoringSystem.trim().length === 0)
    ) {
      throw new ContractValidationError(
        `${context}.severity.scoringSystem: expected a non-empty string.`,
      );
    }

    const evidenceIds = new Set<string>();
    const codeEvidence = finding["codeEvidence"];
    if (Array.isArray(codeEvidence)) {
      for (const [index, evidence] of codeEvidence.entries()) {
        if (!isRecord(evidence)) continue;
        const evidenceContext = `${context}.codeEvidence[${index}]`;
        const evidenceId = evidence["id"];
        const code = evidence["code"];
        requireNonBlank(evidenceId, `${evidenceContext}.id`);
        requireNonBlank(code, `${evidenceContext}.code`);
        if (evidenceIds.has(evidenceId as string)) {
          throw new ContractValidationError(
            `${evidenceContext}.id: duplicate code-evidence id.`,
          );
        }
        evidenceIds.add(evidenceId as string);
      }
    }
    for (const sectionName of [
      "rootCause",
      "validation",
      "attackPath",
    ] as const) {
      const section = finding[sectionName];
      if (!isRecord(section) || !("evidenceRefs" in section)) continue;
      const refs = section["evidenceRefs"];
      if (
        !Array.isArray(refs) ||
        refs.some((ref) => typeof ref !== "string" || ref.trim().length === 0)
      ) {
        throw new ContractValidationError(
          `${context}.${sectionName}.evidenceRefs: expected strings.`,
        );
      }
      const unknown = refs.filter((ref) => !evidenceIds.has(ref));
      if (unknown.length > 0) {
        throw new ContractValidationError(
          `${context}.${sectionName}.evidenceRefs: unknown code-evidence ids: ${unknown.join(", ")}.`,
        );
      }
    }

    const fingerprint = `codex-security/v1:sha256:${sha256Text(
      [
        "codex-security/v1",
        manifest.scan.target.targetId,
        finding.ruleId,
        finding.identity.anchor,
        finding.identity.instance ?? "",
      ].join("\0"),
    )}`;
    const findingId = `csf_${sha256Text(fingerprint).slice(0, 24)}`;
    const occurrenceId = `occ_${sha256Text(
      [manifest.scan.id, fingerprint].join("\0"),
    ).slice(0, 24)}`;
    if (finding.findingId !== findingId) {
      throw new ContractValidationError(
        `${context}.findingId: does not match derived fingerprint identity.`,
      );
    }
    if (finding.occurrenceId !== occurrenceId) {
      throw new ContractValidationError(
        `${context}.occurrenceId: does not match scan occurrence identity.`,
      );
    }
    if (
      finding.fingerprints.algorithm !== "codex-security/v1" ||
      finding.fingerprints.primary !== fingerprint
    ) {
      throw new ContractValidationError(
        `${context}.fingerprints: does not match derived fingerprint.`,
      );
    }
    if (occurrenceIds.has(occurrenceId)) {
      throw new ContractValidationError(
        `${context}: duplicate occurrence identity; use identity.instance to split siblings.`,
      );
    }
    occurrenceIds.add(occurrenceId);
  }
}

function requireNonBlank(value: unknown, context: string): void {
  if (
    typeof value !== "string" ||
    /^(?:\p{White_Space}|[\u001c-\u001f])*$/u.test(value) ||
    !isWellFormedUnicode(value)
  ) {
    throw new ContractValidationError(
      `${context}: expected a non-empty string.`,
    );
  }
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export async function requireScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<string> {
  return (
    await requireCheckedScanFile(scanDirectory, relativePath, context, signal)
  ).path;
}

async function requireCheckedScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<CheckedScanFile> {
  const checkedRoot = await requireScanRoot(scanDirectory, signal);
  const scanDir = checkedRoot.path;
  throwIfAborted(signal);
  const safePath = safeRelativePath(relativePath, context);
  const parts = safePath.split("/");
  let current = scanDir;
  try {
    const rootMetadata = checkedRoot.metadata;
    if (
      expectedRoot !== undefined &&
      (scanDir !== expectedRoot.path ||
        rootMetadata.dev !== expectedRoot.metadata.dev ||
        rootMetadata.ino !== expectedRoot.metadata.ino)
    ) {
      throw new Error("scan directory changed while reading");
    }
    const parents = [{ path: scanDir, metadata: rootMetadata }];
    throwIfAborted(signal);
    if (
      !parents[0]!.metadata.isDirectory() ||
      parents[0]!.metadata.isSymbolicLink()
    ) {
      throw new Error("unsafe scan directory");
    }
    for (const part of parts.slice(0, -1)) {
      current = join(current, part);
      const metadata = await lstat(current);
      throwIfAborted(signal);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error("unsafe parent");
      }
      parents.push({ path: current, metadata });
    }
    const path = join(scanDir, ...parts);
    const metadata = await lstat(path);
    throwIfAborted(signal);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new ContractValidationError(
        `${context}: expected a regular non-symlink file.`,
      );
    }
    const canonical = await realpath(path);
    throwIfAborted(signal);
    if (!isContained(scanDir, canonical)) {
      throw new Error("outside scan directory");
    }
    return { path, metadata, parents };
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) {
      throw error;
    }
    throw new ContractValidationError(
      `${context}: expected a file inside the scan directory.`,
      {
        cause: error,
      },
    );
  }
}

async function validateSeal(
  scanDir: string,
  manifest: ScanManifest,
  findings: FindingsDocument,
  coverage: CoverageDocument,
  documentDigests: ReadonlyMap<string, string>,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<void> {
  const scan = manifest.scan;
  if (
    rfc3339InstantMicros(scan.sealedAt) !==
    rfc3339InstantMicros(scan.completedAt)
  ) {
    throw new ContractValidationError(
      "Manifest sealedAt must match completedAt.",
    );
  }

  const artifactPaths = new Set<string>();
  for (const [index, artifact] of scan.artifacts.entries()) {
    throwIfAborted(signal);
    const context = `manifest.scan.artifacts[${index}]`;
    const normalized = safeRelativePath(artifact.path, `${context}.path`);
    if (artifactPaths.has(normalized)) {
      throw new ContractValidationError(
        `${context}.path: duplicate artifact path.`,
      );
    }
    artifactPaths.add(normalized);
    const digest =
      documentDigests.get(normalized) ??
      (await sha256ScanFile(
        scanDir,
        normalized,
        context,
        signal,
        expectedRoot,
      ));
    if (digest !== artifact.sha256) {
      throw new ContractValidationError(
        `${context}: sealed artifact changed or is missing.`,
      );
    }
  }

  for (const surface of coverage.surfaces) {
    for (const receipt of surface.receiptRefs) {
      throwIfAborted(signal);
      const normalized = safeRelativePath(receipt, "coverage receipt");
      if (!normalized.startsWith("artifacts/")) {
        throw new ContractValidationError(
          `Coverage receipt must be under artifacts/: ${receipt}`,
        );
      }
      if (!artifactPaths.has(normalized)) {
        throw new ContractValidationError(
          `Coverage receipt is missing from sealed artifacts: ${receipt}`,
        );
      }
    }
  }

  for (const [index, finding] of findings.findings.entries()) {
    const writeup = finding["writeup"];
    if (!isRecord(writeup) || typeof writeup["reportPath"] !== "string") {
      continue;
    }
    const file = await openCheckedScanFile(
      scanDir,
      writeup["reportPath"],
      `findings[${index}].writeup.reportPath`,
      signal,
      expectedRoot,
    );
    await file.close();
  }
  const hardening = manifest.scan["hardening"];
  if (isRecord(hardening) && typeof hardening["portfolioPath"] === "string") {
    const file = await openCheckedScanFile(
      scanDir,
      hardening["portfolioPath"],
      "manifest.scan.hardening.portfolioPath",
      signal,
      expectedRoot,
    );
    await file.close();
  }
}

function validateRawArtifactPaths(manifest: Record<string, unknown>): void {
  const scan = manifest["scan"];
  if (!isRecord(scan) || !Array.isArray(scan["artifacts"])) {
    return;
  }
  const paths = new Set<string>();
  for (const [index, artifact] of scan["artifacts"].entries()) {
    if (!isRecord(artifact) || typeof artifact["path"] !== "string") {
      continue;
    }
    const normalized = safeRelativePath(
      artifact["path"],
      `manifest.scan.artifacts[${index}].path`,
    );
    if (paths.has(normalized)) {
      throw new ContractValidationError(
        `manifest.scan.artifacts[${index}].path: duplicate artifact path.`,
      );
    }
    paths.add(normalized);
  }
}

function validateExpectation(
  manifest: ScanManifest,
  coverage: CoverageDocument,
  expectation: ScanExpectation,
): void {
  const scan = manifest.scan;
  if (scan.producer.name !== PRODUCER_NAME) {
    throw new ContractValidationError(
      `Manifest producer must be ${PRODUCER_NAME}, got ${scan.producer.name}.`,
    );
  }
  if (scan.producer.version !== expectation.pluginVersion) {
    throw new ContractValidationError(
      "Manifest producer version does not match the installed Codex Security plugin.",
    );
  }

  const expectedMode = expectedCoverageMode(
    expectation.target,
    expectation.mode,
  );
  if (coverage.mode !== expectedMode) {
    throw new ContractValidationError(
      `Coverage mode must be ${expectedMode}, got ${coverage.mode}.`,
    );
  }

  const target = scan.target;
  const requested = expectation.target;
  if (requested.kind === "refs" || requested.kind === "working_tree") {
    if (target.kind !== "git_diff") {
      throw new ContractValidationError(
        "Diff scan manifest target must be git_diff.",
      );
    }
    if (target.baseRevision !== requested.base) {
      throw new ContractValidationError(
        "Diff scan base revision does not match the request.",
      );
    }
    if (target.headRevision !== requested.head) {
      throw new ContractValidationError(
        "Diff scan head revision does not match the request.",
      );
    }
  } else if (expectation.repositoryRevision === null) {
    if (target.kind !== "directory_snapshot") {
      throw new ContractValidationError(
        "Unversioned scan manifest target must be directory_snapshot.",
      );
    }
  } else {
    if (target.kind !== "git_revision" && target.kind !== "git_worktree") {
      throw new ContractValidationError(
        "Repository scan manifest target must be Git-backed.",
      );
    }
    if (target.revision !== expectation.repositoryRevision) {
      throw new ContractValidationError(
        "Scan target revision does not match the repository.",
      );
    }
  }

  if (requested.kind === "paths") {
    const actual = scan.scope.includePaths.map(safeScopePath);
    if (
      actual.length !== new Set(actual).size ||
      !sameSet(new Set(actual), new Set(requested.paths))
    ) {
      throw new ContractValidationError(
        "Manifest include paths do not match the requested path target.",
      );
    }
  }
}

function expectedCoverageMode(
  target: NormalizedTarget,
  mode: ScanMode,
): CoverageDocument["mode"] {
  if (target.kind === "paths") return "scoped_path";
  if (target.kind === "refs") return "branch_diff";
  if (target.kind === "working_tree") return "working_tree";
  return mode === "deep" ? "deep_repository" : "repository";
}

async function requireScanRoot(
  scanDirectory: string,
  signal?: AbortSignal,
): Promise<ScanRoot> {
  throwIfAborted(signal);
  const absolute = resolve(scanDirectory);
  try {
    const metadata = await lstat(absolute);
    throwIfAborted(signal);
    const canonical = await realpath(absolute);
    throwIfAborted(signal);
    const current = await lstat(absolute);
    throwIfAborted(signal);
    const returned = await lstat(canonical);
    throwIfAborted(signal);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      !current.isDirectory() ||
      current.isSymbolicLink() ||
      metadata.dev !== current.dev ||
      metadata.ino !== current.ino ||
      !returned.isDirectory() ||
      returned.isSymbolicLink() ||
      metadata.dev !== returned.dev ||
      metadata.ino !== returned.ino
    ) {
      throw new Error("not a directory");
    }
    return { path: canonical, metadata: returned };
  } catch (error) {
    throwIfAborted(signal);
    throw new ContractValidationError(
      "Scan directory must be an existing non-symlink directory.",
      { cause: error },
    );
  }
}

async function verifyScanRoot(
  root: ScanRoot,
  signal?: AbortSignal,
): Promise<void> {
  try {
    const current = await lstat(root.path);
    throwIfAborted(signal);
    if (
      !current.isDirectory() ||
      current.isSymbolicLink() ||
      current.dev !== root.metadata.dev ||
      current.ino !== root.metadata.ino
    ) {
      throw new Error("scan directory changed while reading");
    }
  } catch (error) {
    throwIfAborted(signal);
    throw new ContractValidationError(
      "Scan directory changed while reading the canonical contract.",
      { cause: error },
    );
  }
}

function safeRelativePath(value: string, context: string): string {
  const parts = value.split("/");
  if (
    value.length === 0 ||
    !isWellFormedUnicode(value) ||
    value === "." ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    value.includes("\0") ||
    parts.some((part) => part.includes(":"))
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  const normalized = posix.normalize(value).replace(/\/+$/, "");
  if (
    normalized === "." ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

function safeScopePath(value: string): string {
  return value === "."
    ? value
    : safeRelativePath(value, "manifest scope include path");
}

async function readScanJson(
  scanDir: string,
  relativePath: keyof typeof DOCUMENTS,
  documentDigests: Map<string, string>,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<Record<string, unknown>> {
  const file = await openCheckedScanFile(
    scanDir,
    relativePath,
    relativePath,
    signal,
    expectedRoot,
  );
  try {
    const bytes = await file.readFile({ signal });
    throwIfAborted(signal);
    documentDigests.set(
      relativePath,
      createHash("sha256").update(bytes).digest("hex"),
    );
    return parseJson(join(scanDir, relativePath), bytes);
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      `${join(scanDir, relativePath)}: unreadable JSON document.`,
      { cause: error },
    );
  } finally {
    await file.close();
  }
}

async function readJson(
  path: string,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  let bytes: Buffer;
  let file: FileHandle | undefined;
  try {
    const parent = dirname(path);
    const parentMetadata = await lstat(parent);
    const metadata = await lstat(path);
    throwIfAborted(signal);
    if (
      !parentMetadata.isDirectory() ||
      parentMetadata.isSymbolicLink() ||
      !metadata.isFile() ||
      metadata.isSymbolicLink()
    ) {
      throw new Error("not a regular schema file");
    }
    file = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = await file.stat();
    const currentParent = await lstat(parent);
    const current = await lstat(path);
    throwIfAborted(signal);
    if (
      !opened.isFile() ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino ||
      !currentParent.isDirectory() ||
      currentParent.isSymbolicLink() ||
      currentParent.dev !== parentMetadata.dev ||
      currentParent.ino !== parentMetadata.ino ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== metadata.dev ||
      current.ino !== metadata.ino
    ) {
      throw new Error("schema file changed before reading");
    }
    bytes = await file.readFile({ signal });
    throwIfAborted(signal);
  } catch (error) {
    throwIfAborted(signal);
    if (nodeErrorCode(error) === "ENOENT") {
      throw new ContractValidationError(
        `Missing required contract document: ${path}`,
      );
    }
    throw new ContractValidationError(`${path}: unreadable JSON document.`, {
      cause: error,
    });
  } finally {
    await file?.close();
  }
  return parseJson(path, bytes);
}

function parseJson(path: string, bytes: Uint8Array): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new ContractValidationError(`${path}: unreadable JSON document.`, {
      cause: error,
    });
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    throw new ContractValidationError(
      `${path}: invalid JSON: ${String(error)}`,
      { cause: error },
    );
  }
  if (!isRecord(payload)) {
    throw new ContractValidationError(`${path}: expected a JSON object.`);
  }
  validateParsedJson(payload, path);
  return payload;
}

function validateParsedJson(value: unknown, context: string): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ContractValidationError(
        `${context}: non-finite JSON numbers are not supported.`,
      );
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new ContractValidationError(
        `${context}: unsafe integer-valued JSON numbers are not supported.`,
      );
    }
    return;
  }
  if (typeof value === "string") {
    if (!isWellFormedUnicode(value)) {
      throw new ContractValidationError(
        `${context}: expected well-formed Unicode JSON strings.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      validateParsedJson(item, `${context}[${index}]`);
    }
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (!isWellFormedUnicode(key)) {
        throw new ContractValidationError(
          `${context}: expected well-formed Unicode JSON keys.`,
        );
      }
      validateParsedJson(item, `${context}.${key}`);
    }
  }
}

function isWellFormedUnicode(value: string): boolean {
  return Buffer.from(value, "utf8").toString("utf8") === value;
}

function createValidator(): Ajv2020 {
  // The plugin schemas are the immutable v0 contract. They are valid Draft
  // 2020-12 but intentionally omit redundant local `type` keywords that Ajv's
  // optional strict-schema linter requires.
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat("date-time", {
    type: "string",
    validate: validRfc3339DateTime,
  });
  return ajv;
}

async function sha256ScanFile(
  scanDir: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<string> {
  const file = await openCheckedScanFile(
    scanDir,
    relativePath,
    context,
    signal,
    expectedRoot,
  );
  try {
    throwIfAborted(signal);
    const digest = createHash("sha256");
    for await (const chunk of file.createReadStream({
      signal,
      autoClose: false,
    })) {
      digest.update(chunk);
    }
    throwIfAborted(signal);
    return digest.digest("hex");
  } finally {
    await file.close();
  }
}

async function openCheckedScanFile(
  scanDir: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<FileHandle> {
  const checked = await requireCheckedScanFile(
    scanDir,
    relativePath,
    context,
    signal,
    expectedRoot,
  );
  let file: FileHandle | undefined;
  try {
    file = await open(
      checked.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = await file.stat();
    throwIfAborted(signal);
    if (
      !opened.isFile() ||
      opened.dev !== checked.metadata.dev ||
      opened.ino !== checked.metadata.ino
    ) {
      throw new ContractValidationError(
        `${context}: expected the checked regular file.`,
      );
    }
    for (const parent of checked.parents) {
      const current = await lstat(parent.path);
      throwIfAborted(signal);
      if (
        !current.isDirectory() ||
        current.isSymbolicLink() ||
        current.dev !== parent.metadata.dev ||
        current.ino !== parent.metadata.ino
      ) {
        throw new ContractValidationError(
          `${context}: checked parent changed before opening the file.`,
        );
      }
    }
    const current = await lstat(checked.path);
    throwIfAborted(signal);
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== checked.metadata.dev ||
      current.ino !== checked.metadata.ino
    ) {
      throw new ContractValidationError(
        `${context}: checked file changed before reading.`,
      );
    }
    return file;
  } catch (error) {
    await file?.close();
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      `${context}: unable to open the checked regular file.`,
      { cause: error },
    );
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function validRfc3339DateTime(value: string): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/i.exec(
      value,
    );
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = Number(match[7] ?? 0);
  const offsetMinute = Number(match[8] ?? 0);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return false;
  }
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ][month - 1]!;
  return day <= daysInMonth;
}

function rfc3339InstantMicros(value: string): bigint {
  const fraction = /\.(\d+)/.exec(value)?.[1] ?? "";
  const millisecondValue = value.replace(/\.\d+/, `.${fraction.slice(0, 3)}`);
  const milliseconds = BigInt(Date.parse(millisecondValue));
  const remainingMicros = BigInt(fraction.padEnd(6, "0").slice(3, 6));
  return milliseconds * 1000n + remainingMicros;
}

function validateFindingDetails(payload: Record<string, unknown>): void {
  const findings = payload["findings"];
  if (!Array.isArray(findings)) return;
  for (const [index, value] of findings.entries()) {
    if (!isRecord(value)) continue;
    const context = `findings.json:findings.${index}`;
    const validation = value["validation"];
    if (validation !== undefined && validation !== null) {
      if (!isRecord(validation)) {
        throw new ContractValidationError(
          `${context}.validation: expected an object or null.`,
        );
      }
      for (const key of ["summary", "method"] as const) {
        requireOptionalString(validation, key, `${context}.validation`);
      }
      for (const key of ["evidence", "counterEvidence"] as const) {
        requireOptionalStringOrArray(validation, key, `${context}.validation`);
      }
    }

    const attackPath = value["attackPath"];
    if (attackPath !== undefined && attackPath !== null) {
      if (!isRecord(attackPath)) {
        throw new ContractValidationError(
          `${context}.attackPath: expected an object or null.`,
        );
      }
      validateAttackPathBranch(
        attackPath["dataflow"],
        `${context}.attackPath.dataflow`,
        ["source", "sink", "outcome"],
        ["transformations"],
      );
      validateAttackPathBranch(
        attackPath["reachability"],
        `${context}.attackPath.reachability`,
        ["attacker", "entrypoint", "outcome"],
        ["preconditions"],
      );
    }
  }
}

function validateAttackPathBranch(
  value: unknown,
  context: string,
  stringKeys: readonly string[],
  arrayKeys: readonly string[],
): void {
  if (value === undefined || value === null || typeof value === "string")
    return;
  if (!isRecord(value) || typeof value["summary"] !== "string") {
    throw new ContractValidationError(
      `${context}: expected a string or an object with a string summary.`,
    );
  }
  for (const key of stringKeys) requireOptionalString(value, key, context);
  for (const key of arrayKeys) requireOptionalStringArray(value, key, context);
}

function requireOptionalString(
  value: Record<string, unknown>,
  key: string,
  context: string,
): void {
  if (
    value[key] !== undefined &&
    value[key] !== null &&
    (typeof value[key] !== "string" || !isWellFormedUnicode(value[key]))
  ) {
    throw new ContractValidationError(`${context}.${key}: expected a string.`);
  }
}

function requireOptionalStringArray(
  value: Record<string, unknown>,
  key: string,
  context: string,
): void {
  const item = value[key];
  if (
    item !== undefined &&
    item !== null &&
    (!Array.isArray(item) ||
      !item.every(
        (entry) => typeof entry === "string" && isWellFormedUnicode(entry),
      ))
  ) {
    throw new ContractValidationError(
      `${context}.${key}: expected an array of strings.`,
    );
  }
}

function requireOptionalStringOrArray(
  value: Record<string, unknown>,
  key: string,
  context: string,
): void {
  const item = value[key];
  if (
    item !== undefined &&
    item !== null &&
    (typeof item !== "string" || !isWellFormedUnicode(item)) &&
    (!Array.isArray(item) ||
      !item.every(
        (entry) => typeof entry === "string" && isWellFormedUnicode(entry),
      ))
  ) {
    throw new ContractValidationError(
      `${context}.${key}: expected a string or an array of strings.`,
    );
  }
}

function schemaError(
  filename: string,
  errors: readonly ErrorObject[],
): ContractValidationError {
  const first = [...errors].sort((left, right) =>
    left.instancePath.localeCompare(right.instancePath),
  )[0];
  const location = first?.instancePath
    ? first.instancePath.split("/").filter(Boolean).join(".")
    : "<root>";
  return new ContractValidationError(
    `${filename}:${location}: ${first?.message ?? "schema validation failed"}`,
  );
}

function sameArray(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameSet(
  left: ReadonlySet<string>,
  right: ReadonlySet<string>,
): boolean {
  return (
    left.size === right.size && [...left].every((value) => right.has(value))
  );
}

function isContained(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return (
    child === "" ||
    (child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nodeErrorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}
