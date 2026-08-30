import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  lstat,
  open,
  readFile,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import { ContractValidationError } from "./errors.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import {
  requirePrivateOutputDirectory,
  requireSecureOutputAncestry,
} from "./runtime.js";
import type { NormalizedTarget, ScanMode } from "./targets.js";
import { isWindowsUnsafePathComponent } from "./windows-path.js";

const DOCUMENTS = {
  "scan-manifest.json": "scan-manifest.schema.json",
  "findings.json": "findings.schema.json",
  "coverage.json": "coverage.schema.json",
} as const;
const PRODUCER_NAME = "codex-security-plugin";
const SAFE_SCHEMA_ERROR_PROPERTIES = new Set([
  "scan",
  "target",
  "remote",
  "completedAt",
  "sealedAt",
  "artifacts",
  "findings",
  "coverage",
  "scope",
]);
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

type LoadContractOptions = {
  pluginRoot: string;
  expectedScanId?: string;
  expectation?: ScanExpectation;
  workbenchValidated?: boolean;
  signal?: AbortSignal;
};

export async function loadContract(
  scanDirectory: string,
  options: LoadContractOptions,
): Promise<LoadedContract> {
  return (await loadContractWithScanDirectory(scanDirectory, options)).contract;
}

export async function loadContractWithScanDirectory(
  scanDirectory: string,
  options: LoadContractOptions,
): Promise<{ contract: LoadedContract; scanDirectory: string }> {
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
  throwIfAborted(options.signal);
  let findingsPayload: unknown = payloads["findings.json"];

  const ajv = createValidator();
  for (const [filename, schemaName] of Object.entries(DOCUMENTS)) {
    const schema = await readJson(
      join(options.pluginRoot, "schemas", schemaName),
      options.signal,
    );
    let validate: ReturnType<typeof ajv.compile>;
    try {
      validate = ajv.compile(schema);
    } catch {
      throw new ContractValidationError(`${schemaName}: invalid JSON Schema.`);
    }
    let payload: unknown =
      filename === "findings.json"
        ? findingsPayload
        : payloads[filename as keyof typeof payloads];
    let valid: boolean;
    try {
      const result = validate(payload);
      if (typeof result !== "boolean") {
        throw new Error("asynchronous JSON Schema validation is unsupported");
      }
      valid = result;
      if (!valid && filename === "findings.json") {
        payload = legacySealedFindingsForValidation(payload);
        const compatibleResult = validate(payload);
        if (typeof compatibleResult !== "boolean") {
          throw new Error("asynchronous JSON Schema validation is unsupported");
        }
        valid = compatibleResult;
      }
    } catch {
      throw new ContractValidationError(`${schemaName}: invalid JSON Schema.`);
    }
    if (!valid) {
      throw schemaError(filename, validate.errors ?? []);
    }
    if (filename === "findings.json") findingsPayload = payload;
    throwIfAborted(options.signal);
  }
  const manifest = payloads["scan-manifest.json"] as unknown as ScanManifest;
  const findings = findingsPayload as FindingsDocument;
  const coverage = payloads["coverage.json"] as unknown as CoverageDocument;
  if (
    options.expectedScanId !== undefined &&
    manifest.scan.id !== options.expectedScanId
  ) {
    throw new ContractValidationError(
      `Scan artifacts do not match selected scan ${options.expectedScanId}.`,
    );
  }
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

  validateCanonicalContract(manifest, findings);

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
    validateExpectation(
      manifest,
      coverage,
      options.expectation,
      options.workbenchValidated === true,
    );
  }
  await verifyScanRoot(scanRoot, options.signal);
  return {
    contract: { manifest, findings, coverage },
    scanDirectory: scanRoot.path,
  };
}

export async function requireCanonicalScanDirectory(
  scanDirectory: string,
  signal?: AbortSignal,
): Promise<string> {
  return (await requireScanRoot(scanDirectory, signal)).path;
}

type JsonRecord = Record<string, unknown>;

function legacySealedFindingsForValidation(payload: unknown): unknown {
  const compatible = structuredClone(payload);
  if (!isJsonRecord(compatible) || !Array.isArray(compatible["findings"])) {
    return compatible;
  }
  for (const finding of compatible["findings"]) {
    if (!isJsonRecord(finding)) continue;
    const legacyEvidence = finding["code_evidence"];
    if (Array.isArray(legacyEvidence)) {
      const compatibleEvidence: JsonRecord[] = [];
      for (const evidence of legacyEvidence) {
        if (!isJsonRecord(evidence)) continue;
        const id = evidence["id"];
        const code = evidence["code"];
        if (
          typeof id !== "string" ||
          id.length === 0 ||
          typeof code !== "string" ||
          code.length === 0
        ) {
          continue;
        }
        compatibleEvidence.push(evidence);
      }
      finding["code_evidence"] = compatibleEvidence;
    } else if ("code_evidence" in finding && legacyEvidence !== null) {
      delete finding["code_evidence"];
    }

    for (const [sectionName, listFields] of [
      ["root_cause", ["evidenceRefs", "evidence_refs"]],
      [
        "validation",
        [
          "assertions",
          "counterEvidence",
          "evidenceRefs",
          "evidence_refs",
          "limitations",
        ],
      ],
      [
        "attackPath",
        [
          "assumptions",
          "blindspots",
          "controls",
          "evidenceRefs",
          "evidence_refs",
          "limitations",
          "preconditions",
          "steps",
        ],
      ],
    ] satisfies Array<[string, string[]]>) {
      const section = finding[sectionName];
      if (!isJsonRecord(section)) continue;
      normalizeLegacyStringLists(section, listFields);
    }

    const legacyRootCause = finding["root_cause"];
    if (isJsonRecord(legacyRootCause)) {
      removeUnsupportedLegacyStrings(legacyRootCause, [
        "summary",
        "code",
        "language",
      ]);
    } else if (
      "root_cause" in finding &&
      legacyRootCause !== null &&
      typeof legacyRootCause !== "string"
    ) {
      delete finding["root_cause"];
    }

    const validation = finding["validation"];
    if (isJsonRecord(validation)) {
      normalizeLegacyStringOrList(validation, "evidence");
      removeUnsupportedLegacyStrings(validation, ["method", "summary"]);
      removeUnsupportedLegacyNullableStrings(validation, [
        "status",
        "disposition",
        "result",
      ]);
    }

    const attackPath = finding["attackPath"];
    if (!isJsonRecord(attackPath)) continue;
    removeUnsupportedLegacyStrings(attackPath, ["summary"]);
    for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
      const detail = attackPath[field];
      if (detail === null) {
        delete attackPath[field];
        continue;
      }
      if (typeof detail === "string") {
        if (detail.length === 0) delete attackPath[field];
        continue;
      }
      if (!isJsonRecord(detail)) {
        if (field in attackPath) delete attackPath[field];
        continue;
      }
      removeUnsupportedLegacyStrings(detail, [
        "summary",
        "source",
        "sink",
        "outcome",
        ...(field === "reachability" ? ["attacker", "entrypoint"] : []),
      ]);
      normalizeLegacyStringLists(detail, [
        "evidenceRefs",
        "evidence_refs",
        "transformations",
        ...(field === "reachability" ? ["preconditions"] : []),
      ]);
    }
    for (const field of ["impact", "likelihood"]) {
      const detail = attackPath[field];
      if (isJsonRecord(detail)) {
        removeUnsupportedLegacyStrings(detail, ["level", "rationale", "why"]);
      } else if (
        detail !== undefined &&
        detail !== null &&
        (typeof detail !== "string" || detail.length === 0)
      ) {
        delete attackPath[field];
      }
    }
  }
  return compatible;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeLegacyStringLists(
  section: JsonRecord,
  fields: string[],
): void {
  for (const field of fields) {
    if (!(field in section)) continue;
    const value = section[field];
    if (Array.isArray(value)) {
      section[field] = value.filter(
        (item): item is string => typeof item === "string" && item.length > 0,
      );
    } else if (typeof value === "string" && value.length > 0) {
      section[field] = [value];
    } else {
      delete section[field];
    }
  }
}

function normalizeLegacyStringOrList(section: JsonRecord, field: string): void {
  if (!(field in section)) return;
  const value = section[field];
  if (typeof value === "string") {
    if (value.length === 0) delete section[field];
    return;
  }
  if (!Array.isArray(value)) {
    delete section[field];
    return;
  }
  const normalized = value.filter(
    (item): item is string => typeof item === "string" && item.length > 0,
  );
  section[field] = normalized;
}

function removeUnsupportedLegacyStrings(
  section: JsonRecord,
  fields: string[],
): void {
  for (const field of fields) {
    if (
      field in section &&
      (typeof section[field] !== "string" || section[field].length === 0)
    ) {
      delete section[field];
    }
  }
}

function removeUnsupportedLegacyNullableStrings(
  section: JsonRecord,
  fields: string[],
): void {
  for (const field of fields) {
    if (
      field in section &&
      section[field] !== null &&
      (typeof section[field] !== "string" || section[field].length === 0)
    ) {
      delete section[field];
    }
  }
}

function validateCanonicalContract(
  manifest: ScanManifest,
  findings: FindingsDocument,
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

  for (const [findingIndex, finding] of findings.findings.entries()) {
    const context = `findings.findings[${findingIndex}]`;
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
    if (finding.fingerprints.primary !== fingerprint) {
      throw new ContractValidationError(
        `${context}.fingerprints: does not match derived fingerprint.`,
      );
    }
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

export async function readScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  const file = await openCheckedScanFile(
    scanDirectory,
    relativePath,
    context,
    signal,
  );
  try {
    return await file.readFile({ signal });
  } finally {
    await file.close();
  }
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
  const safePath = portableRelativePath(relativePath, context);
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
  if (scan.sealedAt !== scan.completedAt) {
    throw new ContractValidationError(
      "Manifest sealedAt must match completedAt.",
    );
  }

  const artifactPaths = new Set<string>();
  const artifactCollisionKeys = new Set<string>();
  for (const [index, artifact] of scan.artifacts.entries()) {
    throwIfAborted(signal);
    const context = `manifest.scan.artifacts[${index}]`;
    const normalized = portableRelativePath(artifact.path, `${context}.path`);
    const collisionKey = normalized.toLowerCase();
    if (artifactCollisionKeys.has(collisionKey)) {
      throw new ContractValidationError(
        `${context}.path: duplicate artifact path.`,
      );
    }
    artifactPaths.add(normalized);
    artifactCollisionKeys.add(collisionKey);
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
      const normalized = portableRelativePath(receipt, "coverage receipt");
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
    const writeup = finding.writeup;
    if (writeup === undefined) continue;
    const file = await openCheckedScanFile(
      scanDir,
      writeup.reportPath,
      `findings[${index}].writeup.reportPath`,
      signal,
      expectedRoot,
    );
    await file.close();
  }
  const hardening = manifest.scan.hardening;
  if (hardening !== undefined) {
    const file = await openCheckedScanFile(
      scanDir,
      hardening.portfolioPath,
      "manifest.scan.hardening.portfolioPath",
      signal,
      expectedRoot,
    );
    await file.close();
  }
}

function validateExpectation(
  manifest: ScanManifest,
  coverage: CoverageDocument,
  expectation: ScanExpectation,
  workbenchValidated = false,
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

  const requested = expectation.target;
  if (!workbenchValidated) {
    const target = scan.target;
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
    } else if (target.kind === "git_diff") {
      throw new ContractValidationError(
        "Repository scan manifest target must not be git_diff.",
      );
    } else if (
      target.kind !== "directory_snapshot" &&
      expectation.repositoryRevision !== null &&
      target.revision !== expectation.repositoryRevision
    ) {
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
    try {
      requirePrivateOutputDirectory(returned, canonical);
      await requireSecureOutputAncestry(canonical);
    } catch (error) {
      throw new ContractValidationError(
        error instanceof Error
          ? error.message
          : "Scan directory must remain private to the current user.",
        { cause: error },
      );
    }
    return { path: canonical, metadata: returned };
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
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
    requirePrivateOutputDirectory(current, root.path);
    await requireSecureOutputAncestry(root.path);
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
    value.trim().length === 0 ||
    !isWellFormedUnicode(value) ||
    value === "." ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    /[\u0000-\u001f]/u.test(value)
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

function portableRelativePath(value: string, context: string): string {
  const normalized = safeRelativePath(value, context);
  if (value.split("/").some(isWindowsUnsafePathComponent)) {
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
  try {
    return parseJson(path, await readFile(path, { signal }));
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    if (nodeErrorCode(error) === "ENOENT") {
      throw new ContractValidationError(
        `Missing required contract document: ${path}`,
      );
    }
    throw new ContractValidationError(`${path}: unreadable JSON document.`, {
      cause: error,
    });
  }
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
      validateParsedJson(item, `${context}.<property>`);
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
  const ajv = new Ajv2020({ allErrors: false, strict: false });
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
    const buffer = Buffer.alloc(64 * 1024);
    while (true) {
      throwIfAborted(signal);
      const { bytesRead } = await file.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
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
      opened.ino !== checked.metadata.ino ||
      !(await sameCheckedFileDevice(file, checked, opened))
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

export async function sameCheckedFileDevice(
  file: FileHandle,
  checked: CheckedScanFile,
  opened: Stats,
  platform: NodeJS.Platform = process.platform,
  openReference: (path: string, flags: number) => Promise<FileHandle> = open,
): Promise<boolean> {
  if (opened.ino !== checked.metadata.ino) return false;
  if (opened.dev === checked.metadata.dev) return true;
  if (platform !== "win32") return false;

  const [openedIdentity, checkedIdentity] = await Promise.all([
    file.stat({ bigint: true }),
    lstat(checked.path, { bigint: true }),
  ]);
  if (
    !openedIdentity.isFile() ||
    !checkedIdentity.isFile() ||
    checkedIdentity.isSymbolicLink() ||
    openedIdentity.ino !== checkedIdentity.ino
  ) {
    return false;
  }

  const reference = await openReference(
    checked.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const referenceIdentity = await reference.stat({ bigint: true });
    return (
      referenceIdentity.isFile() &&
      openedIdentity.dev === referenceIdentity.dev &&
      openedIdentity.ino === referenceIdentity.ino
    );
  } finally {
    await reference.close();
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

function schemaError(
  filename: string,
  errors: readonly ErrorObject[],
): ContractValidationError {
  const first = errors[0];
  const segments = first?.instancePath.split("/").filter(Boolean) ?? [];
  const location =
    segments.length === 0
      ? "<root>"
      : segments
          .map((segment) => {
            if (/^(?:0|[1-9]\d{0,9})$/.test(segment)) return segment;
            return SAFE_SCHEMA_ERROR_PROPERTIES.has(segment)
              ? segment
              : "<property>";
          })
          .join(".");
  const keyword = first?.keyword ?? "unknown";
  const count = errors.length;
  const format = first?.params["format"];
  const detail =
    keyword === "format" && format === "date-time" ? "; date-time" : "";
  return new ContractValidationError(
    `${filename}:${location}: schema validation failed (${keyword}${detail}; ${count} ${count === 1 ? "error" : "errors"}).`,
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
