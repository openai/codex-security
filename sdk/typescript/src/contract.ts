import { isDeepStrictEqual as sameArray } from "node:util";
import { createHash, hash } from "node:crypto";
import { normalizePersistedFindingDetails } from "./finding-normalization.js";
import { constants, type BigIntStats, type Stats } from "node:fs";
import {
  lstat,
  open,
  readFile,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, join, posix, resolve } from "node:path";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import { regexes } from "zod";
import {
  ContractValidationError,
  abortReason,
  errorMessage,
} from "./errors.js";
import { isRecord } from "./record.js";
import type {
  CoverageDocument,
  Finding,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import {
  requirePrivateOutputDirectory,
  requireSecureOutputAncestry,
} from "./runtime.js";
import type { NormalizedTarget, ScanMode } from "./targets.js";
import { isWithin as isContained } from "./trusted-executable.js";
import { isWindowsUnsafePathComponent } from "./windows-path.js";

const DOCUMENTS = {
  "scan-manifest.json": "scan-manifest.schema.json",
  "findings.json": "findings.schema.json",
  "coverage.json": "coverage.schema.json",
} as const;
const PRODUCER_NAME = "codex-security-plugin";
interface CheckedScanFile {
  path: string;
  metadata: BigIntStats;
  parents: Array<{ path: string; metadata: BigIntStats }>;
}

interface ScanRoot {
  path: string;
  metadata: BigIntStats;
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

export class ContractSchemaError extends ContractValidationError {}

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
  const validators = await loadContractValidators(
    options.pluginRoot,
    options.signal,
  );
  const scanRoot = await requireScanRoot(scanDirectory, options.signal);
  const scanDir = scanRoot.path;
  const documentDigests = new Map<string, string>();
  const payloads: Record<string, unknown> = {};
  for (const filename of Object.keys(DOCUMENTS)) {
    payloads[filename] = await readScanJson(
      scanDir,
      filename as keyof typeof DOCUMENTS,
      documentDigests,
      options.signal,
      scanRoot,
    );
  }
  throwIfAborted(options.signal);

  for (const { filename, schemaName, validate } of validators) {
    let payload: unknown;
    let valid: boolean;
    try {
      payload = payloads[filename];
      const validatePayload = (payload: unknown) => {
        const result = validate(payload);
        if (typeof result !== "boolean") {
          throw new Error("asynchronous JSON Schema validation is unsupported");
        }
        return result;
      };
      valid = validatePayload(payload);
      if (!valid && filename === "findings.json") {
        payload = normalizePersistedFindings(payload);
        valid = validatePayload(payload);
      }
    } catch {
      throw new ContractSchemaError(`${schemaName}: invalid JSON Schema.`);
    }
    if (!valid) {
      throw schemaError(filename, validate.errors ?? []);
    }
    payloads[filename] = payload;
    throwIfAborted(options.signal);
  }
  const manifest = payloads["scan-manifest.json"] as ScanManifest;
  const findings = payloads["findings.json"] as FindingsDocument;
  const coverage = payloads["coverage.json"] as CoverageDocument;
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

/** Normalize optional legacy details on a copy, without changing saved artifacts. */
function normalizePersistedFindings(payload: unknown): unknown {
  const compatible = structuredClone(payload);
  if (!isRecord(compatible) || !Array.isArray(compatible["findings"])) {
    return compatible;
  }
  for (const finding of compatible["findings"]) {
    if (!isRecord(finding)) continue;
    normalizePersistedFindingDetails(finding);
  }
  return compatible;
}

/** Match the producer's Python str.strip without changing saved text. */
export function hasRequiredFindingText(value: string): boolean {
  return !/^[\p{White_Space}\u001c-\u001f]*$/u.test(value);
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

  for (const [index, deferred] of coverage.deferred.entries()) {
    for (const [pathIndex, path] of (deferred.paths ?? []).entries()) {
      const context = `coverage.deferred[${index}].paths[${pathIndex}]`;
      try {
        safeRelativePath(path, context, true);
      } catch (error) {
        throw new ContractValidationError(
          `${context}: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
    }
  }

  const findingIds = new Set<string>();
  for (const [findingIndex, finding] of findings.findings.entries()) {
    const context = `findings.findings[${findingIndex}]`;
    if (findingIds.has(finding.findingId)) {
      throw new ContractValidationError(`${context}: duplicate finding id.`);
    }
    findingIds.add(finding.findingId);
    for (const [field, value] of [
      ["title", finding.title],
      ["summary", finding.summary],
      ["remediation", finding.remediation],
      ["confidence.rationale", finding.confidence.rationale],
      ["taxonomy.category", finding.taxonomy.category],
      ["provenance.source", finding.provenance.source],
      ...(finding.severity.score === undefined
        ? []
        : [["severity.scoringSystem", finding.severity.scoringSystem]]),
    ]) {
      if (!hasRequiredFindingText(value ?? "")) {
        throw new ContractValidationError(
          `${context}.${field}: expected a non-empty string.`,
        );
      }
    }
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
      if ((location.endLine ?? location.startLine) < location.startLine) {
        throw new ContractValidationError(
          `${locationContext}.endLine: expected an integer >= startLine.`,
        );
      }
    }
    for (const [evidenceIndex, evidence] of (
      finding.codeEvidence ?? []
    ).entries()) {
      const evidenceContext = `${context}.codeEvidence[${evidenceIndex}].path`;
      try {
        safeRelativePath(evidence.path, evidenceContext);
      } catch (error) {
        throw new ContractValidationError(
          `${evidenceContext}: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
    }

    const { findingId, occurrenceId, fingerprints } = deriveFindingIdentity(
      manifest.scan.id,
      manifest.scan.target.targetId,
      finding.ruleId,
      finding.identity,
    );
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
    if (finding.fingerprints.primary !== fingerprints.primary) {
      throw new ContractValidationError(
        `${context}.fingerprints: does not match derived fingerprint.`,
      );
    }
  }
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
    for (const part of parts.slice(0, -1)) {
      current = join(current, part);
      const metadata = await lstat(current, { bigint: true });
      throwIfAborted(signal);
      if (!metadata.isDirectory()) {
        throw new Error("unsafe parent");
      }
      parents.push({ path: current, metadata });
    }
    const path = join(scanDir, ...parts);
    const metadata = await lstat(path, { bigint: true });
    throwIfAborted(signal);
    if (!metadata.isFile()) {
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

  const requireSealedReference = (reference: unknown, context: string) => {
    throwIfAborted(signal);
    if (typeof reference !== "string") {
      throw new ContractValidationError(`${context}: expected a string.`);
    }
    const normalized = portableRelativePath(reference, context.toLowerCase());
    if (!normalized.startsWith("artifacts/")) {
      throw new ContractValidationError(
        `${context} must be under artifacts/: ${reference}`,
      );
    }
    if (!artifactPaths.has(normalized)) {
      throw new ContractValidationError(
        `${context} is missing from sealed artifacts: ${reference}`,
      );
    }
  };
  for (const surface of coverage.surfaces) {
    for (const receipt of surface.receiptRefs) {
      requireSealedReference(receipt, "Coverage receipt");
    }
  }
  const extensions = scan["extensions"];
  const imported = isRecord(extensions) ? extensions["import"] : undefined;
  if (isRecord(imported) && "sourceRef" in imported) {
    requireSealedReference(imported["sourceRef"], "Import source");
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
    const actualPaths = scan.scope.includePaths.map(safeScopePath);
    const actual = new Set(actualPaths);
    if (actualPaths.length === actual.size) {
      const expected = new Set(requested.paths);
      if (actual.size === expected.size && actual.isSubsetOf(expected)) return;
    }
    throw new ContractValidationError(
      "Manifest include paths do not match the requested path target.",
    );
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
    const metadata = await lstat(absolute, { bigint: true });
    throwIfAborted(signal);
    const canonical = await realpath(absolute);
    throwIfAborted(signal);
    const current = await lstat(absolute, { bigint: true });
    throwIfAborted(signal);
    const returned = await lstat(canonical, { bigint: true });
    throwIfAborted(signal);
    if (
      !metadata.isDirectory() ||
      !current.isDirectory() ||
      metadata.dev !== current.dev ||
      metadata.ino !== current.ino ||
      !returned.isDirectory() ||
      metadata.dev !== returned.dev ||
      metadata.ino !== returned.ino
    ) {
      throw new Error("not a directory");
    }
    try {
      requirePrivateOutputDirectory(
        { mode: Number(returned.mode), uid: Number(returned.uid) },
        canonical,
      );
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
    const current = await lstat(root.path, { bigint: true });
    throwIfAborted(signal);
    if (
      !current.isDirectory() ||
      current.dev !== root.metadata.dev ||
      current.ino !== root.metadata.ino
    ) {
      throw new Error("scan directory changed while reading");
    }
    requirePrivateOutputDirectory(
      { mode: Number(current.mode), uid: Number(current.uid) },
      root.path,
    );
    await requireSecureOutputAncestry(root.path);
  } catch (error) {
    throwIfAborted(signal);
    throw new ContractValidationError(
      "Scan directory changed while reading the canonical contract.",
      { cause: error },
    );
  }
}

function safeRelativePath(
  value: string,
  context: string,
  allowDot = false,
): string {
  const parts = value.split("/");
  if (
    value.length === 0 ||
    Buffer.from(value, "utf8").toString("utf8") !== value ||
    (!allowDot && value === ".") ||
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
    (!allowDot && normalized === ".") ||
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
  if (
    value.trim().length === 0 ||
    value.split("/").some(isWindowsUnsafePathComponent)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export function safeScopePath(value: string): string {
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
    documentDigests.set(relativePath, hash("sha256", bytes));
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
    if (!value.isWellFormed()) {
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
      if (!key.isWellFormed()) {
        throw new ContractValidationError(
          `${context}: expected well-formed Unicode JSON keys.`,
        );
      }
      validateParsedJson(item, `${context}[${JSON.stringify(key)}]`);
    }
  }
}

async function loadContractValidators(
  pluginRoot: string,
  signal?: AbortSignal,
) {
  // The plugin schemas are the immutable v0 contract. They are valid Draft
  // 2020-12 but intentionally omit redundant local `type` keywords that Ajv's
  // optional strict-schema linter requires.
  const ajv = new Ajv2020({ allErrors: false, strict: false });
  ajv.addFormat("date-time", {
    type: "string",
    validate: validRfc3339DateTime,
  });
  const validators = [];
  for (const [filename, schemaName] of Object.entries(DOCUMENTS)) {
    const schema = await readJson(
      join(pluginRoot, "schemas", schemaName),
      signal,
    ).catch((error: unknown) => {
      throwIfAborted(signal);
      throw new ContractSchemaError(errorMessage(error), { cause: error });
    });
    try {
      const validate = ajv.compile(schema);
      if ("$async" in validate && validate.$async === true) {
        throw new Error("asynchronous JSON Schema validation is unsupported");
      }
      validators.push({ filename, schemaName, validate });
    } catch {
      throw new ContractSchemaError(`${schemaName}: invalid JSON Schema.`);
    }
    throwIfAborted(signal);
  }
  return validators;
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
    const opened = await file.stat({ bigint: true });
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
      const current = await lstat(parent.path, { bigint: true });
      throwIfAborted(signal);
      if (
        !current.isDirectory() ||
        current.dev !== parent.metadata.dev ||
        current.ino !== parent.metadata.ino
      ) {
        throw new ContractValidationError(
          `${context}: checked parent changed before opening the file.`,
        );
      }
    }
    const current = await lstat(checked.path, { bigint: true });
    throwIfAborted(signal);
    if (
      !current.isFile() ||
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
  checked: {
    path: string | Buffer;
    metadata: Pick<Stats | BigIntStats, "dev" | "ino">;
  },
  opened: Pick<Stats | BigIntStats, "dev" | "ino">,
  platform: NodeJS.Platform = process.platform,
  openReference: (
    path: string | Buffer,
    flags: number,
  ) => Promise<FileHandle> = open,
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
  throw abortReason(signal);
}

const RFC3339_DATE_TIME = new RegExp(
  regexes.datetime({ offset: true }).source,
  "i",
);

function validRfc3339DateTime(value: string): boolean {
  return !value.startsWith("0000") && RFC3339_DATE_TIME.test(value);
}

function schemaError(
  filename: string,
  errors: readonly ErrorObject[],
): ContractValidationError {
  const first = errors[0];
  const location = first?.instancePath
    ? JSON.stringify(first.instancePath)
    : "<root>";
  const keyword = first?.keyword ?? "unknown";
  const count = errors.length;
  return new ContractValidationError(
    `${filename}:${location}: schema validation failed (${keyword}${keyword === "format" && first?.params["format"] === "date-time" ? "; date-time" : ""}; ${count} ${count === 1 ? "error" : "errors"})${first?.message ? `: ${first.message}` : ""}.`,
  );
}

function nodeErrorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

/** @internal */
export function sha256Text(value: string): string {
  return hash("sha256", value);
}

export function deriveFindingIdentity(
  scanId: string,
  targetId: string,
  ruleId: string,
  identity: Finding["identity"],
) {
  const fingerprint = `codex-security/v1:sha256:${sha256Text(
    [
      "codex-security/v1",
      targetId,
      ruleId,
      identity.anchor,
      identity.instance ?? "",
    ].join("\0"),
  )}`;
  return {
    findingId: `csf_${sha256Text(fingerprint).slice(0, 24)}`,
    occurrenceId: `occ_${sha256Text([scanId, fingerprint].join("\0")).slice(0, 24)}`,
    ruleId,
    identity,
    fingerprints: {
      algorithm: "codex-security/v1" as const,
      primary: fingerprint,
    },
  };
}
