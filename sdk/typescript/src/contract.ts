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
import { requirePrivateScanOutput } from "./runtime.js";
import type { NormalizedTarget, ScanMode } from "./targets.js";

const DOCUMENTS = {
  "scan-manifest.json": "scan-manifest.schema.json",
  "findings.json": "findings.schema.json",
  "coverage.json": "coverage.schema.json",
} as const;
const PRODUCER_NAME = "codex-security-plugin";
const MAX_CONTRACT_DOCUMENT_BYTES = {
  "scan-manifest.json": 16 * 1024 * 1024,
  "findings.json": 128 * 1024 * 1024,
  "coverage.json": 32 * 1024 * 1024,
} as const;
const MAX_SCHEMA_DOCUMENT_BYTES = 4 * 1024 * 1024;
const DOCUMENT_READ_CHUNK_BYTES = 64 * 1024;
const MAX_JSON_DEPTH = 256;
const MAX_SCHEMA_NODES = 8192;
const MAX_SCHEMA_COLLECTION_ENTRIES = 4096;
const MAX_SCHEMA_APPLICATOR_EDGES = 128;
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
const SAFE_SCHEMA_PATTERNS = new Set([
  "^(?![^:/?#]+://[^/?#]*@)[^?#]+$",
  "^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$",
  "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\).+$",
  "^[a-f0-9]{64}$",
  "^(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)artifacts/.+$",
  "^csf_[a-f0-9]{24}$",
  "^occ_[a-f0-9]{24}$",
  "^[a-z0-9][a-z0-9._/-]*$",
  "^codex-security/v1:sha256:[a-f0-9]{64}$",
  "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$",
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

export async function loadContract(
  scanDirectory: string,
  options: {
    pluginRoot: string;
    expectation?: ScanExpectation;
    workbenchValidated?: boolean;
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
  throwIfAborted(options.signal);

  const ajv = createValidator();
  for (const [filename, schemaName] of Object.entries(DOCUMENTS)) {
    const schema = await readJson(
      join(options.pluginRoot, "schemas", schemaName),
      options.signal,
    );
    requireSchemaComplexity(schema, schemaName);
    let validate: ReturnType<typeof ajv.compile>;
    try {
      validate = ajv.compile(schema);
    } catch {
      throw new ContractValidationError(`${schemaName}: invalid JSON Schema.`);
    }
    const payload = payloads[filename as keyof typeof payloads];
    let valid: boolean;
    try {
      const result = validate(payload);
      if (typeof result !== "boolean") {
        throw new Error("asynchronous JSON Schema validation is unsupported");
      }
      valid = result;
    } catch {
      throw new ContractValidationError(`${schemaName}: invalid JSON Schema.`);
    }
    if (!valid) {
      throw schemaError(filename, validate.errors ?? []);
    }
    throwIfAborted(options.signal);
  }
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
  return { manifest, findings, coverage };
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

async function requireCheckedScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  expectedRoot?: ScanRoot,
): Promise<CheckedScanFile> {
  // Harden once at prepare; during contract load re-verify the pinned root
  // instead of re-entering requireScanRoot (and Windows ACL work) per artifact.
  const checkedRoot =
    expectedRoot === undefined
      ? await requireScanRoot(scanDirectory, signal)
      : (await verifyScanRoot(expectedRoot, signal), expectedRoot);
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
  if (scan.sealedAt !== scan.completedAt) {
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
      const secured = await requirePrivateScanOutput(returned, canonical);
      return { path: secured.path, metadata: secured.metadata };
    } catch (error) {
      throw new ContractValidationError(
        error instanceof Error
          ? error.message
          : "Scan directory must remain private to the current user.",
        { cause: error },
      );
    }
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
    const secured = await requirePrivateScanOutput(current, root.path);
    if (
      secured.metadata.dev !== root.metadata.dev ||
      secured.metadata.ino !== root.metadata.ino
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
    const bytes = await readBoundedDocument(
      file,
      join(scanDir, relativePath),
      MAX_CONTRACT_DOCUMENT_BYTES[relativePath],
      signal,
    );
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
    bytes = await readBoundedDocument(
      file,
      path,
      MAX_SCHEMA_DOCUMENT_BYTES,
      signal,
    );
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
  } finally {
    await file?.close();
  }
  return parseJson(path, bytes);
}

async function requireDocumentSize(
  file: FileHandle,
  path: string,
  maximum: number,
  signal?: AbortSignal,
): Promise<void> {
  const metadata = await file.stat();
  throwIfAborted(signal);
  if (metadata.size > maximum) {
    throw new ContractValidationError(
      `${path}: JSON document exceeds the ${maximum}-byte limit.`,
    );
  }
}

async function readBoundedDocument(
  file: FileHandle,
  path: string,
  maximum: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  await requireDocumentSize(file, path, maximum, signal);
  const chunks: Buffer[] = [];
  let length = 0;
  let exhausted = false;
  while (length <= maximum && !exhausted) {
    const chunk = Buffer.allocUnsafe(
      Math.min(DOCUMENT_READ_CHUNK_BYTES, maximum + 1 - length),
    );
    let offset = 0;
    while (offset < chunk.byteLength) {
      throwIfAborted(signal);
      const result = await file.read(
        chunk,
        offset,
        chunk.byteLength - offset,
        length,
      );
      throwIfAborted(signal);
      if (result.bytesRead === 0) {
        exhausted = true;
        break;
      }
      offset += result.bytesRead;
      length += result.bytesRead;
      if (length > maximum) {
        throw new ContractValidationError(
          `${path}: JSON document exceeds the ${maximum}-byte limit.`,
        );
      }
    }
    if (offset > 0) chunks.push(chunk.subarray(0, offset));
  }
  return Buffer.concat(chunks, length);
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
  requireJsonNesting(text, path);
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

function requireJsonNesting(text: string, path: string): void {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const character of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "{" || character === "[") {
      depth += 1;
      if (depth > MAX_JSON_DEPTH + 1) {
        throw new ContractValidationError(
          `${path}: JSON document exceeds the ${MAX_JSON_DEPTH}-level nesting limit.`,
        );
      }
    } else if (character === "}" || character === "]") depth -= 1;
  }
}

function validateParsedJson(value: unknown, context: string, depth = 0): void {
  if (depth > MAX_JSON_DEPTH) {
    throw new ContractValidationError(
      `${context}: JSON document exceeds the ${MAX_JSON_DEPTH}-level nesting limit.`,
    );
  }
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
      validateParsedJson(item, `${context}[${index}]`, depth + 1);
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
      validateParsedJson(item, `${context}.<property>`, depth + 1);
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

function requireSchemaComplexity(
  schema: Record<string, unknown>,
  schemaName: string,
): void {
  const pending: Array<{ value: unknown; isSchema: boolean }> = [
    { value: schema, isSchema: true },
  ];
  let nodes = 0;
  let applicatorEdges = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    const value = current.value;
    nodes += 1;
    if (nodes > MAX_SCHEMA_NODES) {
      throw new ContractValidationError(
        `${schemaName}: JSON Schema exceeds the ${MAX_SCHEMA_NODES}-node complexity limit.`,
      );
    }
    if (Array.isArray(value)) {
      if (value.length > MAX_SCHEMA_COLLECTION_ENTRIES) {
        throw new ContractValidationError(
          `${schemaName}: JSON Schema exceeds the ${MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit.`,
        );
      }
      for (const child of value) {
        pending.push({ value: child, isSchema: current.isSchema });
      }
    } else if (isRecord(value)) {
      const entries = Object.entries(value);
      if (entries.length > MAX_SCHEMA_COLLECTION_ENTRIES) {
        throw new ContractValidationError(
          `${schemaName}: JSON Schema exceeds the ${MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit.`,
        );
      }
      for (const [keyword, child] of entries) {
        if (!current.isSchema) {
          pending.push({ value: child, isSchema: false });
          continue;
        }
        if (
          keyword === "$async" ||
          keyword === "$ref" ||
          keyword === "$dynamicRef" ||
          keyword === "$recursiveRef" ||
          keyword === "prefixItems" ||
          keyword === "patternProperties" ||
          keyword === "propertyNames" ||
          keyword === "dependentSchemas" ||
          keyword === "dependencies" ||
          keyword === "uniqueItems"
        ) {
          throw new ContractValidationError(
            `${schemaName}: unsupported JSON Schema keyword.`,
          );
        }
        let edges = 0;
        if (
          (keyword === "allOf" || keyword === "anyOf" || keyword === "oneOf") &&
          Array.isArray(child)
        ) {
          edges = child.length;
        } else if (
          (keyword === "if" ||
            keyword === "then" ||
            keyword === "else" ||
            keyword === "not" ||
            keyword === "items" ||
            keyword === "contains" ||
            keyword === "additionalProperties" ||
            keyword === "unevaluatedProperties" ||
            keyword === "unevaluatedItems") &&
          (typeof child === "boolean" || isRecord(child))
        ) {
          edges = 1;
        } else if (
          (keyword === "properties" ||
            keyword === "$defs" ||
            keyword === "definitions") &&
          isRecord(child)
        ) {
          edges = Object.keys(child).length;
        }
        applicatorEdges += edges;
        if (applicatorEdges > MAX_SCHEMA_APPLICATOR_EDGES) {
          throw new ContractValidationError(
            `${schemaName}: JSON Schema exceeds the ${MAX_SCHEMA_APPLICATOR_EDGES}-edge applicator limit.`,
          );
        }
        if (
          keyword === "pattern" &&
          typeof child === "string" &&
          !SAFE_SCHEMA_PATTERNS.has(child)
        ) {
          throw new ContractValidationError(
            `${schemaName}: unsupported JSON Schema pattern.`,
          );
        }
        if (
          (keyword === "properties" ||
            keyword === "$defs" ||
            keyword === "definitions") &&
          isRecord(child)
        ) {
          const schemas = Object.values(child);
          if (schemas.length > MAX_SCHEMA_COLLECTION_ENTRIES) {
            throw new ContractValidationError(
              `${schemaName}: JSON Schema exceeds the ${MAX_SCHEMA_COLLECTION_ENTRIES}-entry collection limit.`,
            );
          }
          for (const childSchema of schemas) {
            pending.push({ value: childSchema, isSchema: true });
          }
          continue;
        }
        const isSchema =
          keyword !== "const" &&
          keyword !== "enum" &&
          keyword !== "default" &&
          keyword !== "examples" &&
          keyword !== "dependentRequired";
        pending.push({ value: child, isSchema });
      }
    }
  }
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
          .slice(0, MAX_JSON_DEPTH)
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
