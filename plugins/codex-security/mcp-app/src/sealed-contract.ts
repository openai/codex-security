import { isDeepStrictEqual as sameArray } from "node:util";
import { createHash, hash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setImmediate } from "node:timers/promises";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import { regexes } from "zod";
import { normalizePersistedFindingDetails } from "./finding-normalization.js";
import { isRecord } from "./record.js";
import {
  adaptTrackingSchema,
  isTrackingDateTime,
  isTrackingRemoteAuthority,
  trackingPortableRelativePath,
} from "./tracking-contract-compat.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import { openScanReadRoot, windowsBinding } from "./native.js";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import {
  filesystemErrorMessage,
  resolvedPathText,
} from "./helpers/helper-files.js";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path.js";
import { escapeControls } from "./helpers/json.js";
import {
  SealedContractError as ContractValidationError,
  SealedContractSchemaError as ContractSchemaError,
  deriveFindingIdentity,
  hasRequiredFindingText,
  safeScopePath,
  safeRelativePath,
  portableRelativePath,
} from "./contract-values.js";

const DOCUMENTS = {
  "scan-manifest.json": "scan-manifest.schema.json",
  "findings.json": "findings.schema.json",
  "coverage.json": "coverage.schema.json",
} as const;

type ContractProfile = "sdk" | "tracking";

type ScanRoot = {
  path: string;
  reader: ReturnType<typeof openScanReadRoot>;
  profile: ContractProfile;
};
export interface LoadedSealedContract {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
}

export async function loadSealedContract(
  scanDirectory: string,
  options: {
    pluginRoot?: string;
    expectedScanId?: string;
    signal?: AbortSignal;
    // Preserve the existing readers' admission rules without changing public SDK options.
    profile?: ContractProfile;
  } = {},
): Promise<{ contract: LoadedSealedContract; scanDirectory: string }> {
  const profile = options.profile ?? "sdk";
  const validators = await loadContractValidators(
    options.pluginRoot ??
      dirname(
        dirname(
          import.meta.url.startsWith("file:")
            ? fileURLToPath(import.meta.url)
            : import.meta.url,
        ),
      ),
    options.signal,
    profile,
  );
  const scanRoot = await requireScanRoot(
    scanDirectory,
    options.signal,
    profile,
  );
  try {
    const documentDigests = new Map<string, string>();
    const payloads: Record<string, unknown> = {};
    for (const filename of Object.keys(DOCUMENTS)) {
      payloads[filename] = await readScanJson(
        scanRoot,
        filename as keyof typeof DOCUMENTS,
        documentDigests,
        options.signal,
        profile,
      );
    }
    throwIfAborted(options.signal);

    for (const { filename, schemaName, validate } of validators) {
      let payload = payloads[filename];
      if (profile === "tracking" && filename === "findings.json") {
        // The tracking reader historically validates the normalized legacy view.
        // Seals continue to bind the original bytes read above.
        payload = normalizePersistedFindings(payload, profile);
        validateParsedJson(payload, filename);
      } else if (profile === "tracking" && filename === "coverage.json") {
        payload = normalizeTrackingCoverage(payload);
      }
      let valid: boolean;
      try {
        const validatePayload = (payload: unknown) => {
          const result = validate(payload);
          if (typeof result !== "boolean") {
            throw new Error(
              "asynchronous JSON Schema validation is unsupported",
            );
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

    validateCanonicalContract(manifest, findings, coverage, profile);

    await validateSeal(
      scanRoot,
      manifest,
      findings,
      coverage,
      documentDigests,
      options.signal,
      profile === "sdk",
    );
    if (profile === "tracking")
      await checkScanFile(scanRoot, "report.md", "report.md", options.signal);
    await verifyScanRoot(scanRoot, options.signal);
    return {
      contract: { manifest, findings, coverage },
      scanDirectory: scanRoot.path,
    };
  } finally {
    scanRoot.reader.close();
  }
}

/** Normalize optional legacy details on a copy, without changing saved artifacts. */
function normalizePersistedFindings(
  payload: unknown,
  profile: ContractProfile = "sdk",
): unknown {
  const compatible = structuredClone(payload);
  if (!isRecord(compatible) || !Array.isArray(compatible["findings"])) {
    return compatible;
  }
  for (const finding of compatible["findings"]) {
    if (!isRecord(finding)) continue;
    normalizePersistedFindingDetails(finding, profile);
  }
  return compatible;
}

/** Tracking validates normalized receipt references but seals the original bytes. */
function normalizeTrackingCoverage(payload: unknown): unknown {
  const compatible = structuredClone(payload);
  if (!isRecord(compatible) || !Array.isArray(compatible["surfaces"])) {
    return compatible;
  }
  for (const [surfaceIndex, surface] of compatible["surfaces"].entries()) {
    if (!isRecord(surface) || !Array.isArray(surface["receiptRefs"])) continue;
    for (const [refIndex, reference] of surface["receiptRefs"].entries()) {
      if (typeof reference !== "string") continue;
      surface["receiptRefs"][refIndex] = trackingPortableRelativePath(
        reference,
        `coverage.surfaces[${surfaceIndex}].receiptRefs[${refIndex}]`,
      );
    }
  }
  return compatible;
}

function validateCanonicalContract(
  manifest: ScanManifest,
  findings: FindingsDocument,
  coverage: CoverageDocument,
  profile: ContractProfile,
): void {
  const requireText = (value: string | undefined, context: string) => {
    if (!hasRequiredFindingText(value ?? "")) {
      throw new ContractValidationError(
        `${context}: expected a non-empty string.`,
      );
    }
  };
  const scan = manifest.scan;
  if (profile === "tracking") {
    for (const [context, value] of [
      ["manifest.scan.id", scan.id],
      ["manifest.scan.producer.name", scan.producer.name],
      ["manifest.scan.producer.version", scan.producer.version],
      ["scan.target.targetId", scan.target.targetId],
      ["scan.target.displayName", scan.target.displayName],
    ] as const) {
      requireText(value, context);
    }
    if (scan.target.kind === "git_revision") {
      requireText(scan.target.revision, "scan.target.revision");
    }
    for (const [index, artifact] of scan.artifacts.entries()) {
      requireText(
        artifact.mediaType,
        `manifest.scan.artifacts[${index}].mediaType`,
      );
    }
  }
  const remote = manifest.scan.target.remote;
  if (remote !== undefined) {
    const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]+)/.exec(
      profile === "tracking" ? remote.replace(/^ +/u, "") : remote,
    )?.[1];
    if (
      remote.includes("\\") ||
      (profile === "tracking" &&
        /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(remote)) ||
      authority === undefined
    ) {
      throw new ContractValidationError(
        "scan.target.remote: expected a sanitized canonical absolute URL.",
      );
    }
    if (authority.includes("@")) {
      throw new ContractValidationError(
        "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
      );
    }
    if (profile === "tracking") {
      if (!isTrackingRemoteAuthority(authority)) {
        throw new ContractValidationError(
          "scan.target.remote: expected a sanitized canonical absolute URL.",
        );
      }
      if (/\?[^#]+|#./u.test(remote)) {
        throw new ContractValidationError(
          "scan.target.remote: remote URL must not contain credentials, query, or fragment.",
        );
      }
    } else {
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
  }

  for (const field of ["includePaths", "excludePaths"] as const) {
    for (const [index, value] of manifest.scan.scope[field].entries()) {
      try {
        if (profile === "tracking")
          safeContractPath(value, "manifest scope path", profile, true);
        else safeScopePath(value);
      } catch (error) {
        throw new ContractValidationError(
          `manifest.scan.scope.${field}[${index}]: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
    }
  }

  if (profile === "tracking") {
    const surfaceIds = new Set<string>();
    for (const [index, surface] of coverage.surfaces.entries()) {
      const context = `coverage.surfaces[${index}]`;
      requireText(surface.id, `${context}.id`);
      requireText(surface.label, `${context}.label`);
      if (surfaceIds.has(surface.id)) {
        throw new ContractValidationError(
          `${context}.id: duplicate surface id.`,
        );
      }
      surfaceIds.add(surface.id);
    }
  }
  const activeDeferredIds = new Set<string>();
  const deferredWork =
    profile === "tracking" && coverage.deferred === undefined
      ? []
      : coverage.deferred;
  for (const [index, deferred] of deferredWork.entries()) {
    activeDeferredIds.add(deferred.id);
    if (typeof deferred["candidateId"] === "string") {
      activeDeferredIds.add(deferred["candidateId"]);
    }
    for (const [pathIndex, path] of (deferred.paths ?? []).entries()) {
      const context = `coverage.deferred[${index}].paths[${pathIndex}]`;
      try {
        safeContractPath(path, context, profile, true);
      } catch (error) {
        throw new ContractValidationError(
          `${context}: expected a safe repository-relative POSIX path.`,
          { cause: error },
        );
      }
    }
  }
  if (profile === "tracking") {
    const resolvedDeferredIds = new Set<string>();
    for (const [index, resolved] of (
      coverage.resolvedDeferred ?? []
    ).entries()) {
      const context = `coverage.resolvedDeferred[${index}]`;
      requireText(resolved.id, `${context}.id`);
      requireText(resolved.reason, `${context}.reason`);
      if (resolvedDeferredIds.has(resolved.id)) {
        throw new ContractValidationError(
          `${context}.id: duplicate resolved deferred id.`,
        );
      }
      if (activeDeferredIds.has(resolved.id)) {
        throw new ContractValidationError(
          `${context}.id: deferred work is still active.`,
        );
      }
      resolvedDeferredIds.add(resolved.id);
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
        safeContractPath(location.path, `${locationContext}.path`, profile);
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
    const evidenceIds = new Set<string>();
    for (const [evidenceIndex, evidence] of (
      finding.codeEvidence ?? []
    ).entries()) {
      const evidenceContext = `${context}.codeEvidence[${evidenceIndex}]`;
      if (profile === "tracking") {
        requireText(evidence.code, `${evidenceContext}.code`);
        if (evidenceIds.has(evidence.id)) {
          throw new ContractValidationError(
            `${evidenceContext}.id: duplicate code-evidence id.`,
          );
        }
        evidenceIds.add(evidence.id);
      }
      try {
        safeContractPath(evidence.path, `${evidenceContext}.path`, profile);
      } catch (error) {
        throw new ContractValidationError(
          `${evidenceContext}.path: expected a safe repository-relative POSIX path.`,
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
    if (
      profile === "tracking"
        ? !sameArray(finding.fingerprints, fingerprints)
        : finding.fingerprints.primary !== fingerprints.primary
    ) {
      throw new ContractValidationError(
        `${context}.fingerprints: does not match derived fingerprint.`,
      );
    }
  }
}

function safeContractPath(
  value: string,
  context: string,
  profile: ContractProfile,
  allowDot = false,
): string {
  // The tracking producer rejects drive-like prefixes using Unicode letters.
  if (profile === "tracking" && /^\p{L}:/u.test(value)) {
    throw new ContractValidationError(
      `${context}: expected a safe repository-relative POSIX path.`,
    );
  }
  return safeRelativePath(value, context, allowDot);
}

function portableContractPath(
  value: string,
  context: string,
  profile: ContractProfile,
): string {
  return profile === "tracking"
    ? trackingPortableRelativePath(value, context)
    : portableRelativePath(value, context);
}

async function validateSeal(
  root: ScanRoot,
  manifest: ScanManifest,
  findings: FindingsDocument,
  coverage: CoverageDocument,
  documentDigests: ReadonlyMap<string, string>,
  signal?: AbortSignal,
  requireDerivedFiles = true,
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
    const normalized = portableContractPath(
      artifact.path,
      `${context}.path`,
      root.profile,
    );
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
      (await sha256ScanFile(root, normalized, context, signal));
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
    const normalized = portableContractPath(
      reference,
      context.toLowerCase(),
      root.profile,
    );
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
    if (root.profile === "tracking" && surface.receiptRefs === undefined)
      continue;
    for (const receipt of surface.receiptRefs) {
      requireSealedReference(receipt, "Coverage receipt");
    }
  }
  const extensions = scan["extensions"];
  const imported = isRecord(extensions) ? extensions["import"] : undefined;
  if (isRecord(imported) && "sourceRef" in imported) {
    requireSealedReference(imported["sourceRef"], "Import source");
  }

  if (!requireDerivedFiles) return;
  for (const [index, finding] of findings.findings.entries()) {
    const writeup = finding.writeup;
    if (writeup === undefined) continue;
    await checkScanFile(
      root,
      writeup.reportPath,
      `findings[${index}].writeup.reportPath`,
      signal,
    );
  }
  const hardening = manifest.scan.hardening;
  if (hardening !== undefined) {
    await checkScanFile(
      root,
      hardening.portfolioPath,
      "manifest.scan.hardening.portfolioPath",
      signal,
    );
  }
}

export async function requireSealedScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<string> {
  const root = await requireScanRoot(scanDirectory, signal);
  try {
    await checkScanFile(root, relativePath, context, signal);
    await verifyScanRoot(root, signal);
    return join(root.path, portableRelativePath(relativePath, context));
  } finally {
    root.reader.close();
  }
}

export async function readSealedScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  const root = await requireScanRoot(scanDirectory, signal);
  try {
    const bytes = await readHeldFile(root, relativePath, context, signal);
    await verifyScanRoot(root, signal);
    return bytes;
  } finally {
    root.reader.close();
  }
}

async function requireScanRoot(
  scanDirectory: string,
  signal?: AbortSignal,
  profile: ContractProfile = "sdk",
): Promise<ScanRoot> {
  throwIfAborted(signal);
  const absolute = resolve(scanDirectory);
  let root: ScanRoot | undefined;
  try {
    const identity = await scanDirectoryIdentity(absolute);
    const path =
      process.platform === "win32"
        ? resolvedPathText(absolute)
        : decodePosixBytes(
            await realpath(encodePosixPath(absolute), { encoding: "buffer" }),
          );
    throwIfAborted(signal);
    root = { path, reader: openScanReadRoot(path), profile };
    const current = await scanDirectoryIdentity(absolute);
    const canonical = await scanDirectoryIdentity(path);
    if (!sameArray(current, identity) || !sameArray(canonical, identity)) {
      throw new Error("scan directory changed while opening");
    }
    if (profile === "sdk") {
      try {
        await requirePrivateScanRoot(path);
      } catch (error) {
        throw new ContractValidationError(
          error instanceof Error
            ? error.message
            : "Scan directory must remain private to the current user.",
          { cause: error },
        );
      }
    }
    root.reader.verify();
    throwIfAborted(signal);
    return root;
  } catch (error) {
    root?.reader.close();
    throwIfAborted(signal);
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(
      "Scan directory must be an existing non-symlink directory.",
      { cause: error },
    );
  }
}

async function scanDirectoryIdentity(path: string) {
  if (process.platform === "win32") {
    return windowsFileSystem(windowsBinding()).directoryIdentity(
      widePath(path),
    );
  }
  const metadata = await lstat(encodePosixPath(path));
  if (!metadata.isDirectory()) throw new Error("not a directory");
  return { dev: metadata.dev, ino: metadata.ino };
}

async function verifyScanRoot(
  root: ScanRoot,
  signal?: AbortSignal,
): Promise<void> {
  try {
    throwIfAborted(signal);
    if (root.profile === "sdk") await requirePrivateScanRoot(root.path);
    root.reader.verify();
    throwIfAborted(signal);
  } catch (error) {
    throwIfAborted(signal);
    throw new ContractValidationError(
      "Scan directory changed while reading the canonical contract.",
      { cause: error },
    );
  }
}

async function requirePrivateScanRoot(path: string): Promise<void> {
  if (process.platform === "win32") return;
  const effectiveUid = process.geteuid?.();
  const metadata = await lstat(encodePosixPath(path));
  if ((metadata.mode & 0o077) !== 0)
    throw new ContractValidationError(
      `Scan output directory must not be accessible to other users (chmod 700): ${path}`,
    );
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid)
    throw new ContractValidationError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  let current = dirname(path);
  while (true) {
    const parent = await lstat(encodePosixPath(current));
    if (!parent.isDirectory())
      throw new ContractValidationError(
        `Scan output parent must be a non-symlink directory: ${current}`,
      );
    if (
      effectiveUid !== undefined &&
      parent.uid !== 0 &&
      parent.uid !== effectiveUid
    )
      throw new ContractValidationError(
        `Scan output parent must have a trusted owner: ${current}`,
      );
    if ((parent.mode & 0o022) !== 0 && (parent.mode & 0o1000) === 0)
      throw new ContractValidationError(
        `Scan output parent must not be group- or world-writable without the sticky bit: ${current}`,
      );
    const next = dirname(current);
    if (next === current) return;
    current = next;
  }
}

function openHeldFile(
  root: ScanRoot,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
) {
  throwIfAborted(signal);
  const normalized = portableContractPath(relativePath, context, root.profile);
  try {
    const file = root.reader.openFile(normalized);
    if (file === null)
      throw Object.assign(new Error("missing file"), { code: "ENOENT" });
    return file;
  } catch (error) {
    throw new ContractValidationError(
      `${context}: expected a file inside the scan directory. ${filesystemErrorMessage(error)}`,
      { cause: error },
    );
  }
}

async function checkScanFile(
  root: ScanRoot,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<void> {
  openHeldFile(root, relativePath, context, signal).close();
}

async function readHeldFile(
  root: ScanRoot,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
  digest?: ReturnType<typeof createHash>,
): Promise<Buffer> {
  const file = openHeldFile(root, relativePath, context, signal);
  const chunks: Buffer[] = [];
  try {
    while (true) {
      throwIfAborted(signal);
      const chunk = file.read(64 * 1024);
      if (chunk.length === 0) break;
      if (digest) digest.update(chunk);
      else chunks.push(chunk);
      await setImmediate();
    }
    throwIfAborted(signal);
    root.reader.verify();
    return Buffer.concat(chunks);
  } finally {
    file.close();
  }
}

async function readScanJson(
  root: ScanRoot,
  relativePath: keyof typeof DOCUMENTS,
  documentDigests: Map<string, string>,
  signal?: AbortSignal,
  profile: ContractProfile = "sdk",
): Promise<Record<string, unknown>> {
  const bytes = await readHeldFile(root, relativePath, relativePath, signal);
  documentDigests.set(relativePath, hash("sha256", bytes));
  return parseJson(
    profile === "tracking" ? relativePath : join(root.path, relativePath),
    bytes,
    profile,
  );
}

async function sha256ScanFile(
  root: ScanRoot,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<string> {
  const digest = createHash("sha256");
  await readHeldFile(root, relativePath, context, signal, digest);
  return digest.digest("hex");
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

function parseJson(
  path: string,
  bytes: Uint8Array,
  profile: ContractProfile = "sdk",
): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new ContractValidationError(`${path}: unreadable JSON document.`, {
      cause: error,
    });
  }
  let payload: unknown;
  const decimalFields = new WeakMap<object, Set<string>>();
  try {
    payload = JSON.parse(
      text,
      function (
        this: object,
        key: string,
        value: unknown,
        context?: { source?: string },
      ) {
        if (
          profile === "tracking" &&
          (key === "startLine" || key === "endLine") &&
          typeof value === "number" &&
          context?.source !== undefined &&
          /[.eE]/u.test(context.source)
        ) {
          const fields = decimalFields.get(this) ?? new Set<string>();
          fields.add(key);
          decimalFields.set(this, fields);
        }
        return value;
      },
    );
  } catch (error) {
    const message = `${path}: invalid JSON: ${String(error)}`;
    throw new ContractValidationError(
      profile === "tracking" && error instanceof SyntaxError
        ? escapeControls(message)
        : message,
      { cause: error },
    );
  }
  if (!isRecord(payload)) {
    throw new ContractValidationError(`${path}: expected a JSON object.`);
  }
  validateParsedJson(
    payload,
    path,
    !(
      profile === "tracking" &&
      payload["documentType"] === "codex-security.findings"
    ),
  );
  // Canonical line numbers are authored as JSON integers by the producer.
  // JSON.parse otherwise loses the distinction between 41, 41.0, and 41e0.
  if (
    profile === "tracking" &&
    payload["documentType"] === "codex-security.findings" &&
    Array.isArray(payload["findings"])
  ) {
    for (const [findingIndex, finding] of payload["findings"].entries()) {
      if (!isRecord(finding)) continue;
      for (const field of ["locations", "codeEvidence"]) {
        const rows = finding[field];
        if (!Array.isArray(rows)) continue;
        for (const [rowIndex, row] of rows.entries()) {
          if (!isRecord(row)) continue;
          for (const line of ["startLine", "endLine"]) {
            if (decimalFields.get(row)?.has(line)) {
              throw new ContractValidationError(
                `${path}.findings[${findingIndex}].${field}[${rowIndex}].${line}: expected an integer JSON number.`,
              );
            }
          }
        }
      }
    }
  }
  return payload;
}

function validateParsedJson(
  value: unknown,
  context: string,
  validateStrings = true,
): void {
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
    if (validateStrings && !value.isWellFormed()) {
      throw new ContractValidationError(
        `${context}: expected well-formed Unicode JSON strings.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      validateParsedJson(item, `${context}[${index}]`, validateStrings);
    }
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (validateStrings && !key.isWellFormed()) {
        throw new ContractValidationError(
          `${context}: expected well-formed Unicode JSON keys.`,
        );
      }
      validateParsedJson(
        item,
        `${context}[${JSON.stringify(key)}]`,
        validateStrings,
      );
    }
  }
}

async function loadContractValidators(
  pluginRoot: string,
  signal?: AbortSignal,
  profile: ContractProfile = "sdk",
) {
  // The plugin schemas are the immutable v0 contract. They are valid Draft
  // 2020-12 but intentionally omit redundant local `type` keywords that Ajv's
  // optional strict-schema linter requires.
  const ajv = new Ajv2020({ allErrors: false, strict: false });
  ajv.addFormat("date-time", {
    type: "string",
    validate:
      profile === "tracking"
        ? (value: string) => isTrackingDateTime(value, validRfc3339DateTime)
        : validRfc3339DateTime,
  });
  const validators = [];
  for (const [filename, schemaName] of Object.entries(DOCUMENTS)) {
    const schema = await readJson(
      join(pluginRoot, "schemas", schemaName),
      signal,
    ).catch((error: unknown) => {
      throwIfAborted(signal);
      const message = error instanceof Error ? error.message : String(error);
      throw new ContractSchemaError(
        profile === "tracking" &&
          error instanceof ContractValidationError &&
          (error.cause instanceof SyntaxError ||
            (error.cause instanceof Error &&
              ("errno" in error.cause || "winerror" in error.cause)))
          ? escapeControls(message)
          : message,
        { cause: error },
      );
    });
    if (profile === "tracking") adaptTrackingSchema(filename, schema);
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

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
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
