import { hash, randomUUID } from "node:crypto";
import { chmodSync } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { isBoxedPrimitive, isNativeError, isProxy } from "node:util/types";
import { readCloudCredentials } from "./cloud-publish.js";
import {
  cloudBaseUrl,
  cloudFindingsUrl,
  DEFAULT_CLOUD_BASE_URL,
} from "./cloud-endpoint.js";
import { CodexSecurityError } from "./errors.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  codexSecurityStateDirectory,
  createWindowsOutputDirectory,
  validatePreparedOutputDir,
} from "./runtime.js";
import {
  EXTERNAL_FINDINGS_PROVIDERS,
  readExternalFindings,
  type ExternalFindingsReaderOptions,
} from "./external-findings-read.js";
import {
  canSnapshotWithoutGetters,
  canonicalJson,
  isRecord,
} from "./record.js";
import { notify } from "./value.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { wizFindingRepository } from "./wiz-findings.js";
import { legacyGitHubFindings } from "./github-findings.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import { snykRepositoryUrls } from "./snyk-findings.js";
import { endorRepositoryUrls } from "./endor-findings.js";
import {
  blackDuckReportRepositories,
  projectedBlackDuckRepositoryUrl,
} from "./blackduck-findings.js";
import { veracodeReportRepositories } from "./veracode-findings.js";
import { inspectorReportRepository } from "./inspector-findings.js";
import { sonarRepositoryUrls } from "./sonar-findings.js";
import {
  snapshotImportOptions,
  cloneImportPreview,
  nativeErrorStackGetter,
  snapshotNormalizedFindings,
  type ExternalFindings,
  type ExternalPublicationInput,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  CloudEvidenceDepthError,
  validateImportRequest,
  validateExternalEvidence,
  validateExternalEvidenceShape,
  validateExternalReport,
  validateImportReceipt,
  validateRepositories,
  validateSourceReports,
  validateSourceReport,
} from "./external-import-contract.js";
import type {
  FindingImportRequest,
  FindingImportReceipt,
  ImportRepository,
  SourceReportSummary,
} from "./external-import-models.js";

const MAX_REQUEST_BYTES = 5 * 1024 * 1024;

/** Source and destination for evidence already normalized to the Cloud contract. */
export interface NormalizedExternalPublicationOptions {
  repository: string;
  provider: FindingImportRequest["source"]["provider"];
  sourceKey: string;
  /** Full Inspector project ARNs mapped to independently verified repository URLs. */
  inspectorProjectMap?: ReadonlyMap<string, string>;
}

/** File readers accept the vendor formats installed in this SDK. */
export interface ExternalPublicationOptions extends Omit<
  NormalizedExternalPublicationOptions,
  "provider"
> {
  provider: ExternalFindingsReaderOptions["provider"];
  sourceRepositoryUrl?: string;
}

/** Optional transport, account, cancellation, and progress hooks. */
export interface ExternalPublicationDependencies {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: string, options: RequestInit) => Promise<Response>;
  credentials?: () => Promise<{ access_token: string; account_id: string }>;
  signal?: AbortSignal;
  onProgress?: (event: ExternalPublicationProgress) => void;
}

export interface ExternalPublicationProgress {
  phase:
    | "reading"
    | "discovering"
    | "preparing"
    | "waiting"
    | "uploading"
    | "verifying";
  completed: number;
  total?: number;
}

/** Counts describe acknowledged receipts, even when later transport or readback fails. */
export interface ExternalPublicationResult {
  cloudApiUrl: string;
  cloudUrl?: string;
  status: "complete" | "partial" | "interrupted";
  read: number;
  report?: ExternalFindings["report"];
  ready: number;
  excluded: ExternalFindings["excluded"];
  receipts: FindingImportReceipt[];
  counts: Required<FindingImportReceipt["counts"]>;
  failures: { source_finding_id: string; code: string; message: string }[];
  unacknowledged: number;
  verified: number;
  error?: string;
  savedSubmission?: string;
}

/** Preserve accepted work in CLI JSON output when publication cannot finish. */
export class ExternalPublicationError extends CodexSecurityError {
  constructor(
    message: string,
    public readonly result: ExternalPublicationResult,
    cause: unknown,
  ) {
    super(message, { cause });
  }
}

interface SavedSubmission {
  accountId: string;
  requests: FindingImportRequest[];
  receipts?: FindingImportReceipt[];
  inputProjection?: {
    identityFormat?: 2;
    inputDigest: string;
    savedEvidenceDigest: string;
  };
  // A verified older approval stays at its original deployment-bound filename.
  wireKey?: string;
  // Only a verified released approval may preserve a native value different from fresh JSON.
  legacyApproval?: true;
  // The older canonical file was checked under its lock for a second approval.
  canonicalChecked?: true;
  inspectorProjectMapRequired?: true;
}

export interface ExternalPublicationPreview extends ExternalFindings {
  cloudApiUrl: string;
  cloudUrl?: string;
  accountId: string;
  destination: ImportRepository;
  source: FindingImportRequest["source"];
  resumed: boolean;
  requests: FindingImportRequest[];
}

export interface PreparedExternalPublication {
  preview: ExternalPublicationPreview;
  publish(): Promise<ExternalPublicationResult>;
}

// Limit read concurrency to avoid one network round trip per finding in series.
// Wait for the entire batch on failure so callers never outlive their read tasks.
async function readInBatches<T, U>(
  items: T[],
  read: (item: T) => Promise<U>,
): Promise<U[]> {
  const output: U[] = [];
  for (let start = 0; start < items.length; start += 4) {
    const batch = await Promise.allSettled(
      items.slice(start, start + 4).map(read),
    );
    for (const result of batch) {
      if (result.status === "rejected") throw result.reason;
      output.push(result.value);
    }
  }
  return output;
}

// JSON.stringify serializes boxed primitives after the replacer. Let it
// produce their actual wire values, including false and strings.
function wireJson(value: unknown): string {
  return canonicalJson(value, undefined, isBoxedPrimitive);
}

function sameSubmission(
  left: SavedSubmission,
  right: SavedSubmission,
): boolean {
  return (
    left.accountId === right.accountId &&
    left.inspectorProjectMapRequired === right.inspectorProjectMapRequired &&
    wireJson(left.requests) === wireJson(right.requests)
  );
}

function wireFinding({
  source_finding_id,
  evidence,
}: ExternalFindings["findings"][number]) {
  return { source_finding_id, evidence };
}

function submissionFindings(
  requests: readonly FindingImportRequest[],
): ExternalFindings["findings"] {
  return requests.flatMap((batch) => batch.items.map(wireFinding));
}

function sameNonNumericJson(saved: unknown, current: unknown): boolean {
  // JSON serialization can replace a boxed number with any value, or omit its property.
  if (typeof saved === "number") return true;
  if (saved === current) return true;
  if (Array.isArray(saved) && Array.isArray(current))
    return (
      saved.length === current.length &&
      saved.every((child, i) => sameNonNumericJson(child, current[i]))
    );
  if (!isRecord(saved) || !isRecord(current)) return false;
  return (
    Object.keys(current).every((key) => Object.hasOwn(saved, key)) &&
    Object.keys(saved).every((key) =>
      sameNonNumericJson(saved[key], current[key]),
    )
  );
}

function sameFindingSelection(
  left: ExternalFindings["findings"],
  right: ExternalFindings["findings"],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (finding, index) =>
        finding.source_finding_id === right[index]!.source_finding_id,
    )
  );
}

async function readOptionalFile(path: string): Promise<string | undefined> {
  return readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
}

function reportForJson(report: ExternalFindings["report"]) {
  const errors = report?.["errors"];
  if (!Array.isArray(errors)) return report;
  const json = JSON.stringify(errors, (_key, entry: unknown) =>
    entry instanceof Error ? { ...entry, message: entry.message } : entry,
  );
  return { ...report, errors: JSON.parse(json) as unknown[] };
}

export function externalPublicationStateDirectory(
  environment: NodeJS.ProcessEnv,
): string {
  return join(
    codexSecurityStateDirectory(environment),
    "external-finding-publications",
  );
}

export async function writeAtomicJson(
  path: string,
  value: unknown,
): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(JSON.stringify(value));
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

function sourcePath(repository: ImportRepository): string {
  return `/repository_connectors/${encodeURIComponent(repository.repo_connector_id)}/repositories/${encodeURIComponent(repository.id)}/source_reports`;
}

class CloudImportError extends CodexSecurityError {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function validatePublicationReceipt(
  value: unknown,
  batch: FindingImportRequest,
): FindingImportReceipt {
  const receipt = validateImportReceipt(value);
  const batchItems = new Map(batch.items.map((item) => [item.client_id, item]));
  if (
    receipt.id !== batch.request_id ||
    wireJson(receipt.repository) !== wireJson(batch.repository) ||
    wireJson(receipt.source) !== wireJson(batch.source) ||
    receipt.item_count !== batch.items.length ||
    receipt.results.length !== batch.items.length ||
    new Set(receipt.results.map((item) => item.client_id)).size !==
      batch.items.length ||
    receipt.results.some((item) => !batchItems.has(item.client_id))
  )
    throw new CodexSecurityError(
      "Cloud returned a receipt for a different publication.",
    );
  const actual = { created: 0, updated: 0, unchanged: 0, error: 0 };
  for (const result of receipt.results) {
    actual[result.outcome]++;
    if (result.outcome === "error") {
      if (
        !result.error ||
        result.source_report_id !== null ||
        result.observation_id !== null ||
        result.canonical_finding_id !== null ||
        result.version !== null
      )
        throw new CodexSecurityError(
          "Cloud returned inconsistent item error fields.",
        );
    } else if (
      result.error !== null ||
      !result.source_report_id ||
      !result.observation_id ||
      !result.canonical_finding_id ||
      result.version === null
    )
      throw new CodexSecurityError(
        "Cloud returned an incomplete saved finding.",
      );
  }
  if (wireJson(receipt.counts) !== wireJson(actual))
    throw new CodexSecurityError(
      "Cloud returned inconsistent publication counts.",
    );
  return receipt;
}

async function withImportLocks<T>(
  state: string,
  keys: string[],
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  if (process.platform === "win32")
    await createWindowsOutputDirectory(state, true);
  else await mkdir(state, { recursive: true, mode: 0o700 });
  await validatePreparedOutputDir(state, undefined, true);
  const require = createRequire(import.meta.url);
  const Database = (
    process.versions["bun"]
      ? require("bun:sqlite").Database
      : require("node:sqlite").DatabaseSync
  ) as new (path: string) => { exec(sql: string): void; close(): void };
  const guards: InstanceType<typeof Database>[] = [];
  try {
    for (const key of [...new Set(keys)].sort()) {
      const path = join(state, `${key}.lock.sqlite`);
      const metadata = await lstat(path).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return undefined;
          throw error;
        },
      );
      if (metadata && !metadata.isFile())
        throw new CodexSecurityError(
          "The publication lock is not a regular file.",
        );
      const guard = new Database(path);
      guards.push(guard);
      if (process.platform !== "win32") chmodSync(path, 0o600);
      guard.exec("PRAGMA busy_timeout = 0");
    }
    for (;;) {
      signal?.throwIfAborted();
      let acquired = 0;
      try {
        // SQLite releases these transactions on process exit.
        for (const guard of guards) {
          guard.exec("BEGIN EXCLUSIVE");
          acquired++;
        }
        break;
      } catch (error) {
        const sqliteError = error as { code?: string; errcode?: number };
        if (sqliteError.errcode !== 5 && sqliteError.code !== "SQLITE_BUSY")
          throw error;
        // Older SDKs can acquire historical keys in a different order.
        for (const guard of guards.slice(0, acquired)) guard.exec("ROLLBACK");
        await delay(50, undefined, { signal });
      }
    }
    return await operation();
  } finally {
    for (const guard of guards) guard.close();
  }
}

export async function prepareExternalPublication(
  path: string,
  options: ExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies = {},
): Promise<PreparedExternalPublication> {
  requireExternalImports(dependencies.environment);
  const settings = snapshotImportOptions(options);
  const parsed = await readExternalFindings(path, settings);
  return preparePublicationInput(
    parsed.publication ?? normalizedPublicationInput(parsed.findings),
    { ...settings, provider: EXTERNAL_FINDINGS_PROVIDERS[settings.provider] },
    dependencies,
  );
}

/** Prepare normalized provider evidence without reading a vendor export. */
export async function prepareNormalizedExternalPublication(
  input: ExternalFindings,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies = {},
): Promise<PreparedExternalPublication> {
  requireExternalImports(dependencies.environment);
  const settings = snapshotImportOptions(options);
  return preparePublicationInput(
    normalizedPublicationInput(input),
    settings,
    dependencies,
  );
}

interface PublicationSelection extends ExternalPublicationInput {
  original?: { parsed: ExternalFindings; identity: unknown };
  potentialIds?: string[];
  unprovenIdPrefixes?: string[];
  freshLimitError?: Error;
}

function ownData(value: unknown, key: string) {
  return isRecord(value) && !isProxy(value)
    ? (Object.getOwnPropertyDescriptor(value, key)?.value as unknown)
    : undefined;
}

function withDataProperty<T extends object>(
  record: T,
  key: string,
  value: unknown,
): T {
  const fields = Object.getOwnPropertyDescriptors(record);
  return Object.create(Object.getPrototypeOf(record) as object | null, {
    ...fields,
    [key]: { ...fields[key], value },
  }) as T;
}

// Native cloning discarded enumerable diagnostic fields. Recover its message
// without reading the caller's stack getter or changing their report.
function previousDiagnosticInput(input: ExternalFindings): ExternalFindings {
  const report = ownData(input, "report");
  const errors = ownData(report, "errors");
  if (!isRecord(report) || !Array.isArray(errors) || isProxy(errors))
    return input;
  let entries: PropertyDescriptorMap | undefined;
  for (let index = 0; index < errors.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(errors, index);
    const diagnostic: unknown = descriptor?.value;
    if (!descriptor || !isNativeError(diagnostic)) continue;
    const stack = Object.getOwnPropertyDescriptor(diagnostic, "stack");
    const message = ownData(diagnostic, "message");
    const cause = Object.getOwnPropertyDescriptor(diagnostic, "cause");
    const name = Object.getOwnPropertyDescriptor(diagnostic, "name");
    if (
      Object.getPrototypeOf(diagnostic) !== Error.prototype ||
      typeof message !== "string" ||
      (stack?.get && stack.get !== nativeErrorStackGetter) ||
      (name && typeof name.value !== "string") ||
      (cause &&
        (!Object.hasOwn(cause, "value") ||
          !canSnapshotWithoutGetters(cause.value, true)))
    )
      return input;
    (entries ??= Object.getOwnPropertyDescriptors(errors as object))[index] = {
      ...descriptor,
      value: { message },
    };
  }
  if (!entries) return input;
  const capturedErrors = Object.defineProperties([], entries) as unknown[];
  const capturedReport = withDataProperty(report, "errors", capturedErrors);
  return withDataProperty(input, "report", capturedReport);
}

// Capture before JSON hooks can change their source. If native capture would
// invoke caller code too, the original bytes cannot be observed independently.
function previousNormalizedFindings(
  input: ExternalFindings,
): ExternalFindings | undefined {
  input = previousDiagnosticInput(input);
  if (!canSnapshotWithoutGetters(input, true)) return;
  // Object spread skips a hidden report, but explicitly reading it could run a getter.
  const reportField = Object.getOwnPropertyDescriptor(input, "report");
  if (reportField && !Object.hasOwn(reportField, "value")) return;
  const { report, ...parsed } = input;
  const snapshot: ExternalFindings = structuredClone(parsed);
  if (report !== undefined) snapshot.report = structuredClone(report);
  return snapshot;
}

function normalizedPublicationInput(
  input: ExternalFindings,
): PublicationSelection {
  let original: ExternalFindings | undefined;
  try {
    original = previousNormalizedFindings(input);
  } catch {
    /* A valid JSON export can contain an uncloneable value. */
  }
  let current: ExternalFindings;
  let freshLimitError: Error | undefined;
  try {
    current = snapshotNormalizedFindings(input, undefined, "cloud");
  } catch (error) {
    if (!(error instanceof CloudEvidenceDepthError) || !original) throw error;
    // Serialization stopped before the complete fresh selection was available.
    // Only an independently validated original can recover an existing approval.
    freshLimitError = error;
    current = { read: original.read, findings: [], excluded: [] };
  }
  validateExternalReport(current.report);
  const reader = !freshLimitError
    ? legacyGitHubFindings(input, current)
    : undefined;
  if (reader) original = reader.snapshot;
  try {
    if (original) {
      // The released SDK cloned the report separately, then detached each raw
      // finding before Cloud validation defaulted its typed evidence in place.
      for (const finding of original.findings)
        if (finding.evidence.source_data !== undefined)
          finding.evidence.source_data = structuredClone(
            finding.evidence.source_data,
          );
      for (const finding of original.findings)
        finding.evidence = freshLimitError
          ? validateExternalEvidence(finding.evidence)
          : validateExternalEvidenceShape(finding.evidence);
    }
  } catch {
    if (freshLimitError) throw freshLimitError;
    original = undefined;
  }
  const identities = new Set<string>();
  for (const finding of current.findings) {
    const id = finding.source_finding_id;
    if (!id.trim() || id.includes("\0") || Buffer.byteLength(id) > 512)
      throw new CodexSecurityError(
        "Source finding id must contain 1–512 UTF-8 bytes and no NUL characters.",
      );
    if (identities.has(id))
      throw new CodexSecurityError(
        `Duplicate source finding id ${JSON.stringify(id)}.`,
      );
    identities.add(id);
    try {
      finding.evidence = validateExternalEvidence(finding.evidence);
    } catch (error) {
      if (
        !(error instanceof Error) ||
        (error.message !== "Evidence exceeds the Cloud limit of 256 KiB." &&
          error.message !==
            "Evidence exceeds the Cloud JSON depth limit of 20.") ||
        !original
      )
        throw error;
      // A previous normalized SDK input can contain a Buffer whose captured
      // request fits even when the fresh Buffer JSON exceeds the limit.
      const prior = original.findings.find(
        (row) => row.source_finding_id === id,
      );
      if (!prior || wireJson(prior.evidence) === wireJson(finding.evidence))
        throw error;
      try {
        validateExternalEvidence(prior.evidence);
      } catch {
        throw error;
      }
      freshLimitError = error;
    }
  }
  function identityOf(parsed: ExternalFindings) {
    return parsed.report === undefined
      ? parsed.findings
      : {
          findings: parsed.findings,
          report: reportForJson(parsed.report),
        };
  }
  const identity = identityOf(current);
  return {
    current,
    legacy: current,
    currentIdentity: identity,
    freshLimitError,
    legacyIdentity: identity,
    ...(original
      ? { original: { parsed: original, identity: identityOf(original) } }
      : {}),
    unprovenIdPrefixes: reader?.unprovenIdPrefixes,
    potentialIds:
      reader?.sourceFindingIds ??
      (original
        ? undefined
        : current.findings.map((row) => row.source_finding_id)),
  };
}

// The old hash represented Number objects as {}. Unpublished row properties
// and report metadata cannot be recovered from the immutable saved request.
function verifiableLegacyMetadata(
  { report, findings }: ExternalFindings,
  wireIdentity: boolean,
): boolean {
  let verifiable = true;
  // Only values in these records can be old scalar projections. Their record
  // containers are required by the normalized selection, including an empty report.
  const { errors, ...metadata } = report ?? {};
  JSON.stringify(
    [
      Object.values(metadata),
      // The original hash used the serialized form of report.errors arrays.
      Array.isArray(errors) ? undefined : errors,
      findings.map(({ evidence: _, ...fields }) => Object.values(fields)),
    ],
    (_key, value: unknown) => {
      if (isRecord(value) && !(wireIdentity && isBoxedPrimitive(value))) {
        // {} and string-index records can both be the old form of a scalar.
        let index = 0;
        if (
          Object.keys(value).every((key) => {
            const item = value[key];
            return (
              item === undefined ||
              (key === String(index++) &&
                typeof item === "string" &&
                item.length === 1)
            );
          })
        )
          verifiable = false;
      }
      return value;
    },
  );
  return verifiable;
}

async function preparePublicationInput(
  input: PublicationSelection,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies,
): Promise<PreparedExternalPublication> {
  const { inspectorProjectMap } = options;
  const progress = (event: ExternalPublicationProgress): void =>
    notify(() => dependencies.onProgress?.(event));
  if (
    !options.sourceKey.trim() ||
    options.sourceKey.includes("\0") ||
    Buffer.byteLength(options.sourceKey) > 512
  ) {
    throw new CodexSecurityError(
      "The source key must contain 1–512 UTF-8 bytes and no NUL characters. Use a stable scanner organization/project/branch namespace across imports.",
    );
  }
  progress({ phase: "reading", completed: 0 });
  let {
    current: parsed,
    legacy: legacyParsed,
    currentIdentity,
    legacyIdentity,
  } = input;
  function noFindings(): never {
    const diagnostics = reportForJson(parsed.report)?.["errors"];
    throw new CodexSecurityError(
      `No supported findings are ready to publish. ${parsed.excluded.map((item) => `Item ${item.position}: ${item.reason}`).join(" ")}${Array.isArray(diagnostics) && diagnostics.length ? ` Scanner diagnostics: ${JSON.stringify(diagnostics)}` : ""}`,
    );
  }
  if (
    !parsed.findings.length &&
    !input.original?.parsed.findings.length &&
    !input.potentialIds?.length &&
    !input.unprovenIdPrefixes?.length
  )
    noFindings();
  progress({ phase: "discovering", completed: 0 });
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const apiBaseUrl = cloudBaseUrl(environment);
  const cloudApiUrl = `${apiBaseUrl}/external`;
  // Validate the configured return destination before authentication or uploads.
  cloudFindingsUrl(environment, options.repository);
  const credentials = await (
    dependencies.credentials ?? (() => readCloudCredentials(environment))
  )();
  async function request(
    endpoint: string,
    body?: FindingImportRequest,
  ): Promise<unknown> {
    dependencies.signal?.throwIfAborted();
    // Allow upload and response transport around the server's publication budget.
    const timeout = AbortSignal.timeout(body ? 60_000 : 30_000);
    const response = await (dependencies.fetch ?? globalThis.fetch)(
      `${cloudApiUrl}${endpoint}`,
      {
        method: body ? "POST" : "GET",
        headers: {
          Authorization: `Bearer ${credentials.access_token}`,
          "ChatGPT-Account-ID": credentials.account_id,
          Accept: "application/json",
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: "error",
        signal: dependencies.signal
          ? AbortSignal.any([dependencies.signal, timeout])
          : timeout,
      },
    );
    if (!response.ok) {
      const payload = (await response.json().catch(() => null)) as {
        error?: { message?: string };
      } | null;
      const retryAfter = response.headers.get("Retry-After");
      throw new CloudImportError(
        response.status,
        `Cloud import failed (HTTP ${response.status}). ${payload?.error?.message ?? response.statusText}${retryAfter ? ` Retry-After: ${retryAfter}.` : ""}`,
      );
    }
    return response.json();
  }
  const destinations: ImportRepository[] = [];
  let page: string | null = null;
  const seenPages = new Set<string>();
  do {
    const result = validateRepositories(
      await request(
        `/repositories?limit=20&repository=${encodeURIComponent(options.repository)}${page ? `&page=${encodeURIComponent(page)}` : ""}`,
      ),
    );
    destinations.push(
      ...result.data.filter(
        (item) =>
          item.id === options.repository ||
          cloudRepositoryUrlKey(item.url) ===
            cloudRepositoryUrlKey(options.repository),
      ),
    );
    page = result.next;
    if (
      result.has_more !== (page !== null) ||
      (page !== null && seenPages.has(page))
    )
      throw new CodexSecurityError(
        "Cloud returned invalid repository pagination.",
      );
    if (page !== null) seenPages.add(page);
  } while (page !== null);
  if (destinations.length !== 1)
    throw new CodexSecurityError(
      destinations.length
        ? "The repository matches multiple connectors. Select an unambiguous Cloud repository."
        : "The destination repository is not available to this Cloud account. Copy its repository URL or ID from Codex Security Cloud and check that you are signed into the intended account.",
    );
  const destination = destinations[0]!;
  const source = { provider: options.provider, source_key: options.sourceKey };
  const importPrefix = source.provider === "sonar" ? "/v2" : "";
  const sourceReportsPath = importPrefix + sourcePath(destination);
  const state = externalPublicationStateDirectory(environment);
  const checkpointIdentity = [
    // Keep existing production checkpoints readable; other deployments must
    // never share a saved request or receipt with the production default.
    ...(apiBaseUrl === DEFAULT_CLOUD_BASE_URL ? [] : [apiBaseUrl]),
    credentials.account_id,
    destination.id,
    destination.repo_connector_id,
    source,
  ];
  function scopeKey(identity: unknown, wire: boolean) {
    return hash(
      "sha256",
      (wire ? wireJson : canonicalJson)([...checkpointIdentity, identity]),
    );
  }
  function localeKey(rows: ExternalFindings["findings"]) {
    return hash(
      "sha256",
      canonicalJson([...checkpointIdentity, rows], (left, right) =>
        left.localeCompare(right),
      ),
    );
  }
  const freshKey = scopeKey(currentIdentity, true);
  const original = input.original;
  const originalIdentity = original?.identity ?? currentIdentity;
  let hasBoxedScalars = false;
  const originalWire = canonicalJson(originalIdentity, undefined, (value) => {
    if (!isBoxedPrimitive(value)) return false;
    hasBoxedScalars = true;
    return true;
  });
  const changedCapture = original && originalWire !== wireJson(currentIdentity);
  const originalKey =
    changedCapture || hasBoxedScalars
      ? scopeKey(originalIdentity, false)
      : undefined;
  let historicalOnly = false;
  const originalWireKey = changedCapture
    ? scopeKey(originalIdentity, true)
    : undefined;
  if (changedCapture && originalKey && originalWireKey) {
    // A released SDK could stage either spelling. A modern approval for the
    // fresh JSON can occupy the very same historical filename.
    for (const pathKey of new Set([
      originalKey,
      originalWireKey,
      localeKey(original.parsed.findings),
    ])) {
      const bytes = await readOptionalFile(
        join(state, `${pathKey}.pending.json`),
      );
      if (bytes === undefined) continue;
      const record = JSON.parse(bytes) as SavedSubmission | null;
      if (
        (record?.legacyApproval &&
          (record.wireKey ?? pathKey) === originalWireKey) ||
        (record?.wireKey === undefined &&
          record?.inputProjection?.identityFormat !== 2 &&
          (pathKey === originalKey ||
            pathKey === originalWireKey ||
            original.parsed.report === undefined ||
            record?.inputProjection?.inputDigest ===
              hash("sha256", canonicalJson(originalIdentity))))
      ) {
        parsed = legacyParsed = original.parsed;
        currentIdentity = legacyIdentity = original.identity;
        historicalOnly = true;
        break;
      }
    }
  }
  if (input.freshLimitError && !historicalOnly) throw input.freshLimitError;
  const inputDigest = hash("sha256", wireJson(currentIdentity));
  const legacyInputDigest =
    currentIdentity === legacyIdentity
      ? inputDigest
      : hash("sha256", wireJson(legacyIdentity));
  const previousKey = originalKey;
  function readSaved(
    content: SavedSubmission | null | undefined,
  ): SavedSubmission {
    if (
      !content ||
      content.accountId !== credentials.account_id ||
      !Array.isArray(content.requests) ||
      content.requests.length === 0
    )
      throw new Error("Saved import account or requests do not match.");
    content.requests = content.requests.map(validateImportRequest);
    for (const submission of content.requests) {
      if (
        submission.repository.id !== destination.id ||
        submission.repository.repo_connector_id !==
          destination.repo_connector_id ||
        wireJson(submission.source) !== wireJson(source)
      )
        throw new Error("Saved import destination does not match.");
    }
    return content;
  }

  function validateSaved(
    record: SavedSubmission | null | undefined,
    legacy = false,
  ): SavedSubmission {
    const content = readSaved(record);
    const saved = submissionFindings(content.requests);
    const wire = wireJson(saved);
    const expected = legacy ? legacyParsed.findings : parsed.findings;
    const projection = content.inputProjection;
    if (
      projection &&
      (!sameFindingSelection(saved, expected) ||
        projection.inputDigest !== (legacy ? legacyInputDigest : inputDigest) ||
        projection.savedEvidenceDigest !== hash("sha256", wire))
    )
      throw new Error(
        "Saved import evidence does not match the selected input.",
      );
    // Older file readers can have a different, explicitly bound projection.
    // A corrected numeric checkpoint must carry the selected evidence verbatim.
    const exactWire =
      historicalOnly || hasBoxedScalars || content.wireKey !== undefined;
    if (
      (!projection || exactWire) &&
      wire !== wireJson(exactWire ? expected.map(wireFinding) : expected)
    )
      throw new Error(
        "Saved import evidence does not match the selected input.",
      );
    if (
      !legacy &&
      hasBoxedScalars &&
      projection?.identityFormat !== 2 &&
      !verifiableLegacyMetadata(original?.parsed ?? parsed, true)
    )
      throw unmatchedPreviousNumbers();
    return content;
  }

  // The original filename and digests identify the previous selection, but
  // contained {} for every boxed number. Only its actual saved request can
  // prove which numbers were approved.
  function readPreviousNumbers(
    record: SavedSubmission | null,
  ): SavedSubmission | "different-wire" | undefined {
    const content = readSaved(record);
    const projection = content.inputProjection;
    const savedWire = wireJson(submissionFindings(content.requests));
    const wireDigest = hash("sha256", savedWire);
    if (
      projection?.inputDigest !==
      hash("sha256", canonicalJson(originalIdentity))
    )
      throw unmatchedPreviousNumbers();
    if (projection.identityFormat === 2) {
      // A current writer may own the old filename for an ordinary object.
      if (projection.savedEvidenceDigest === wireDigest) return undefined;
      throw unmatchedPreviousNumbers();
    }
    const selected = (original?.parsed ?? parsed).findings.map(wireFinding);
    if (
      projection.savedEvidenceDigest !== hash("sha256", canonicalJson(selected))
    )
      throw unmatchedPreviousNumbers();
    if (savedWire !== wireJson(selected)) {
      // A genuinely empty object at this key is a separate ordinary selection.
      if (wireDigest === projection.savedEvidenceDigest) return undefined;
      return "different-wire";
    }
    if (
      (changedCapture && !historicalOnly) ||
      !verifiableLegacyMetadata(original?.parsed ?? parsed, false)
    )
      throw unmatchedPreviousNumbers();
    content.legacyApproval = true;
    content.inputProjection = {
      identityFormat: 2,
      inputDigest,
      savedEvidenceDigest: wireDigest,
    };
    return content;
  }
  function unmatchedPreviousNumbers() {
    return new CodexSecurityError(
      "The older saved import cannot be matched to the selected input. Its checkpoint was preserved without uploading.",
    );
  }
  const key = historicalOnly ? scopeKey(currentIdentity, true) : freshKey;
  const canonicalPath = join(state, `${key}.pending.json`);
  const lookupPath = join(state, `${key}.lookup.json`);
  // A lookup only suggests a regular file to validate. A missing or stale hint
  // leaves the same on-disk discovery available as before.
  async function readOptionalRegularFile(path: string) {
    try {
      if ((await lstat(path)).isFile()) return await readFile(path, "utf8");
    } catch {
      // Optional discovery must not veto an independently verified checkpoint.
    }
  }
  async function lookupFileKey() {
    const serialized = await readOptionalRegularFile(lookupPath);
    return serialized?.trim().match(/^"([a-f0-9]{64})"$/u)?.[1];
  }

  const historicalKey = localeKey(legacyParsed.findings);
  const legacyIdentityKey = hash(
    "sha256",
    wireJson([...checkpointIdentity, legacyIdentity]),
  );
  const legacyKeys = new Set([legacyIdentityKey, historicalKey]);
  function underLocks<T>(keys: string[], operation: () => Promise<T>) {
    return withImportLocks(state, keys, dependencies.signal, operation);
  }
  let recovered: SavedSubmission | undefined;
  for (const legacyKey of legacyKeys) {
    if (legacyKey === key || legacyKey === previousKey) continue;
    const legacyPath = join(state, `${legacyKey}.pending.json`);
    const captured = await readOptionalFile(legacyPath);
    if (captured !== undefined) {
      // Preserve requests staged by the earlier locale-based filename format.
      // Hold both publication locks while moving the original checkpoint.
      await underLocks([key, legacyKey], async () => {
        const current = await readOptionalFile(canonicalPath);
        const serialized = await readOptionalFile(legacyPath);
        let prior: SavedSubmission | undefined | null;
        if (serialized !== undefined) {
          try {
            prior = JSON.parse(serialized) as SavedSubmission | null;
          } catch (error) {
            if (current === undefined || !(error instanceof SyntaxError))
              throw error;
          }
        }
        if (prior?.wireKey !== undefined) return;
        if (current !== undefined) {
          recovered = validateSaved(JSON.parse(current));
          if (prior && sameSubmission(prior, recovered)) await rm(legacyPath);
          return;
        }
        // A report-free approval at the locale-era filename can be a separate input.
        if (
          legacyKey === historicalKey &&
          legacyKey !== legacyIdentityKey &&
          prior?.inputProjection &&
          prior.inputProjection.inputDigest !== legacyInputDigest
        ) {
          const projection = prior.inputProjection;
          const rows = legacyParsed.findings;
          if (
            projection.identityFormat === 2 ||
            (projection.inputDigest === hash("sha256", wireJson(rows)) &&
              projection.savedEvidenceDigest ===
                hash("sha256", wireJson(submissionFindings(prior.requests))))
          )
            return;
          // The released SDK hashed report-free rows as an array and boxed scores as {}.
          if (
            hasBoxedScalars &&
            legacyParsed.report !== undefined &&
            legacyKey === scopeKey(original?.parsed.findings ?? rows, false) &&
            projection.inputDigest ===
              hash(
                "sha256",
                canonicalJson(original?.parsed.findings ?? rows),
              ) &&
            projection.savedEvidenceDigest ===
              hash(
                "sha256",
                canonicalJson(
                  (original?.parsed.findings ?? rows).map(wireFinding),
                ),
              ) &&
            sameFindingSelection(
              submissionFindings(readSaved(prior).requests),
              rows,
            )
          )
            return;
        }
        const content = validateSaved(
          serialized === undefined ? JSON.parse(captured) : prior,
          true,
        );
        if (!sameFindingSelection(legacyParsed.findings, parsed.findings))
          throw new CodexSecurityError(
            "The saved import selects different findings from this input. Resume the original selection before publishing this selection.",
          );
        if (
          content.requests.some(
            (submission) =>
              submission.repository.reset_marker !== destination.reset_marker,
          )
        ) {
          if (serialized !== undefined) await rm(legacyPath);
          throw new CloudImportError(
            409,
            "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.",
          );
        }
        const savedEvidenceDigest =
          content.inputProjection?.savedEvidenceDigest ??
          hash("sha256", wireJson(legacyParsed.findings));
        const rebindProjection =
          content.inputProjection !== undefined ||
          savedEvidenceDigest !== inputDigest;
        if (rebindProjection) {
          if (content.inputProjection?.identityFormat !== 2)
            content.legacyApproval = true;
          content.inputProjection = {
            ...content.inputProjection,
            identityFormat: 2,
            inputDigest,
            savedEvidenceDigest,
          };
        }
        recovered = content;
        if (serialized === undefined) return;
        if (!rebindProjection) {
          await rename(legacyPath, canonicalPath);
        } else {
          // Bind the new input projection to the original immutable evidence,
          // so later inventory reordering still resumes these exact requests.
          await writeAtomicJson(canonicalPath, content);
          await rm(legacyPath);
        }
      });
    }
  }

  interface Checkpoint {
    fileKey: string;
    content: SavedSubmission;
    historical: boolean;
    checkedCanonical?: true;
  }
  // Some getter-backed batches cannot reproduce a released filename. Their IDs
  // can stop a conflicting upload, but never authorize replay of a saved request.
  const potentialIds =
    input.potentialIds ??
    (changedCapture
      ? original?.parsed.findings.map((row) => row.source_finding_id)
      : undefined);
  const unprovenPrefixes = new Set(input.unprovenIdPrefixes);
  const prefixCandidates = unprovenPrefixes.size
    ? new Map(parsed.findings.map((row) => [row.source_finding_id, row]))
    : undefined;
  const cannotCaptureOriginal =
    !input.original && !!(potentialIds?.length || unprovenPrefixes.size);
  function potentialOriginal(record: SavedSubmission, fileKey: string) {
    const projection = record.inputProjection;
    if (
      !projection ||
      !/^[a-f0-9]{64}$/u.test(projection.inputDigest) ||
      !/^[a-f0-9]{64}$/u.test(projection.savedEvidenceDigest) ||
      (projection.identityFormat === 2 &&
        !(cannotCaptureOriginal && record.wireKey)) ||
      record.accountId !== credentials.account_id
    )
      return false;
    try {
      const rows = submissionFindings(record.requests);
      if (
        !record.wireKey &&
        projection.inputDigest === projection.savedEvidenceDigest &&
        projection.inputDigest === hash("sha256", wireJson(rows))
      ) {
        // These rows reconstruct the complete old report-free identity. A
        // different deployment's filename cannot belong to this selection.
        if (fileKey !== scopeKey(rows, false) && fileKey !== localeKey(rows))
          return false;
        if (original && originalWire !== wireJson(rows)) return false;
      }
      if (
        prefixCandidates &&
        rows.length &&
        rows.every((row) => {
          const id = row.source_finding_id;
          if (unprovenPrefixes.has(id.replace(/\/[a-f0-9]{64}$/u, "/")))
            return true;
          const current = prefixCandidates.get(id);
          return current && wireJson(row) === wireJson(wireFinding(current));
        })
      ) {
        // An uncertain alert might have changed refs or been excluded entirely.
        // Its identity can stop a duplicate batch but never authorize replay.
        readSaved(record);
        return true;
      }
      const candidates = original?.parsed.findings ?? parsed.findings;
      const ids =
        potentialIds ?? parsed.findings.map((row) => row.source_finding_id);
      if (
        !ids.length ||
        rows.length !== ids.length ||
        !rows.every((row, i) => row.source_finding_id === ids[i])
      )
        return false;
      if (
        projection.inputDigest === projection.savedEvidenceDigest &&
        parsed.report !== undefined
      )
        return false;
      if (
        potentialIds === undefined &&
        (hasBoxedScalars ||
          projection.savedEvidenceDigest === hash("sha256", wireJson(rows)))
      )
        return false;
      readSaved(record);
      return (
        !sameFindingSelection(rows, candidates) ||
        (input.unprovenIdPrefixes !== undefined && !original) ||
        rows.every((row, i) => {
          const { source_data: savedData, ...savedFields } = row.evidence;
          const { source_data: selectedData, ...selectedFields } =
            candidates[i]!.evidence;
          if (wireJson(savedFields) !== wireJson(selectedFields)) return false;
          // Once the original SDK discarded boxed positions, a plain JSON export
          // alone cannot attribute a new numeric spelling to that saved request.
          return (
            (potentialIds !== undefined && !original) ||
            sameNonNumericJson(savedData, selectedData)
          );
        })
      );
    } catch {
      return false;
    }
  }
  async function selectedCheckpoint(knownFileKey?: string, preparing = false) {
    const directory = await validatePreparedOutputDir(
      state,
      undefined,
      true,
    ).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    });
    if (!directory) return undefined;
    const known = new Set(
      [key, previousKey, knownFileKey].filter((value) => value !== undefined),
    );
    let unidentified = false;
    let unprovenOriginal = false;
    let incomplete = false;
    let differentOldWire = false;
    let stagingPathOccupied = false;
    async function readCandidate(
      fileKey: string,
      selected?: Checkpoint,
      contents?: string,
    ): Promise<Checkpoint | undefined> {
      const path = join(state, `${fileKey}.pending.json`);
      const serialized =
        contents ??
        (selected?.fileKey === key && !known.has(fileKey)
          ? await readOptionalRegularFile(path)
          : await readOptionalFile(path));
      if (serialized === undefined) {
        if (!known.has(fileKey)) incomplete = true;
        return selected;
      }
      if (fileKey === (previousKey ?? key)) stagingPathOccupied = true;
      let record: SavedSubmission | null;
      try {
        record = JSON.parse(serialized) as SavedSubmission | null;
      } catch (error) {
        if (known.has(fileKey)) throw error;
        incomplete = true;
        return selected;
      }
      if (record?.wireKey !== undefined && record.wireKey !== key) {
        if (cannotCaptureOriginal && potentialOriginal(record, fileKey))
          unprovenOriginal = true;
        return selected;
      }
      const historical =
        fileKey !== key &&
        record?.wireKey === undefined &&
        fileKey === previousKey;
      if (fileKey !== key && record?.wireKey !== key && !historical) {
        if (record && potentialOriginal(record, fileKey))
          unprovenOriginal = true;
        // Some early locale filenames carry no deployment identity. Never guess their target.
        if (record && !record.inputProjection && !legacyKeys.has(fileKey)) {
          try {
            validateSaved(record, true);
            unidentified = true;
          } catch {
            /* Unrelated input. */
          }
        }
        return selected;
      }
      const content = historical
        ? readPreviousNumbers(record)
        : validateSaved(record);
      if (content === "different-wire") {
        // Another spelling may already have a verified checkpoint for this wire value.
        differentOldWire = true;
        return selected;
      }
      if (!content) return selected;
      if (selected) {
        const conflict = new CodexSecurityError(
          "Two saved imports match this input. Their original requests and receipts were preserved without uploading.",
        );
        if (!preparing) throw conflict;
        // The two unlocked reads may have straddled completion of the first request.
        return await underLocks([key, selected.fileKey, fileKey], async () => {
          const first = await readCandidate(selected.fileKey);
          if (first && (await readCandidate(fileKey))) throw conflict;
          if (first && sameSubmission(first.content, selected.content))
            return first;
          if (
            await readCompletedPublication(
              selected.content.requests,
              selected.fileKey,
            )
          )
            return selected;
          throw changedWhilePreparing();
        });
      }
      return { fileKey, content, historical };
    }
    let selected: Checkpoint | undefined;
    for (const fileKey of known)
      selected = await readCandidate(fileKey, selected);
    // A known file that disappeared can be checked against its completed receipt.
    if (!selected && knownFileKey !== undefined) return undefined;
    const hint = await lookupFileKey();
    if (hint && !known.has(hint)) {
      const contents = await readOptionalRegularFile(
        join(state, `${hint}.pending.json`),
      );
      if (contents !== undefined) {
        selected = await readCandidate(hint, selected, contents);
        known.add(hint);
      }
    }
    // A released publisher could stage the canonical request while another SDK
    // tagged its old filename but had not yet written the optional lookup.
    if (
      selected &&
      !selected.historical &&
      (selected.fileKey !== key ||
        selected.content.canonicalChecked ||
        selected.content.inputProjection?.identityFormat === 2)
    )
      return selected;
    const entries = await readdir(state, { withFileTypes: true }).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return [];
        throw error;
      },
    );
    for (const entry of entries) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.pending\.json$/u.test(entry.name))
        continue;
      const fileKey = entry.name.slice(0, -".pending.json".length);
      if (!known.has(fileKey))
        selected = await readCandidate(fileKey, selected);
    }
    if (!selected && (differentOldWire || unprovenOriginal))
      throw unmatchedPreviousNumbers();
    if (!selected && stagingPathOccupied) throw occupiedCheckpoint();
    if (!selected && unidentified)
      throw new CodexSecurityError(
        "An older pending import matches this input, but its checkpoint identity could not be established. Resume it using the original deployment and locale before publishing this selection. The saved request was preserved without uploading.",
      );
    if (selected?.fileKey === key && !preparing && !incomplete)
      selected.checkedCanonical = true;
    return selected;
  }
  async function readCompletedPublication(
    requests: FindingImportRequest[],
    observedKey: string,
  ) {
    for (const resultKey of new Set([key, observedKey])) {
      const serialized = await readOptionalFile(
        join(state, `${resultKey}.result.json`),
      );
      if (serialized === undefined) continue;
      const completed = JSON.parse(
        serialized,
      ) as ExternalPublicationResult | null;
      if (
        (completed?.status === "complete" || completed?.status === "partial") &&
        Array.isArray(completed.receipts) &&
        completed.receipts.length === requests.length &&
        completed.receipts.every(
          (receipt, i) => receipt?.id === requests[i]!.request_id,
        )
      )
        return {
          receipts: completed.receipts.map((receipt, i) =>
            validatePublicationReceipt(receipt, requests[i]!),
          ),
          verified: completed.verified,
        };
    }
  }
  function changedWhilePreparing() {
    return new CodexSecurityError(
      "The saved publication changed while preparing this input. Review it again.",
    );
  }
  function occupiedCheckpoint() {
    return new CodexSecurityError(
      "Finish the other pending import at this checkpoint first, then review this input again.",
    );
  }
  let selected = await selectedCheckpoint(recovered ? key : undefined, true);
  const fileKey = selected?.fileKey ?? (recovered ? key : (previousKey ?? key));
  const pendingPath = join(state, `${fileKey}.pending.json`);
  async function rememberFile() {
    if (fileKey !== key && (await lookupFileKey()) !== fileKey)
      await writeAtomicJson(lookupPath, fileKey).catch(() => undefined);
  }
  async function removePending() {
    await rm(pendingPath, { force: true });
    if (fileKey !== key && (await lookupFileKey()) === fileKey)
      await rm(lookupPath, { force: true }).catch(() => undefined);
  }

  const lockKeys = [
    ...new Set([
      key,
      fileKey,
      ...(previousKey === undefined ? [] : [previousKey]),
    ]),
  ];
  if (selected?.historical) {
    const observed = selected;
    selected = await underLocks(lockKeys, async () => {
      const current = await selectedCheckpoint(fileKey);
      if (
        !current ||
        current.fileKey !== fileKey ||
        !sameSubmission(current.content, observed.content)
      ) {
        if (
          await readCompletedPublication(
            observed.content.requests,
            observed.fileKey,
          )
        )
          return observed;
        throw changedWhilePreparing();
      }
      if (current.historical) {
        current.content.wireKey = key;
        await writeAtomicJson(pendingPath, current.content);
        await rememberFile();
      }
      return current;
    });
  }
  const saved = selected?.content ?? recovered;
  if (historicalOnly && !saved) throw unmatchedPreviousNumbers();
  if (!parsed.findings.length) noFindings();
  if (saved) {
    const content = saved;
    for (const submission of content.requests) {
      if (submission.repository.reset_marker !== destination.reset_marker) {
        // The old request is never sent after reset. A subsequent explicit
        // invocation prepares a fresh submission and asks for approval again.
        await underLocks(lockKeys, async () => {
          const current = await readOptionalFile(pendingPath);
          if (
            current !== undefined &&
            sameSubmission(JSON.parse(current) as SavedSubmission, content)
          )
            await removePending();
        });
        throw new CloudImportError(
          409,
          "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.",
        );
      }
    }
  }
  if (saved?.inspectorProjectMapRequired && !inspectorProjectMap)
    throw new CodexSecurityError(
      "Supply the verified Inspector project binding again to resume.",
    );

  function checkRepositories(
    findings: ExternalFindings["findings"],
    report?: ExternalFindings["report"],
  ) {
    function requireDestination(id: string, url: string | null | undefined) {
      if (
        url &&
        cloudRepositoryUrlKey(url) !== cloudRepositoryUrlKey(destination.url)
      )
        throw new CodexSecurityError(
          `Finding ${JSON.stringify(id)} belongs to ${JSON.stringify(url)}, which does not match the selected Cloud repository ${JSON.stringify(destination.url)}. Verify the source repository mapping before publishing.`,
        );
    }
    // Historical checkpoints already fixed the provider and request bytes.
    // Recheck any projected source against the destination discovered for this retry.
    const replay = saved && options.provider !== "blackduck";
    if (!saved || options.provider === "sonar") {
      for (const url of sonarRepositoryUrls(
        options.provider,
        findings,
        report,
        "cloud",
      ))
        requireDestination("Sonar source", url);
    }
    const repositories = replay
      ? undefined
      : blackDuckReportRepositories(options.provider, findings, "cloud");
    if (!saved || options.provider === "veracode") {
      for (const [id, source] of veracodeReportRepositories(
        options.provider,
        findings,
        "cloud",
      ))
        requireDestination(id, source.url);
    }
    if (
      !replay ||
      options.provider === "inspector" ||
      options.provider === "veracode"
    ) {
      const binding = inspectorReportRepository(
        options.provider,
        findings,
        "cloud",
        inspectorProjectMap,
      );
      if (binding) requireDestination(binding.findingId, binding.url);
    }
    for (const finding of findings) {
      const { source_finding_id: id, evidence } = finding;
      const projected = repositories
        ? repositories.get(id)?.url
        : projectedBlackDuckRepositoryUrl(finding, "cloud");
      if (
        replay &&
        !projected &&
        options.provider !== "inspector" &&
        options.provider !== "veracode" &&
        options.provider !== "sonar"
      )
        continue;
      const urls = [
        projected,
        evidence.details?.repository?.url,
        options.provider === "wiz"
          ? projected
            ? wizFindingRepository(evidence, "cloud")?.url
            : wizCsvRepositoryUrl(evidence)
          : undefined,
        ...(options.provider === "snyk"
          ? snykRepositoryUrls(evidence.source_data, {
              cloudRepositoryUrl: destination.url,
            })
          : []),
        ...(options.provider === "endor"
          ? endorRepositoryUrls(evidence.source_data)
          : []),
        options.provider === "github"
          ? dependabotRepository(finding)
          : undefined,
      ];
      for (const url of urls) requireDestination(id, url);
    }
  }
  checkRepositories(parsed.findings, parsed.report);
  // A retry sends its saved projection, which may differ from today's reader.
  if (saved) {
    // A common Sonar ref can supply missing row refs. Only use the report
    // associated with the input digest in the saved checkpoint.
    const report =
      saved.inputProjection?.inputDigest === inputDigest
        ? parsed.report
        : undefined;
    checkRepositories(submissionFindings(saved.requests), report);
  }

  let requests = saved?.requests;
  if (!requests) {
    let preparedCount = 0;
    progress({
      phase: "preparing",
      completed: 0,
      total: parsed.findings.length,
    });
    const previousReports = await readInBatches(
      parsed.findings,
      async (finding): Promise<SourceReportSummary | undefined> => {
        const query = new URLSearchParams({
          provider: source.provider,
          source_key: source.source_key,
          source_finding_id: finding.source_finding_id,
          limit: "2",
        });
        const summaries = validateSourceReports(
          await request(`${sourceReportsPath}?${query}`),
        );
        if (summaries.has_more || summaries.data.length > 1)
          throw new CodexSecurityError(
            "Cloud returned more than one report for a source identity.",
          );
        const previous = summaries.data[0];
        if (
          previous &&
          (previous.source_finding_id !== finding.source_finding_id ||
            previous.source.provider !== source.provider ||
            previous.source.source_key !== source.source_key ||
            previous.repo_id !== destination.id ||
            previous.repo_connector_id !== destination.repo_connector_id)
        )
          throw new CodexSecurityError(
            "Cloud returned a different source identity.",
          );
        progress({
          phase: "preparing",
          completed: ++preparedCount,
          total: parsed.findings.length,
        });
        return previous;
      },
    );
    requests = [];
    let current: FindingImportRequest | undefined;
    let currentBytes = 0;
    for (const [index, finding] of parsed.findings.entries()) {
      const previous = previousReports[index];
      const environmentId =
        previous?.environment_id ?? destination.import_environment_id;
      if (environmentId == null)
        throw new CodexSecurityError(
          "Configure an authorized Cloud environment for this repository before importing findings.",
        );
      const item = {
        client_id: `item-${index + 1}`,
        source_finding_id: finding.source_finding_id,
        expected_version: previous?.version ?? 0,
        evidence: finding.evidence,
      };
      const itemBytes = Buffer.byteLength(JSON.stringify(item));
      if (
        current &&
        (current.repository.environment_id !== environmentId ||
          current.items.length === 100 ||
          currentBytes + 1 + itemBytes > MAX_REQUEST_BYTES)
      ) {
        requests.push(validateImportRequest(current));
        current = undefined;
      }
      if (!current) {
        current = {
          request_id: randomUUID(),
          repository: {
            id: destination.id,
            repo_connector_id: destination.repo_connector_id,
            environment_id: environmentId,
            reset_marker: destination.reset_marker,
          },
          source,
          items: [],
        };
        currentBytes = Buffer.byteLength(JSON.stringify(current));
      } else {
        currentBytes++;
      }
      current.items.push(item);
      currentBytes += itemBytes;
    }
    if (current) requests.push(validateImportRequest(current));
  }
  const submission: SavedSubmission = {
    accountId: credentials.account_id,
    requests,
    receipts: saved?.receipts,
    legacyApproval: saved?.legacyApproval,
    wireKey: saved?.wireKey ?? (fileKey === key ? undefined : key),
    inputProjection: saved?.inputProjection ?? {
      identityFormat: saved ? undefined : 2,
      inputDigest,
      savedEvidenceDigest: hash(
        "sha256",
        wireJson(submissionFindings(requests)),
      ),
    },
  };
  if (inspectorProjectMap) submission.inspectorProjectMapRequired = true;
  const preview: ExternalPublicationPreview = {
    ...parsed,
    findings: submissionFindings(requests),
    cloudApiUrl,
    cloudUrl: cloudFindingsUrl(environment, destination.id),
    accountId: credentials.account_id,
    destination,
    source,
    resumed: saved !== undefined,
    requests,
  };
  return {
    preview: cloneImportPreview(preview),
    async publish() {
      progress({ phase: "waiting", completed: 0 });
      const result = (
        acknowledged: FindingImportReceipt[],
        verified: number,
      ): ExternalPublicationResult => {
        const counts = { created: 0, updated: 0, unchanged: 0, error: 0 };
        const failures: ExternalPublicationResult["failures"] = [];
        for (const [index, receipt] of acknowledged.entries()) {
          for (const outcome of Object.keys(counts) as (keyof typeof counts)[])
            counts[outcome] += receipt.counts[outcome] ?? 0;
          const ids = new Map(
            requests[index]!.items.map((item) => [
              item.client_id,
              item.source_finding_id,
            ]),
          );
          for (const item of receipt.results)
            if (item.error)
              failures.push({
                source_finding_id: ids.get(item.client_id)!,
                ...item.error,
              });
        }
        return {
          cloudApiUrl,
          cloudUrl: preview.cloudUrl,
          status:
            parsed.excluded.length || counts.error ? "partial" : "complete",
          read: parsed.read,
          ...(parsed.report === undefined
            ? {}
            : snapshotNormalizedFindings({ report: parsed.report })),
          ready: parsed.findings.length,
          excluded: parsed.excluded,
          receipts: acknowledged,
          counts,
          failures,
          unacknowledged:
            parsed.findings.length -
            Object.values(counts).reduce((sum, count) => sum + count, 0),
          verified,
        };
      };
      function interruptedPreview(
        message: string,
        cause?: unknown,
        savedSubmission?: string,
      ) {
        // The expected file is gone or another publisher owns the lock. Use only
        // the acknowledgements this caller saw when it prepared the request.
        const known = submission.receipts ?? [];
        if (known.length > submission.requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged = known.map((receipt, index) =>
          validatePublicationReceipt(receipt, submission.requests[index]!),
        );
        return new ExternalPublicationError(
          message,
          {
            ...result(acknowledged, 0),
            status: "interrupted",
            error: message,
            ...(savedSubmission === undefined ? {} : { savedSubmission }),
          },
          cause,
        );
      }
      let acquired = false;
      return await underLocks(lockKeys, async () => {
        acquired = true;
        // Re-read under the lock to keep checkpoints from another publisher.
        const selected = await selectedCheckpoint(saved ? fileKey : undefined);
        const pending = selected?.content;
        const current = pending ?? submission;
        const adoptProjectMap =
          submission.inspectorProjectMapRequired &&
          current.inspectorProjectMapRequired === undefined;
        if (adoptProjectMap) current.inspectorProjectMapRequired = true;
        if (
          !selected ||
          selected.fileKey !== fileKey ||
          selected.historical ||
          !sameSubmission(current, submission)
        ) {
          const message = selected
            ? "Another publication prepared this input. Run the command again to review and resume that saved request."
            : "The saved publication changed after preview. Review its result before publishing again.";
          if (saved) {
            const completed = await readCompletedPublication(requests, fileKey);
            if (completed)
              return result(completed.receipts, completed.verified);
            throw interruptedPreview(message);
          }
          if (selected) throw new CodexSecurityError(message);
          if ((await readOptionalFile(pendingPath)) !== undefined)
            throw occupiedCheckpoint();
        }
        const receipts = (current.receipts ?? []).map(validateImportReceipt);
        if (receipts.length > requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged: FindingImportReceipt[] = [];
        let verified = 0;
        let persisted = pending !== undefined;
        try {
          if (selected?.checkedCanonical) current.canonicalChecked = true;
          if (pending === undefined || adoptProjectMap) {
            await writeAtomicJson(pendingPath, current);
            persisted = true;
          } else if (selected?.checkedCanonical) {
            // The existing approval and receipts are usable if caching the scan fails.
            await writeAtomicJson(pendingPath, current).catch(() => undefined);
          }
          await rememberFile();
          progress({
            phase: "uploading",
            completed: 0,
            total: parsed.findings.length,
          });
          let acknowledgedCount = 0;
          for (const [batchIndex, batch] of requests.entries()) {
            const receipt = validatePublicationReceipt(
              receipts[batchIndex] ??
                (await request(`${importPrefix}/finding_imports`, batch)),
              batch,
            );
            acknowledged.push(receipt);
            acknowledgedCount += receipt.item_count;
            progress({
              phase: "uploading",
              completed: acknowledgedCount,
              total: parsed.findings.length,
            });
            if (batchIndex === receipts.length) {
              receipts.push(receipt);
              // Acknowledged batches must not consume another POST quota on retry.
              // Readback can still resume after this checkpoint without replaying writes.
              await writeAtomicJson(pendingPath, {
                ...submission,
                canonicalChecked: current.canonicalChecked,
                receipts,
              });
            }
          }
          // Verify readable source records without mistaking a newer concurrent
          // observation for failure of the original, immutable import receipt.
          const readbacks = receipts.flatMap((receipt, batchIndex) => {
            const batch = requests[batchIndex]!;
            const batchItems = new Map(
              batch.items.map((item) => [item.client_id, item]),
            );
            return receipt.results
              .filter((item) => item.outcome !== "error")
              .map((item) => ({
                item,
                expected: batchItems.get(item.client_id)!,
                batch,
              }));
          });
          progress({
            phase: "verifying",
            completed: 0,
            total: readbacks.length,
          });
          await readInBatches(readbacks, async ({ item, expected, batch }) => {
            const report = validateSourceReport(
              await request(
                `${sourceReportsPath}/${encodeURIComponent(item.source_report_id!)}`,
              ),
            );
            if (
              report.id !== item.source_report_id ||
              report.canonical_finding_id !== item.canonical_finding_id ||
              report.version < item.version! ||
              (report.version === item.version &&
                (report.observation_id !== item.observation_id ||
                  wireJson(report.evidence) !== wireJson(expected.evidence))) ||
              report.source_finding_id !== expected.source_finding_id ||
              report.repo_id !== destination.id ||
              report.repo_connector_id !== destination.repo_connector_id ||
              report.environment_id !== batch.repository.environment_id ||
              wireJson(report.source) !== wireJson(source)
            )
              throw new CodexSecurityError(
                "Cloud readback did not match the saved finding identity.",
              );
            progress({
              phase: "verifying",
              completed: ++verified,
              total: readbacks.length,
            });
          });
          const completed = result(acknowledged, verified);
          await writeAtomicJson(join(state, `${key}.result.json`), {
            ...completed,
            report: reportForJson(completed.report),
          });
          await removePending();
          return completed;
        } catch (error) {
          if (error instanceof CloudImportError && error.status === 409) {
            await removePending();
            persisted = false;
          }
          const message = `${error instanceof Error ? error.message : String(error)} ${error instanceof CloudImportError && error.status === 409 ? "The old submission was retired. Rediscover and approve a fresh publication." : persisted ? `Repeat the same command to resume the saved request. Saved submission: ${pendingPath}` : "No resumable request was saved. Correct the error and review the input before retrying."}`;
          throw new ExternalPublicationError(
            message,
            {
              ...result(acknowledged, verified),
              status: "interrupted",
              error: message,
              ...(persisted ? { savedSubmission: pendingPath } : {}),
            },
            error,
          );
        }
      }).catch((error: unknown) => {
        if (acquired || !dependencies.signal?.aborted) throw error;
        const message = saved
          ? `Publication canceled while waiting. Repeat the same command to resume the saved request. Saved submission: ${pendingPath}`
          : "Publication canceled while waiting. No resumable request was saved by this invocation.";
        throw interruptedPreview(
          message,
          error,
          saved ? pendingPath : undefined,
        );
      });
    },
  };
}
