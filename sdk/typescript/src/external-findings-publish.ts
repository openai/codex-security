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
import {
  privateImportClient,
  privateReport,
  readPrivateCheckpoint,
  type PrivateImportJob,
} from "./private-finding-import.js";
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
import { canonicalJson } from "./record.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { wizFindingRepository } from "./wiz-findings.js";
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
  type ExternalFindings,
  type ExternalPublicationInput,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  validateImportRequest,
  validateExternalEvidence,
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
  /** Private jobs expose aggregate outcomes before assessment or publication. */
  privateJob?: PrivateImportJob;
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
  inputProjection?: { inputDigest: string; savedEvidenceDigest: string };
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
  privateImport?: { contextVersion: string; sha256: string; bytes: number };
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

function sameSubmission(
  left: SavedSubmission,
  right: SavedSubmission,
): boolean {
  return (
    left.accountId === right.accountId &&
    left.inspectorProjectMapRequired === right.inspectorProjectMapRequired &&
    canonicalJson(left.requests) === canonicalJson(right.requests)
  );
}

function submissionFindings(
  requests: readonly FindingImportRequest[],
): ExternalFindings["findings"] {
  return requests.flatMap((batch) =>
    batch.items.map(({ source_finding_id, evidence }) => ({
      source_finding_id,
      evidence,
    })),
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
    entry instanceof Error ? { message: entry.message } : entry,
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
    canonicalJson(receipt.repository) !== canonicalJson(batch.repository) ||
    canonicalJson(receipt.source) !== canonicalJson(batch.source) ||
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
  if (canonicalJson(receipt.counts) !== canonicalJson(actual))
    throw new CodexSecurityError(
      "Cloud returned inconsistent publication counts.",
    );
  return receipt;
}

async function withImportLock<T>(
  state: string,
  key: string,
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  if (process.platform === "win32")
    await createWindowsOutputDirectory(state, true);
  else await mkdir(state, { recursive: true, mode: 0o700 });
  await validatePreparedOutputDir(state, undefined, true);
  const path = join(state, `${key}.lock.sqlite`);
  const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (metadata && !metadata.isFile())
    throw new CodexSecurityError("The publication lock is not a regular file.");
  const require = createRequire(import.meta.url);
  const Database = (
    process.versions["bun"]
      ? require("bun:sqlite").Database
      : require("node:sqlite").DatabaseSync
  ) as new (path: string) => { exec(sql: string): void; close(): void };
  const guard = new Database(path);
  try {
    if (process.platform !== "win32") chmodSync(path, 0o600);
    guard.exec("PRAGMA busy_timeout = 0");
    for (;;) {
      signal?.throwIfAborted();
      try {
        // Keep this inode across invocations. SQLite releases the transaction
        // on process exit, so a paused publisher cannot lose its lock to a lease.
        guard.exec("BEGIN EXCLUSIVE");
        break;
      } catch (error) {
        const sqliteError = error as { code?: string; errcode?: number };
        if (sqliteError.errcode !== 5 && sqliteError.code !== "SQLITE_BUSY")
          throw error;
        await delay(50, undefined, { signal });
      }
    }
    return await operation();
  } finally {
    guard.close();
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

function normalizedPublicationInput(
  input: ExternalFindings,
): ExternalPublicationInput {
  // Validation adds Cloud defaults; leave the caller's objects unchanged.
  const { report, ...parsed } = input;
  const current: ExternalFindings = structuredClone(parsed);
  if (report !== undefined) {
    current.report = structuredClone(report);
    validateExternalReport(current.report);
  }
  // structuredClone preserves aliases. Detach every raw record before adding
  // typed defaults, including aliases shared with another finding's evidence.
  for (const finding of current.findings)
    if (finding.evidence.source_data !== undefined)
      finding.evidence.source_data = structuredClone(
        finding.evidence.source_data,
      );
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
    finding.evidence = validateExternalEvidence(finding.evidence);
  }
  const identity =
    current.report === undefined
      ? current.findings
      : { findings: current.findings, report: reportForJson(current.report) };
  return {
    current,
    legacy: current,
    currentIdentity: identity,
    legacyIdentity: identity,
  };
}

async function preparePublicationInput(
  input: ExternalPublicationInput,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies,
): Promise<PreparedExternalPublication> {
  const { inspectorProjectMap } = options;
  const progress = (event: ExternalPublicationProgress): void => {
    try {
      dependencies.onProgress?.(event);
    } catch {
      // Optional progress must not interrupt preparation or publication.
    }
  };
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
  const {
    current: parsed,
    legacy: legacyParsed,
    currentIdentity,
    legacyIdentity,
  } = input;
  if (parsed.findings.length === 0) {
    const diagnostics = reportForJson(parsed.report)?.["errors"];
    throw new CodexSecurityError(
      `No supported findings are ready to publish. ${parsed.excluded.map((item) => `Item ${item.position}: ${item.reason}`).join(" ")}${Array.isArray(diagnostics) && diagnostics.length ? ` Scanner diagnostics: ${JSON.stringify(diagnostics)}` : ""}`,
    );
  }
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
  let privateProviders: Set<string> | undefined;
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
    if (endpoint.startsWith("/repositories?")) {
      const advertised = response.headers.get(
        "Codex-Security-Private-Import-Providers",
      );
      if (advertised !== null)
        privateProviders = new Set(
          advertised.split(",").map((provider) => provider.trim()),
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
  const inputDigest = hash("sha256", canonicalJson(currentIdentity));
  const legacyInputDigest = hash("sha256", canonicalJson(legacyIdentity));
  function validateSaved(serialized: string, legacy = false): SavedSubmission {
    const content = JSON.parse(serialized) as SavedSubmission;
    if (
      content.accountId !== credentials.account_id ||
      !Array.isArray(content.requests) ||
      content.requests.length === 0
    )
      throw new Error("Saved import account or requests do not match.");
    content.requests = content.requests.map(validateImportRequest);
    const savedFindings = submissionFindings(content.requests);
    const savedEvidence = canonicalJson(savedFindings);
    const expected = legacy ? legacyParsed.findings : parsed.findings;
    const matches =
      content.inputProjection !== undefined
        ? sameFindingSelection(savedFindings, expected) &&
          content.inputProjection?.inputDigest ===
            (legacy ? legacyInputDigest : inputDigest) &&
          content.inputProjection?.savedEvidenceDigest ===
            hash("sha256", savedEvidence)
        : savedEvidence === canonicalJson(expected);
    if (!matches)
      throw new Error(
        "Saved import evidence does not match the selected input.",
      );
    for (const submission of content.requests) {
      if (
        submission.repository.id !== destination.id ||
        submission.repository.repo_connector_id !==
          destination.repo_connector_id ||
        canonicalJson(submission.source) !== canonicalJson(source)
      )
        throw new Error("Saved import destination does not match.");
    }
    return content;
  }
  const key = hash(
    "sha256",
    canonicalJson([...checkpointIdentity, currentIdentity]),
  );
  const pendingPath = join(state, `${key}.pending.json`);
  const historicalKey = hash(
    "sha256",
    canonicalJson(
      [...checkpointIdentity, legacyParsed.findings],
      (left, right) => left.localeCompare(right),
    ),
  );
  const legacyKeys = new Set([
    hash("sha256", canonicalJson([...checkpointIdentity, legacyIdentity])),
    historicalKey,
  ]);
  async function rejectUnidentifiedLegacyCheckpoint(): Promise<void> {
    const entries = await readdir(state, { withFileTypes: true }).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return [];
        throw error;
      },
    );
    if (entries.length) await validatePreparedOutputDir(state, undefined, true);
    for (const entry of entries) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.pending\.json$/u.test(entry.name))
        continue;
      const candidateKey = entry.name.slice(0, -".pending.json".length);
      if (candidateKey === key || legacyKeys.has(candidateKey)) continue;
      const serialized = await readOptionalFile(join(state, entry.name));
      if (serialized === undefined) continue;
      try {
        // Locale-dependent filenames predate input projections. Later formats
        // must remain isolated by their deployment-bound checkpoint keys.
        const content = JSON.parse(serialized) as SavedSubmission | null;
        if (!content || content.inputProjection !== undefined) continue;
        validateSaved(serialized, true);
      } catch {
        continue;
      }
      // These older bodies contain no deployment identity. Do not guess a
      // destination or replace their immutable request with a fresh publication.
      throw new CodexSecurityError(
        "An older pending import matches this input, but its checkpoint identity could not be established. Resume it using the original deployment and locale before publishing this selection. The saved request was preserved without uploading.",
      );
    }
  }
  let recovered: SavedSubmission | undefined;
  for (const legacyKey of legacyKeys) {
    if (legacyKey === key) continue;
    const legacyPath = join(state, `${legacyKey}.pending.json`);
    const captured = await readOptionalFile(legacyPath);
    if (captured !== undefined) {
      // Preserve requests staged by the earlier locale-based filename format.
      // Hold both publication locks while moving the original checkpoint.
      await withImportLock(state, key, dependencies.signal, async () =>
        withImportLock(state, legacyKey, dependencies.signal, async () => {
          const current = await readOptionalFile(pendingPath);
          const serialized = await readOptionalFile(legacyPath);
          if (current !== undefined) {
            recovered = validateSaved(current);
            if (serialized !== undefined) {
              // A crash may leave both copies after installing the canonical file.
              // Retire only an identical immutable submission, never another request.
              let duplicate: SavedSubmission | null = null;
              try {
                duplicate = JSON.parse(serialized) as SavedSubmission | null;
              } catch (error) {
                if (!(error instanceof SyntaxError)) throw error;
              }
              if (
                duplicate !== null &&
                typeof duplicate === "object" &&
                sameSubmission(duplicate, recovered)
              )
                await rm(legacyPath);
            }
            return;
          }
          // A competing resumer may have completed and removed both paths while
          // this caller waited. Retain its observed immutable request and receipts.
          const content = validateSaved(serialized ?? captured, true);
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
            hash("sha256", canonicalJson(legacyParsed.findings));
          const rebindProjection =
            content.inputProjection !== undefined ||
            savedEvidenceDigest !== inputDigest;
          if (rebindProjection)
            content.inputProjection = { inputDigest, savedEvidenceDigest };
          recovered = content;
          if (serialized === undefined) return;
          if (!rebindProjection) {
            await rename(legacyPath, pendingPath);
          } else {
            // Bind the new input projection to the original immutable evidence,
            // so later inventory reordering still resumes these exact requests.
            await writeAtomicJson(pendingPath, content);
            await rm(legacyPath);
          }
        }),
      );
    }
  }
  const serialized = await readOptionalFile(pendingPath);
  const saved =
    serialized === undefined ? recovered : validateSaved(serialized);
  if (!saved) await rejectUnidentifiedLegacyCheckpoint();
  if (saved) {
    const content = saved;
    for (const submission of content.requests) {
      if (submission.repository.reset_marker !== destination.reset_marker) {
        // The old request is never sent after reset. A subsequent explicit
        // invocation prepares a fresh submission and asks for approval again.
        await withImportLock(state, key, dependencies.signal, async () => {
          const current = await readOptionalFile(pendingPath);
          if (
            current !== undefined &&
            sameSubmission(JSON.parse(current) as SavedSubmission, content)
          )
            await rm(pendingPath);
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

  // Existing repository submissions keep their original request bodies and receipts.
  const privatePath = join(state, `${key}.private-import.json`);
  const privateSaved = await readOptionalFile(privatePath);
  if (
    !saved &&
    (privateProviders?.has(source.provider) || privateSaved !== undefined)
  ) {
    const client = privateImportClient(
      apiBaseUrl,
      credentials,
      dependencies.fetch ?? globalThis.fetch,
      dependencies.signal,
    );
    const context = await client.context();
    if (source.source_key.trim() !== source.source_key)
      throw new CodexSecurityError(
        "A private source key cannot have leading or trailing whitespace.",
      );
    const report = privateReport(parsed.findings, context.limits);
    const binding = {
      apiBaseUrl,
      accountId: credentials.account_id,
      source,
      repository: {
        id: destination.id,
        repo_connector_id: destination.repo_connector_id,
      },
      sha256: report.digest,
      contextVersion: context.context_version,
    };
    function checkpointForContext(data: string | undefined) {
      if (data === undefined) return undefined;
      const checkpoint = readPrivateCheckpoint(data, binding);
      // A reset requires another preview and fresh upload and job request IDs.
      return checkpoint.contextVersion === binding.contextVersion
        ? checkpoint
        : undefined;
    }
    const previous = checkpointForContext(privateSaved);
    function requireAccess(
      value: typeof context,
      savedFile: boolean,
      savedJob: boolean,
    ) {
      if (
        !value.can_read ||
        (!savedJob &&
          ((!savedFile && !value.can_upload) ||
            !value.can_create_import_jobs ||
            !value.formats.includes("security.findings.v1")))
      )
        throw new CodexSecurityError(
          "Private findings import is unavailable for this account or report format.",
        );
    }
    requireAccess(context, !!previous?.fileId, !!previous?.jobId);
    const privateImport = {
      contextVersion: binding.contextVersion,
      sha256: report.digest,
      bytes: Buffer.byteLength(report.bytes),
    };
    const preview: ExternalPublicationPreview = {
      ...parsed,
      cloudApiUrl: `${apiBaseUrl}/finding-imports`,
      accountId: credentials.account_id,
      destination,
      source,
      resumed: previous !== undefined,
      requests: [],
      privateImport,
    };
    return {
      preview: structuredClone(preview),
      publish: () =>
        withImportLock(state, key, dependencies.signal, async () => {
          const current = await client.context();
          if (current.context_version !== binding.contextVersion)
            throw new CodexSecurityError(
              "The private inbox changed. Run the command again to review the new destination.",
            );
          const stored = checkpointForContext(
            await readOptionalFile(privatePath),
          );
          requireAccess(current, !!stored?.fileId, !!stored?.jobId);
          if ((await readOptionalFile(pendingPath)) !== undefined)
            throw new CodexSecurityError(
              "A repository submission is pending. Review its saved request before continuing.",
            );
          const checkpoint = stored ?? {
            ...binding,
            uploadRequestId: randomUUID(),
            jobRequestId: randomUUID(),
            fileId: undefined,
            jobId: undefined,
            receipt: undefined,
          };
          const result: ExternalPublicationResult = {
            cloudApiUrl: preview.cloudApiUrl,
            status: "interrupted",
            read: parsed.read,
            ready: parsed.findings.length,
            report: parsed.report,
            excluded: parsed.excluded,
            receipts: [],
            counts: { created: 0, updated: 0, unchanged: 0, error: 0 },
            failures: [],
            unacknowledged: parsed.findings.length,
            verified: 0,
          };
          if (!stored) await writeAtomicJson(privatePath, checkpoint);
          try {
            if (!checkpoint.fileId) {
              progress({ phase: "uploading", completed: 0 });
              checkpoint.fileId = await client.upload({
                requestId: checkpoint.uploadRequestId,
                contextVersion: binding.contextVersion,
                ...report,
                recovering: stored !== undefined,
              });
              await writeAtomicJson(privatePath, checkpoint);
            }
            progress({ phase: "verifying", completed: 0 });
            const job = await client.job(
              {
                requestId: checkpoint.jobRequestId,
                contextVersion: binding.contextVersion,
                fileId: checkpoint.fileId,
                source,
                repository: binding.repository,
                jobId: checkpoint.jobId,
              },
              async (id) => {
                checkpoint.jobId = id;
                await writeAtomicJson(privatePath, checkpoint);
              },
            );
            const { created, updated, unchanged, error } = job.counts;
            const processed = created + updated + unchanged + error;
            if (
              job.counts.discovered !== processed + job.counts.unprocessed ||
              job.counts.discovered > result.ready ||
              (job.status === "completed" &&
                (processed !== result.ready ||
                  job.counts.total !== result.ready))
            )
              throw new CodexSecurityError(
                "Cloud returned counts that do not match the selected report.",
              );
            checkpoint.receipt = job;
            await writeAtomicJson(privatePath, checkpoint);
            Object.assign(result, {
              privateJob: job,
              counts: { created, updated, unchanged, error },
              unacknowledged: result.ready - processed,
              status:
                job.status === "completed" && !error && !parsed.excluded.length
                  ? "complete"
                  : "partial",
              ...(job.error ? { error: job.error.message } : {}),
            });
            return result;
          } catch (error) {
            result.error =
              error instanceof Error ? error.message : String(error);
            result.savedSubmission = privatePath;
            throw new ExternalPublicationError(result.error, result, error);
          }
        }),
    };
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
    inputProjection: saved?.inputProjection ?? {
      inputDigest,
      savedEvidenceDigest: hash(
        "sha256",
        canonicalJson(submissionFindings(requests)),
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
    preview: structuredClone(preview),
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
            : { report: structuredClone(parsed.report) }),
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
      let acquired = false;
      return await withImportLock(state, key, dependencies.signal, async () => {
        acquired = true;
        // Re-read under the lock to keep checkpoints from another publisher.
        const pending = await readOptionalFile(pendingPath);
        if (pending === undefined && !saved) {
          if ((await readOptionalFile(privatePath)) !== undefined)
            throw new CodexSecurityError(
              "A private import already owns this selection. Review its saved job before continuing.",
            );
          await rejectUnidentifiedLegacyCheckpoint();
        }
        const current =
          pending === undefined
            ? submission
            : (JSON.parse(pending) as SavedSubmission);
        const adoptProjectMap =
          submission.inspectorProjectMapRequired &&
          current.inspectorProjectMapRequired === undefined;
        if (adoptProjectMap) current.inspectorProjectMapRequired = true;
        if (!sameSubmission(current, submission))
          throw new CodexSecurityError(
            "Another publication prepared this input. Run the command again to review and resume that saved request.",
          );
        const receipts = (current.receipts ?? []).map(validateImportReceipt);
        if (receipts.length > requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged: FindingImportReceipt[] = [];
        let verified = 0;
        let persisted = pending !== undefined;
        try {
          if (pending === undefined || adoptProjectMap) {
            await writeAtomicJson(pendingPath, current);
            persisted = true;
          }
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
                  canonicalJson(report.evidence) !==
                    canonicalJson(expected.evidence))) ||
              report.source_finding_id !== expected.source_finding_id ||
              report.repo_id !== destination.id ||
              report.repo_connector_id !== destination.repo_connector_id ||
              report.environment_id !== batch.repository.environment_id ||
              canonicalJson(report.source) !== canonicalJson(source)
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
          await rm(pendingPath, { force: true });
          return completed;
        } catch (error) {
          if (error instanceof CloudImportError && error.status === 409) {
            await rm(pendingPath, { force: true });
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
        // The active publisher owns the checkpoint. Report only acknowledgements
        // already observed during preparation, without rewriting its files.
        const known = submission.receipts ?? [];
        if (known.length > requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged = known.map((receipt, index) =>
          validatePublicationReceipt(receipt, requests[index]!),
        );
        const message = saved
          ? `Publication canceled while waiting. Repeat the same command to resume the saved request. Saved submission: ${pendingPath}`
          : "Publication canceled while waiting. No resumable request was saved by this invocation.";
        throw new ExternalPublicationError(
          message,
          {
            ...result(acknowledged, 0),
            status: "interrupted",
            error: message,
            ...(saved ? { savedSubmission: pendingPath } : {}),
          },
          error,
        );
      });
    },
  };
}
