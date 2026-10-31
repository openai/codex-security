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
  semgrepSarifRepositories,
  type ExternalFindingsReaderOptions,
} from "./external-findings-read.js";
import { canonicalJson, isRecord } from "./record.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { wizFindingRepository } from "./wiz-findings.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import {
  normalizeSemgrepFindings,
  readSemgrepReport,
} from "./semgrep-findings.js";
import {
  normalizeSnykFile,
  readSnykReport,
  snykRepositoryUrls,
} from "./snyk-findings.js";
import {
  type SnykIssuesFindings,
  isSnykRestFinding,
  isSnykRestFormat,
  snykRestImportRepository,
  snykRestRepositoryMatches,
} from "./snyk-rest-findings.js";
import {
  isSemgrepPlatformEvidence,
  isSemgrepPlatformFormat,
  semgrepLegacyRepositoryWitnesses,
  semgrepNativeProjectUrl,
  semgrepPlatformFindingBinding,
  semgrepPlatformRepositoryReference,
  semgrepPlatformReportScope,
} from "./semgrep-platform-findings.js";
import {
  hostedRepositoryUrlKey,
  normalizeHostedGitRepositoryUrl,
} from "./hosted-git-repository.js";
import { hostedRepositoryUrl } from "./hosted-scanner-http.js";
import { endorRepositoryUrls } from "./endor-findings.js";
import {
  blackDuckReportRepositories,
  projectedBlackDuckRepositoryUrl,
} from "./blackduck-findings.js";
import { veracodeReportRepositories } from "./veracode-findings.js";
import { inspectorReportRepository } from "./inspector-findings.js";
import {
  snapshotImportOptions,
  snapshotSourceRepositories,
  type ExternalFindings,
  type ExternalPublicationInput,
  type ExternalSourceRepository,
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
  /** Independently verified source repositories for hosted Semgrep or Snyk evidence. */
  sourceRepositories?: readonly ExternalSourceRepository[];
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
    inputDigest: string;
    savedEvidenceDigest: string;
    retainedHostedSelection?: true;
  };
  inspectorProjectMapRequired?: true;
  /** Catalog URL when this source selection was approved, before any repository rename. */
  approvedRepositoryUrl?: string;
  approvedRepositoryPlatform?: "other";
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

async function writeAtomicJson(path: string, value: unknown): Promise<void> {
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

type ResolvedPublicationInput = ExternalPublicationInput & {
  recheckFileRepository?: (approvedUrl: string) => Promise<unknown>;
};

type PreparePublicationInput =
  | ResolvedPublicationInput
  | ((destination: ImportRepository) => Promise<ResolvedPublicationInput>);

function hostedSourceReferences(
  readerSources: readonly ExternalSourceRepository[],
  url?: string,
  sourcePlatform?: string,
): readonly ExternalSourceRepository[] {
  // The catalog supplies a GitHub identity only when the reader has no SCM mapping.
  const sources =
    readerSources.length || !url
      ? readerSources
      : [{ url, platform: "github" as const }];
  return sourcePlatform === "other"
    ? sources.filter(({ platform }) => platform !== "github")
    : sources;
}

export async function prepareExternalPublication(
  path: string,
  options: ExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies = {},
): Promise<PreparedExternalPublication> {
  requireExternalImports(dependencies.environment);
  const settings = snapshotImportOptions(options);
  const readerSources = snapshotSourceRepositories(
    dependencies.sourceRepositories,
  );
  const provider = EXTERNAL_FINDINGS_PROVIDERS[settings.provider];
  let input: PreparePublicationInput;
  if (settings.provider === "semgrep" || settings.provider === "snyk") {
    const semgrep = settings.provider === "semgrep";
    const report = await (semgrep
      ? readSemgrepReport(path)
      : readSnykReport(path));
    const normalize = async (url?: string) => {
      const references = hostedSourceReferences(readerSources, url);
      const findings = semgrep
        ? normalizeSemgrepFindings(
            report,
            {
              sourceRepositoryUrl: settings.sourceRepositoryUrl,
              sourceRepositories: references,
            },
            "cloud",
          )
        : await normalizeSnykFile(report, "cloud", references);
      return normalizedPublicationInput(findings, provider);
    };
    const hosted =
      isRecord(report) &&
      (semgrep
        ? isSemgrepPlatformFormat(report["format"])
        : isSnykRestFormat(report["format"]));
    input = hosted
      ? async (destination) => {
          try {
            return await normalize(destination.url);
          } catch (error) {
            const project = report["project"];
            const candidate =
              report["sourceRepositoryUrl"] ??
              settings.sourceRepositoryUrl ??
              (semgrep && isRecord(project) ? project["url"] : undefined);
            if (typeof candidate !== "string" || candidate === destination.url)
              throw error;
            // A renamed repository can require its old spelling to identify the saved request.
            // Only an approved checkpoint can later authorize that spelling.
            const projection = await normalize(
              normalizeHostedGitRepositoryUrl(candidate, destination.url, true),
            );
            return {
              ...projection,
              recheckFileRepository: (approvedUrl) => {
                if (approvedUrl === destination.url) throw error;
                return normalize(approvedUrl);
              },
            };
          }
        }
      : await normalize();
  } else {
    const parsed = await readExternalFindings(path, settings);
    input =
      parsed.publication ??
      normalizedPublicationInput(parsed.findings, provider);
  }
  return preparePublicationInput(
    input,
    { ...settings, provider },
    dependencies,
    readerSources,
    settings.sourceRepositoryUrl,
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
    normalizedPublicationInput(input, settings.provider),
    settings,
    dependencies,
    snapshotSourceRepositories(dependencies.sourceRepositories),
  );
}

function cloudSourceKey(
  url: string,
  platform: ExternalSourceRepository["platform"],
) {
  return hostedRepositoryUrlKey(
    url,
    platform === "github",
    platform === "gitlab",
  );
}

/** Verify every source in a hosted selection, including SDK inputs containing typed-only rows. */
function hostedRepositoryMatcher(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: NormalizedExternalPublicationOptions["provider"],
  declaredUrl: string | undefined,
  destination: Pick<ImportRepository, "url">,
  readerSources: readonly ExternalSourceRepository[],
  allowOpaqueLegacyRows = false,
): { github: boolean; matches: (url: string) => boolean } | undefined {
  const references = hostedSourceReferences(
    readerSources,
    destination.url,
    input.sourceRepositoryPlatform,
  );
  if (provider === "snyk") {
    const declaredSource =
      input.sourceRepositoryUrl !== undefined ||
      input.sourceRepositoryPlatform !== undefined ||
      declaredUrl !== undefined ||
      readerSources.length > 0;
    const binding = snykRestImportRepository(
      input,
      provider,
      [
        ...readerSources.map(({ url }) => url),
        ...(declaredUrl === undefined ? [] : [declaredUrl]),
      ],
      references,
      allowOpaqueLegacyRows,
      declaredSource ? destination.url : undefined,
    );
    if (binding)
      return {
        github: binding.platform === "github",
        matches: (url) => snykRestRepositoryMatches(binding, url),
      };
  }
  if (provider !== "semgrep") return;

  const declared =
    input.sourceRepositoryUrl === undefined
      ? undefined
      : hostedRepositoryUrl(
          input.sourceRepositoryUrl,
          "Semgrep source repository",
        );
  const reportScope = semgrepPlatformReportScope(input);
  const claims = new Set<string>();
  let original: string | undefined;
  const nativeRows: ExternalFindings["findings"] = [];
  for (const finding of input.findings) {
    const typed = finding.evidence.details?.repository?.url;
    if (typed) claims.add(typed);
    for (const { url } of semgrepSarifRepositories(finding)) claims.add(url);

    const data = finding.evidence.source_data;
    const project = data?.["project"];
    if (
      !allowOpaqueLegacyRows ||
      (isRecord(project) &&
        project["id"] != null &&
        project["name"] != null &&
        data?.["deployment"] != null &&
        data["ref"] != null &&
        data["product"] != null &&
        ((isRecord(data["finding"]) && data["finding"]["id"] != null) ||
          typeof data["semgrepPlatformFindingJson"] === "string"))
    ) {
      nativeRows.push(finding);
      continue;
    }
    // Released SDKs could save partial native records. Retain any source still
    // identifiable on that row while validating complete siblings under the new mapping.
    if (!data || !isSemgrepPlatformEvidence(finding, provider)) continue;
    const native = isRecord(project)
      ? semgrepNativeProjectUrl(project["url"], references)
      : undefined;
    for (const url of [native, data["sourceRepositoryUrl"]]) {
      if (typeof url !== "string") continue;
      original ??= url;
      claims.add(url);
    }
  }
  const witnesses = semgrepLegacyRepositoryWitnesses(
    nativeRows,
    provider,
    references,
    "cloud",
  );
  for (const finding of nativeRows) {
    const native = semgrepPlatformFindingBinding(
      finding,
      provider,
      references,
      witnesses,
      reportScope,
      "cloud",
    )?.url;
    if (native) {
      original ??= native;
      claims.add(native);
    }
  }
  const source =
    original ??
    declared ??
    declaredUrl ??
    (readerSources.length || input.sourceRepositoryPlatform !== undefined
      ? destination.url
      : undefined);
  if (source === undefined) return;
  const { platform } = semgrepPlatformRepositoryReference(source, references);
  const expected = cloudSourceKey(source, platform);
  const matches = (url: string) => cloudSourceKey(url, platform) === expected;
  if (declared !== undefined) claims.add(declared);
  if (declaredUrl !== undefined) claims.add(declaredUrl);
  for (const url of claims)
    if (!matches(hostedRepositoryUrl(url, "Semgrep source repository")))
      throw new CodexSecurityError(
        "The finding does not match the original Semgrep project repository.",
      );
  return { github: platform === "github", matches };
}

function normalizedPublicationInput(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: NormalizedExternalPublicationOptions["provider"],
): ExternalPublicationInput {
  // Validation adds Cloud defaults; leave the caller's objects unchanged.
  const { report, ...parsed } = input;
  if (!Object.hasOwn(parsed, "sourceFormat") && "sourceFormat" in input)
    Object.assign(parsed, { sourceFormat: input.sourceFormat });
  // Read the Snyk discriminator even when the caller selected another provider.
  if (!Object.hasOwn(parsed, "snykRestContext") && "snykRestContext" in input)
    parsed.snykRestContext = input.snykRestContext;
  if (parsed.snykRestContext !== undefined) {
    if (provider !== "snyk")
      throw new CodexSecurityError(
        "Snyk REST evidence requires the snyk provider.",
      );
    if (!isSnykRestFormat(parsed.snykRestContext?.["format"]))
      throw new CodexSecurityError(
        "Expected a versioned Snyk REST report context.",
      );
  }
  if (provider === "semgrep" || provider === "snyk") {
    // Normalized SDK inputs may expose the source binding through class getters.
    for (const key of [
      "sourceRepositoryUrl",
      "sourceRepositoryPlatform",
    ] as const) {
      if (!Object.hasOwn(parsed, key) && key in input)
        Object.assign(parsed, { [key]: input[key] });
    }
  }
  if (
    "sourceFormat" in parsed &&
    isSemgrepPlatformFormat(parsed.sourceFormat)
  ) {
    if (provider !== "semgrep")
      throw new CodexSecurityError(
        "Semgrep Platform evidence requires the semgrep provider.",
      );
    if (
      !Object.hasOwn(parsed, "semgrepPlatformScope") &&
      "semgrepPlatformScope" in input
    )
      Object.assign(parsed, {
        semgrepPlatformScope: input.semgrepPlatformScope,
      });
    semgrepPlatformReportScope(parsed);
  }
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
  const identity = publicationIdentity(current);
  return {
    current,
    legacy: current,
    currentIdentity: identity,
    legacyIdentity: identity,
  };
}

function publicationIdentity(input: ExternalFindings) {
  return input.report === undefined
    ? input.findings
    : { findings: input.findings, report: reportForJson(input.report) };
}

// A v1 SDK retained native rows as objects; the file reader preserves them as
// lossless JSON. Only change the current projection, so an approved old request
// can still be recovered under its original evidence digest.
function canonicalSemgrepPublication(
  input: ResolvedPublicationInput,
  destination: ImportRepository,
  readerSources: readonly ExternalSourceRepository[],
): ResolvedPublicationInput {
  const current: ExternalFindings & Partial<SnykIssuesFindings> = input.current;
  const originalRow = (finding: ExternalFindings["findings"][number]) =>
    isRecord(finding.evidence.source_data?.["finding"]) &&
    isSemgrepPlatformEvidence(finding, "semgrep");
  const first = current.findings.find(originalRow);
  if (!first) return input;
  const reportScope = semgrepPlatformReportScope(current);
  const retained = first.evidence.source_data;
  const project = retained?.["project"];
  const retainedUrl =
    current.sourceRepositoryUrl ??
    retained?.["sourceRepositoryUrl"] ??
    (isRecord(project) ? project["url"] : undefined);
  // A renamed repository may need the original spelling to identify its checkpoint.
  // Preparation validates the unmodified report against the authenticated approval.
  for (const url of new Set([destination.url, retainedUrl])) {
    if (typeof url !== "string") continue;
    const references = hostedSourceReferences(
      readerSources,
      url,
      current.sourceRepositoryPlatform,
    );
    try {
      const witnesses = semgrepLegacyRepositoryWitnesses(
        current.findings,
        "semgrep",
        references,
        "cloud",
      );
      const findings = current.findings.map((finding) => {
        if (!originalRow(finding)) return finding;
        const binding = semgrepPlatformFindingBinding(
          finding,
          "semgrep",
          references,
          witnesses,
          reportScope,
          "cloud",
        );
        return binding?.sourceData
          ? {
              ...finding,
              evidence: {
                ...finding.evidence,
                source_data: binding.sourceData,
              },
            }
          : finding;
      });
      const upgraded = { ...current, findings };
      return {
        ...input,
        current: upgraded,
        currentIdentity: publicationIdentity(upgraded),
      };
    } catch {
      // The released SDK also accepted partial original records; keep the raw
      // identity as a fallback so its exact saved request remains recoverable.
    }
  }
  return input;
}

function requireFindings(
  input: ResolvedPublicationInput,
): ResolvedPublicationInput {
  const parsed = input.current;
  if (parsed.findings.length === 0) {
    const diagnostics = reportForJson(parsed.report)?.["errors"];
    throw new CodexSecurityError(
      `No supported findings are ready to publish. ${parsed.excluded.map((item) => `Item ${item.position}: ${item.reason}`).join(" ")}${Array.isArray(diagnostics) && diagnostics.length ? ` Scanner diagnostics: ${JSON.stringify(diagnostics)}` : ""}`,
    );
  }
  return input;
}

async function preparePublicationInput(
  input: PreparePublicationInput,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies,
  readerSources: readonly ExternalSourceRepository[],
  declaredUrl?: string,
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
  if (typeof input !== "function") requireFindings(input);
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
  const resolved =
    typeof input === "function"
      ? requireFindings(await input(destination))
      : input;
  const report: ExternalFindings & Partial<SnykIssuesFindings> =
    resolved.current;
  const source = { provider: options.provider, source_key: options.sourceKey };
  const state = join(
    codexSecurityStateDirectory(environment),
    "external-finding-publications",
  );
  const checkpointIdentity = [
    // Keep existing production checkpoints readable; other deployments must
    // never share a saved request or receipt with the production default.
    ...(apiBaseUrl === DEFAULT_CLOUD_BASE_URL ? [] : [apiBaseUrl]),
    credentials.account_id,
    destination.id,
    destination.repo_connector_id,
    source,
  ];
  const keyFor = (identity: unknown) =>
    hash("sha256", canonicalJson([...checkpointIdentity, identity]));
  const canonical =
    options.provider === "semgrep"
      ? canonicalSemgrepPublication(resolved, destination, readerSources)
      : resolved;
  const canonicalKey = keyFor(canonical.currentIdentity);
  const originalKey =
    canonical === resolved ? canonicalKey : keyFor(resolved.currentIdentity);
  // Keep an earlier SDK's immutable request at its original key. Moving it during a
  // preview destroys the source witness used to recognize reordered same-ID retries.
  const capturedOriginal =
    originalKey !== canonicalKey &&
    (await readOptionalFile(join(state, canonicalKey + ".pending.json"))) ===
      undefined
      ? await readOptionalFile(join(state, originalKey + ".pending.json"))
      : undefined;
  const {
    current: parsed,
    legacy: legacyParsed,
    currentIdentity,
    legacyIdentity,
    recheckFileRepository,
  } = capturedOriginal === undefined ? canonical : resolved;
  const inputDigest = hash("sha256", canonicalJson(currentIdentity));
  const legacyInputDigest = hash("sha256", canonicalJson(legacyIdentity));
  const originalHostedRetry =
    "This source has a pending hosted Cloud request from an earlier SDK. Resume it with the SDK build that created it before publishing this source again.";
  const unknownHostedRetry =
    "A pending hosted v1 request matches this provider and repository, but its deployment could not be established. Resume it with the SDK build that created it, on the original deployment, using the full original input and metadata.";
  function originalHostedPending(
    content: SavedSubmission,
    filenameKey: string,
  ) {
    const projection = content.inputProjection;
    if (
      (options.provider !== "semgrep" && options.provider !== "snyk") ||
      content.accountId !== credentials.account_id ||
      (content.approvedRepositoryUrl !== undefined &&
        !projection?.retainedHostedSelection) ||
      !projection ||
      !content.requests?.length ||
      !content.requests.every(
        ({ repository, source: savedSource }) =>
          repository.id === destination.id &&
          repository.repo_connector_id === destination.repo_connector_id &&
          canonicalJson(savedSource) === canonicalJson(source),
      )
    )
      return false;
    const findings = submissionFindings(content.requests);
    if (
      projection.savedEvidenceDigest !== hash("sha256", canonicalJson(findings))
    )
      return false;
    const projections = [findings];
    // Historical filenames include caller fields discarded by request validation.
    // Reuse them by stable ID with the evidence and order of the approved request.
    const metadata = new Map(
      legacyParsed.findings
        .filter((row) =>
          Object.keys(row).some(
            (key) => key !== "evidence" && key !== "source_finding_id",
          ),
        )
        .map((row) => [row.source_finding_id, row]),
    );
    if (findings.some((row) => metadata.has(row.source_finding_id)))
      projections.push(
        findings.map((row) => ({
          ...metadata.get(row.source_finding_id),
          ...row,
        })),
      );
    const identities: unknown[] = [...projections];
    if (parsed.report !== undefined) {
      const report = reportForJson(parsed.report);
      identities.push(
        ...projections.map((rows) => ({ findings: rows, report })),
      );
    }
    // Caller metadata on a normalized finding is part of the filename but not the
    // request body. An exact retry still supplies that original identity.
    if (filenameKey === keyFor(legacyIdentity))
      identities.unshift(legacyIdentity);
    const identity = identities.find((value) => filenameKey === keyFor(value));
    const digest = (value: unknown) => hash("sha256", canonicalJson(value));
    if (identity && projection.inputDigest !== digest(identity))
      return "verified";

    const selected = new Set(
      parsed.findings.map((row) => row.source_finding_id),
    );
    const sameIds =
      findings.length === selected.size &&
      findings.every((row) => selected.delete(row.source_finding_id));
    const semgrep = options.provider === "semgrep";
    const native = findings.some(({ evidence }) => {
      const data = evidence.source_data;
      if (!data || !isRecord(data[semgrep ? "finding" : "issue"])) return false;
      const expected = semgrep
        ? "semgrep-platform-findings/v1"
        : "snyk-rest-issues/v1";
      if (data["format"] !== undefined && data["format"] !== expected)
        return false;
      if (identity && data["format"] === expected) return true;
      if (
        !isRecord(data["project"]) ||
        (!identity && !sameIds && data["format"] !== expected)
      )
        return false;
      // Prove the actual native shape independently of a format label or a caller ID.
      const evidenceOnly = {
        source_finding_id: "",
        evidence: { ...evidence, source_data: { ...data, format: undefined } },
      };
      return semgrep
        ? isSemgrepPlatformEvidence(evidenceOnly, "semgrep")
        : isSnykRestFinding(evidenceOnly);
    });
    if (!native) return false;
    if (!identity) {
      // If the saved selections reconstruct an old input digest but not its scoped
      // filename, the pending request belongs to another deployment. The #2085
      // writer included its original repository comparison flags in the digest.
      const repositories = new Set([destination.url]);
      for (const { evidence } of findings) {
        const data = evidence.source_data;
        const project = data?.["project"];
        const retained =
          semgrep && isRecord(project)
            ? project["url"]
            : data?.["sourceRepositoryUrl"];
        if (typeof retained === "string") repositories.add(retained);
      }
      const paths = semgrep ? [null, true] : [false, true];
      const suffixes = semgrep ? [false] : [false, true];
      for (const candidate of identities) {
        if (digest(candidate) === projection.inputDigest) return false;
        for (const strict of paths) {
          for (const suffix of suffixes) {
            for (const repository of repositories) {
              const url = hostedRepositoryUrlKey(repository, !strict, suffix);
              if (
                digest([candidate, [url, strict, suffix]]) ===
                projection.inputDigest
              )
                return false;
            }
          }
        }
      }
      return "unidentified";
    }
    // The released normalized SDK can also retain native rows. Hold only its same IDs.
    return sameIds && "verified";
  }
  function wasReset(content: SavedSubmission) {
    return content.requests.some(
      ({ repository }) => repository.reset_marker !== destination.reset_marker,
    );
  }
  const resetMessage =
    "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.";
  async function retireReset(
    content: SavedSubmission,
    filenameKey: string,
  ): Promise<never> {
    const path = join(state, filenameKey + ".pending.json");
    await withImportLock(state, filenameKey, dependencies.signal, async () => {
      const current = await readOptionalFile(path);
      if (
        current !== undefined &&
        sameSubmission(JSON.parse(current) as SavedSubmission, content)
      )
        await rm(path);
    });
    throw new CloudImportError(409, resetMessage);
  }
  function validateSaved(
    serialized: string,
    legacy = false,
    filenameKey = key,
  ): SavedSubmission {
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
    if (!matches) {
      const status = originalHostedPending(content, filenameKey);
      if (status === "unidentified")
        throw new CodexSecurityError(unknownHostedRetry);
      if (!status)
        throw new Error(
          "Saved import evidence does not match the selected input.",
        );
      if (!wasReset(content)) throw new CodexSecurityError(originalHostedRetry);
      // Return only to the existing reset-retirement path, before preparation or upload.
    }
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
  const key = capturedOriginal === undefined ? canonicalKey : originalKey;
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
      let hostedV1: SavedSubmission | undefined;
      let unknownHosted = false;
      try {
        const content = JSON.parse(serialized) as SavedSubmission | null;
        if (!content) continue;
        if (content.inputProjection !== undefined) {
          const identified = originalHostedPending(content, candidateKey);
          if (!identified) continue;
          if (identified === "verified") hostedV1 = content;
          else unknownHosted = true;
        } else validateSaved(serialized, true);
      } catch {
        continue;
      }
      if (unknownHosted) throw new CodexSecurityError(unknownHostedRetry);
      if (hostedV1) {
        if (wasReset(hostedV1)) await retireReset(hostedV1, candidateKey);
        throw new CodexSecurityError(originalHostedRetry);
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
          const content = validateSaved(
            serialized ?? captured,
            true,
            legacyKey,
          );
          if (!sameFindingSelection(legacyParsed.findings, parsed.findings))
            throw new CodexSecurityError(
              "The saved import selects different findings from this input. Resume the original selection before publishing this selection.",
            );
          if (wasReset(content)) {
            if (serialized !== undefined) await rm(legacyPath);
            throw new CloudImportError(409, resetMessage);
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
  const serialized = (await readOptionalFile(pendingPath)) ?? capturedOriginal;
  const saved =
    serialized === undefined ? recovered : validateSaved(serialized);
  if (!saved) await rejectUnidentifiedLegacyCheckpoint();
  if (saved && wasReset(saved)) await retireReset(saved, key);
  if (saved?.inspectorProjectMapRequired && !inspectorProjectMap)
    throw new CodexSecurityError(
      "Supply the verified Inspector project binding again to resume.",
    );

  // The findings-only checkpoint key lets projected and native callers resume one immutable
  // request. Supplemental report claims are outside that digest and must still match its source.
  const hosted = options.provider === "snyk" || options.provider === "semgrep";
  const declaredSource =
    readerSources.length > 0 ||
    declaredUrl !== undefined ||
    report.sourceRepositoryUrl !== undefined ||
    report.sourceRepositoryPlatform !== undefined ||
    report.snykRestContext !== undefined;
  let legacyTypedUrl: string | undefined;
  let suppliedReport = report;
  const sourceFor = (url: string, platform?: "other") =>
    hostedRepositoryMatcher(
      platform
        ? { ...suppliedReport, sourceRepositoryPlatform: platform }
        : suppliedReport,
      options.provider,
      declaredUrl,
      { url },
      readerSources,
      saved !== undefined,
    );
  if (hosted && saved && declaredSource) {
    // The released publisher checked typed repository URLs against its authenticated catalog.
    // Opaque original records could name a different project and cannot establish a rename.
    const findings = submissionFindings(saved.requests);
    if (!saved.approvedRepositoryUrl)
      legacyTypedUrl = findings.find(
        ({ evidence }) => evidence.details?.repository?.url,
      )?.evidence.details?.repository?.url;
    // Supplemental claims must agree with each verifiable row from the immutable request.
    suppliedReport = { ...report, findings };
  }
  // The released request retained its typed finding URL, but only the authenticated
  // catalog or a previously recorded approval can bind a new source declaration.
  const approvedUrl = saved?.approvedRepositoryUrl ?? destination.url;
  if (
    hosted &&
    readerSources.some(({ platform, url }) => {
      const source = normalizeHostedGitRepositoryUrl(
        url,
        approvedUrl,
        platform !== undefined,
      );
      return (
        cloudSourceKey(source, platform) !==
        cloudSourceKey(approvedUrl, platform)
      );
    })
  )
    throw new CodexSecurityError(
      "The reader's source repository does not match the selected Cloud repository.",
    );
  await recheckFileRepository?.(approvedUrl);
  const hostedSource =
    hosted && (!saved || declaredSource)
      ? sourceFor(approvedUrl, saved?.approvedRepositoryPlatform)
      : undefined;
  const matchesHostedRepository = hostedSource?.matches;
  function requireApprovedSource(url: string, platform?: "other") {
    const binding =
      platform && hostedSource?.github
        ? sourceFor(url, platform)
        : hostedSource;
    if (binding && !binding.matches(url))
      throw new CodexSecurityError(
        "The source project does not match the selected Cloud repository.",
      );
  }
  requireApprovedSource(approvedUrl);
  if (legacyTypedUrl) requireApprovedSource(legacyTypedUrl);

  if (saved) {
    checkRepositories(parsed.findings);
    // A resumed request sends its saved projection; validate both before recording approval.
    checkRepositories(submissionFindings(saved.requests));
  }

  // An older, genuinely unbound checkpoint first acquires a URL on a matching preview.
  // Retain it at the original path so its bare caller can still recover the same request.
  if (saved && !saved.approvedRepositoryUrl && hostedSource) {
    await withImportLock(state, key, dependencies.signal, async () => {
      const serialized = await readOptionalFile(pendingPath);
      if (serialized === undefined) return;
      const current = validateSaved(serialized);
      if (!sameSubmission(current, saved))
        throw new CodexSecurityError(
          "Another publication prepared this input. Review the saved request again.",
        );
      if (current.approvedRepositoryUrl) {
        requireApprovedSource(
          current.approvedRepositoryUrl,
          current.approvedRepositoryPlatform,
        );
      } else {
        // Adding the catalog URL cannot erase an older SDK's same-selection hold.
        if (
          current.inputProjection &&
          originalHostedPending(current, key) === "verified"
        )
          current.inputProjection.retainedHostedSelection = true;
        current.approvedRepositoryUrl = approvedUrl;
        if (!hostedSource.github) current.approvedRepositoryPlatform = "other";
        await writeAtomicJson(pendingPath, current);
      }
      saved.inputProjection = current.inputProjection;
      saved.approvedRepositoryUrl = current.approvedRepositoryUrl;
      saved.approvedRepositoryPlatform = current.approvedRepositoryPlatform;
    });
  }

  function checkRepositories(findings: ExternalFindings["findings"]) {
    // A catalog casing or spelling change keeps the original source comparison target.
    const approved = hosted ? saved?.approvedRepositoryUrl : undefined;
    const sameCatalog =
      approved !== undefined &&
      hostedRepositoryUrlKey(approved, true) ===
        hostedRepositoryUrlKey(destination.url, true);
    const comparisonUrl = sameCatalog ? approved : destination.url;
    const key = sameCatalog
      ? (url: string) =>
          hostedRepositoryUrlKey(
            url,
            saved?.approvedRepositoryPlatform !== "other",
          )
      : cloudRepositoryUrlKey;
    function requireDestination(id: string, url: string | null | undefined) {
      if (
        url &&
        (matchesHostedRepository
          ? !matchesHostedRepository(url) ||
            !matchesHostedRepository(comparisonUrl)
          : key(url) !== key(comparisonUrl))
      )
        throw new CodexSecurityError(
          `Finding ${JSON.stringify(id)} belongs to ${JSON.stringify(url)}, which does not match the selected Cloud repository ${JSON.stringify(destination.url)}. Verify the source repository mapping before publishing.`,
        );
    }
    // Historical checkpoints already fixed the provider and request bytes.
    // Recheck any projected source against the destination discovered for this retry.
    const replay = saved && options.provider !== "blackduck";
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
        options.provider !== "veracode"
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
  if (!saved) {
    for (const finding of parsed.findings) {
      if (
        options.provider !== "semgrep" &&
        isSemgrepPlatformEvidence(finding, options.provider)
      )
        throw new CodexSecurityError(
          "Semgrep Platform evidence requires the semgrep provider.",
        );
      if (options.provider !== "snyk" && isSnykRestFinding(finding))
        throw new CodexSecurityError(
          "Snyk REST evidence requires the snyk provider.",
        );
    }
    checkRepositories(parsed.findings);
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
          await request(`${sourcePath(destination)}?${query}`),
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
  if (
    hosted &&
    (!saved || saved.approvedRepositoryUrl || matchesHostedRepository)
  )
    submission.approvedRepositoryUrl =
      saved?.approvedRepositoryUrl ?? approvedUrl;
  if (
    saved?.approvedRepositoryPlatform ||
    (!saved && hostedSource && !hostedSource.github)
  )
    submission.approvedRepositoryPlatform = "other";
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
          if (
            originalKey !== key &&
            (await readOptionalFile(
              join(state, originalKey + ".pending.json"),
            )) !== undefined
          )
            throw new CodexSecurityError(
              "Another publication prepared this input. Run the command again to review and resume that saved request.",
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
        if (current.approvedRepositoryUrl)
          requireApprovedSource(
            current.approvedRepositoryUrl,
            current.approvedRepositoryPlatform,
          );
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
                (await request("/finding_imports", batch)),
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
                ...current,
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
                `${sourcePath(destination)}/${encodeURIComponent(item.source_report_id!)}`,
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
