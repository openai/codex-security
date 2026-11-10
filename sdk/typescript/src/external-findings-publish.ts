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
import { join } from "node:path";
import { nullIfMissingFile } from "./targets.js";
import { setTimeout as delay } from "node:timers/promises";
import { isBoxedPrimitive, isProxy, isStringObject } from "node:util/types";
import {
  privateImportClient,
  selectPrivateReport,
  type PrivateImportFormat,
  readPrivateCheckpoint,
  type PrivateImportContext,
  unsuccessfulJob,
  type PrivateImportJob,
} from "./private-finding-import.js";
import { readCloudCredentials } from "./cloud-publish.js";
import type { LocalExternalImportOptions } from "./external-findings-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import {
  tenableReportFormat,
  tenableSourceRepository,
} from "./tenable-findings.js";
import {
  guardianFindingId,
  guardianFindingRepository,
  guardianSelectionFormat,
} from "./semgrep-guardian-findings.js";
import {
  cloudBaseUrl,
  cloudFindingsUrl,
  DEFAULT_CLOUD_BASE_URL,
} from "./cloud-endpoint.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  codexSecurityStateDirectory,
  createWindowsOutputDirectory,
  validatePreparedOutputDir,
  sqliteDatabaseOpener,
} from "./runtime.js";
import {
  EXTERNAL_FINDINGS_PROVIDERS,
  readExternalFindings,
  semgrepSarifRepositories,
  snykFileRepositories,
  type ExternalFindingsReader,
} from "./external-findings-read.js";
import { canonicalJson, isRecord } from "./record.js";
import { notify } from "./value.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { isWizPackageFinding, wizFindingRepository } from "./wiz-findings.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import { retainedGitHubRepository } from "./github-findings.js";
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
  snykRestCheckpointFindingId,
  snykRestImportRepository,
  snykRestRepositoryMatches,
} from "./snyk-rest-findings.js";
import {
  hasRetainedSemgrepScope,
  isSemgrepPlatformEvidence,
  isSemgrepPlatformFormat,
  semgrepPlatformFormat,
  semgrepLegacyRepositoryWitnesses,
  semgrepPlatformFindingBinding,
  semgrepPlatformRepositoryReference,
  semgrepPlatformReportScope,
} from "./semgrep-platform-findings.js";
import {
  hostedRepositoryUrlKey,
  normalizeHostedGitRepositoryUrl,
} from "./hosted-git-repository.js";
import { trivyRemoteKey, trivyRepositoryUrl } from "./trivy-findings.js";
import { hostedRepositoryUrl } from "./hosted-scanner-http.js";
import {
  endorRepositoryUrls,
  requiresStructuredEndorReport,
} from "./endor-findings.js";
import {
  blackDuckReportRepositories,
  projectedBlackDuckRepositoryUrl,
} from "./blackduck-findings.js";
import { checkmarxSelection } from "./checkmarx-repository.js";
import { continuumReportRepositories } from "./continuum-findings.js";
import { veracodeReportRepositories } from "./veracode-findings.js";
import { inspectorReportRepository } from "./inspector-findings.js";
import { sonarRepositoryUrls } from "./sonar-findings.js";
import {
  checkRetainedTrivyProvider,
  checkTrivyReportProvider,
  isTrivyReportHeader,
  retainedTrivyReport,
  trivyBatchSourceUrls,
  validateTrivyRepositoryUrl,
} from "./trivy-import.js";
import {
  NoPublishableFindingsError,
  reportForJson,
  snapshotSourceRepositories,
  type ExternalSourceRepository,
  snapshotImportOptions,
  cloneImportPreview,
  snapshotNormalizedFindings,
  type ExternalFinding,
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
  Provider,
  SourceReportSummary,
} from "./external-import-models.js";

const MAX_REQUEST_BYTES = 5 * 1024 * 1024;

/** Source and destination for evidence already normalized to the Cloud contract. */
export interface NormalizedExternalPublicationOptions {
  repository: string;
  provider: FindingImportRequest["source"]["provider"];
  sourceKey: string;
  /** For Tenable, verify this declaration against the retained repository evidence. */
  sourceRepositoryUrl?: string;
  /** Full Inspector project ARNs mapped to independently verified repository URLs. */
  inspectorProjectMap?: ReadonlyMap<string, string>;
}

/** File readers accepted by the Cloud publisher. */
export interface ExternalPublicationOptions extends LocalExternalImportOptions {
  provider: ExternalFindingsReader;
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
  format: 1;
  apiBaseUrl: string;
  accountId: string;
  inputDigest: string;
  evidenceDigest: string;
  semgrepScope?: string;
  nativeIds?: string[];
  approvedRepositoryUrl: string;
  approvedRepositoryPlatform?: "other";
  inspectorProjectMapRequired?: true;
  requests: FindingImportRequest[];
  receipts?: FindingImportReceipt[];
}

export interface ExternalPublicationPreview extends ExternalFindings {
  cloudApiUrl: string;
  cloudUrl?: string;
  accountId: string;
  destination: ImportRepository;
  source: FindingImportRequest["source"];
  resumed: boolean;
  requests: FindingImportRequest[];
  privateImport?: {
    format: PrivateImportFormat;
    contextVersion: string;
    sha256: string;
    bytes: number;
    retryOfJobId?: string;
  };
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

function jsonDigest(value: unknown): string {
  return hash("sha256", wireJson(value));
}

function matchesRepositoryEvidence(
  expected: ExternalFindings["findings"][number]["evidence"],
  stored: ExternalFindings["findings"][number]["evidence"],
): boolean {
  const storedWire = wireJson(stored);
  if (wireJson(expected) === storedWire) return true;
  // A repository can store a literal first-component colon with an explicit
  // relative prefix. Match only that spelling in typed locations and their manifests.
  const qualified = new Map<string, string>();
  const locations = expected.locations?.map((location, index) => {
    const { path } = location;
    const actual = stored.locations?.[index]?.path;
    if (actual !== `./${path}` || !/^[^/:\\@]+:[^/\\]/u.test(path))
      return location;
    qualified.set(path, actual);
    return { ...location, path: actual };
  });
  if (!qualified.size) return false;
  const packages = expected.packages?.map((item) => {
    const path = item.manifest_path && qualified.get(item.manifest_path);
    return path ? { ...item, manifest_path: path } : item;
  });
  return wireJson({ ...expected, locations, packages }) === storedWire;
}

function sameSubmission(
  left: SavedSubmission,
  right: SavedSubmission,
): boolean {
  return (
    left.accountId === right.accountId &&
    left.apiBaseUrl === right.apiBaseUrl &&
    left.inputDigest === right.inputDigest &&
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

async function readOptionalFile(path: string): Promise<string | undefined> {
  return (await readFile(path, "utf8").catch(nullIfMissingFile)) ?? undefined;
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
  const remaining = new Set(batch.items.map((item) => item.client_id));
  if (
    receipt.id !== batch.request_id ||
    wireJson(receipt.repository) !== wireJson(batch.repository) ||
    wireJson(receipt.source) !== wireJson(batch.source) ||
    receipt.item_count !== batch.items.length ||
    receipt.results.length !== batch.items.length ||
    receipt.results.some((item) => !remaining.delete(item.client_id))
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
  const openDatabase = sqliteDatabaseOpener();
  const path = join(state, `${key}.lock.sqlite`);
  const metadata = await lstat(path).catch(nullIfMissingFile);
  if (metadata && !metadata.isFile())
    throw new CodexSecurityError("The publication lock is not a regular file.");
  const lock = openDatabase(path);
  try {
    if (process.platform !== "win32") chmodSync(path, 0o600);
    lock.exec("PRAGMA busy_timeout = 0");
    for (;;) {
      signal?.throwIfAborted();
      try {
        lock.exec("BEGIN EXCLUSIVE");
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
    lock.close();
  }
}

type ResolvedPublicationInput = PublicationSelection & {
  nativeIds?: string[];
  recheckFileRepository?: (
    approvedUrl: string,
    platform?: "other",
  ) => Promise<unknown>;
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

function storedFindingId(finding: ExternalFinding): string {
  const seen = new Set<object>();
  for (
    let owner: object | null = finding;
    owner && !seen.has(owner);
    owner = Object.getPrototypeOf(owner) as object | null
  ) {
    const property = Object.getOwnPropertyDescriptor(
      owner,
      "source_finding_id",
    );
    if (property) {
      const id: unknown = property.value;
      return typeof id === "string" || isStringObject(id)
        ? String.prototype.valueOf.call(id)
        : "";
    }
    seen.add(owner);
  }
  return "";
}

function checkFindingProvider(
  input: Pick<ExternalFindings, "findings" | "report">,
  provider: Provider,
): void {
  function checkFormat(format: unknown) {
    if (format === tenableReportFormat && provider !== "tenable")
      throw new CodexSecurityError(
        "Retained Tenable evidence requires the tenable provider.",
      );
    if (format === guardianSelectionFormat && provider !== "semgrep")
      throw new CodexSecurityError(
        "Use the semgrep provider for Guardian findings.",
      );
  }
  checkFormat(ownData(ownData(input, "report"), "format"));
  if (!Array.isArray(input?.findings)) return;
  for (const row of input.findings) {
    if (!row) continue;
    if (guardianFindingId.test(storedFindingId(row)))
      checkFormat(guardianSelectionFormat);
    checkFormat(ownData(ownData(row.evidence, "source_data"), "format"));
  }
}

export async function prepareExternalPublication(
  path: string,
  options: ExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies = {},
): Promise<PreparedExternalPublication> {
  const settings = snapshotImportOptions(options);
  const readerSources = snapshotSourceRepositories(
    dependencies.sourceRepositories,
  );
  const provider = EXTERNAL_FINDINGS_PROVIDERS[settings.provider];
  let input: PreparePublicationInput;
  let fileRepositories: (() => readonly ExternalSourceRepository[]) | undefined;
  if (settings.provider === "semgrep" || settings.provider === "snyk") {
    const semgrep = settings.provider === "semgrep";
    const report = await (semgrep
      ? readSemgrepReport(path)
      : readSnykReport(path));
    const normalize = async (url?: string, platform?: "other") => {
      const references = hostedSourceReferences(
        readerSources,
        url,
        semgrep ? platform : undefined,
      );
      const semgrepOptions = {
        sourceRepositoryUrl: settings.sourceRepositoryUrl,
        sourceRepositories: references,
      };
      const findings = semgrep
        ? normalizeSemgrepFindings(report, semgrepOptions, "cloud")
        : await normalizeSnykFile(report, "cloud", references);
      return normalizedPublicationInput(findings, provider);
    };
    const hosted =
      isRecord(report) &&
      (semgrep
        ? isSemgrepPlatformFormat(report["format"]) ||
          report["format"] === guardianSelectionFormat
        : isSnykRestFormat(report["format"]));
    if (!semgrep && !hosted)
      fileRepositories = () => snykFileRepositories(report);
    input = hosted
      ? async (destination) => {
          try {
            const projection = await normalize(destination.url);
            if (!semgrep) return projection;
            return {
              ...projection,
              recheckFileRepository: async (approvedUrl, platform) => {
                if (platform === "other")
                  await normalize(approvedUrl, platform);
              },
            };
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
              recheckFileRepository: (approvedUrl, platform) => {
                if (approvedUrl === destination.url) throw error;
                return normalize(approvedUrl, platform);
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
    if (provider === "endor") {
      fileRepositories = () => parsed.sourceRepositories ?? [];
      input.requiresStructuredReport = requiresStructuredEndorReport(
        parsed.findings,
      );
    }
  }
  return preparePublicationInput(
    input,
    { ...settings, provider },
    dependencies,
    readerSources,
    settings.sourceRepositoryUrl,
    path,
    fileRepositories,
  );
}

/** Prepare normalized provider evidence without reading a vendor export. */
export async function prepareNormalizedExternalPublication(
  input: ExternalFindings,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies = {},
): Promise<PreparedExternalPublication> {
  const settings = snapshotImportOptions(options);
  return preparePublicationInput(
    normalizedPublicationInput(input, settings.provider),
    settings,
    dependencies,
    snapshotSourceRepositories(dependencies.sourceRepositories),
    settings.provider === "tenable" ? settings.sourceRepositoryUrl : undefined,
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
    "cloud",
  );
}

/** Verify every source in a hosted selection, including SDK inputs containing typed-only rows. */
function hostedRepositoryMatcher(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: NormalizedExternalPublicationOptions["provider"],
  declaredUrl: string | undefined,
  destination: Pick<ImportRepository, "url">,
  readerSources: readonly ExternalSourceRepository[],
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
      undefined,
      false,
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
  const reportScope = semgrepPlatformReportScope(input, provider, references);
  const hasNativeSource =
    reportScope !== undefined ||
    input.findings.some((finding) =>
      isSemgrepPlatformEvidence(finding, provider),
    );
  const claims = new Set<string>();
  let original =
    input.report?.["format"] === guardianSelectionFormat
      ? declaredScannerRepositoryUrl(input.report["repositoryUrl"], "Guardian")
      : undefined;
  const nativeRows = [];
  for (const finding of input.findings) {
    const typed = finding.evidence.details?.repository?.url;
    if (typed) claims.add(typed);
    const guardian = guardianFindingRepository(finding, "cloud");
    if (guardian) {
      original ??= guardian;
      claims.add(guardian);
      continue;
    }
    const sarif = semgrepSarifRepositories(finding, hasNativeSource);
    for (const { url } of sarif)
      claims.add(hostedRepositoryUrl(url, "Semgrep source repository"));
    nativeRows.push({ finding, sarif });
  }
  const witnesses = semgrepLegacyRepositoryWitnesses(
    nativeRows.map(({ finding }) => finding),
    provider,
    references,
    "cloud",
  );
  for (const { finding, sarif } of nativeRows) {
    const native = semgrepPlatformFindingBinding(
      finding,
      provider,
      references,
      witnesses,
      reportScope,
      [{ url: projectedBlackDuckRepositoryUrl(finding, "cloud") }, ...sarif],
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
  for (const reader of readerSources)
    claims.add(
      normalizeHostedGitRepositoryUrl(
        reader.url,
        source,
        reader.platform !== undefined,
      ),
    );
  for (const url of claims)
    if (!matches(hostedRepositoryUrl(url, "Semgrep source repository")))
      throw new CodexSecurityError(
        "The finding does not match the original Semgrep project repository.",
      );
  return { github: platform === "github", matches };
}

interface PublicationSelection extends ExternalPublicationInput {
  requiresStructuredReport?: boolean;
}

function ownData(value: unknown, key: string) {
  return isRecord(value) && !isProxy(value)
    ? (Object.getOwnPropertyDescriptor(value, key)?.value as unknown)
    : undefined;
}

function publicationIdentity(
  parsed: ExternalFindings,
  provider?: NormalizedExternalPublicationOptions["provider"],
) {
  // For Trivy and Tenable, the checked header binds the repository. Files
  // and normalized rows use the same checkpoint when their findings agree.
  if (
    parsed.report === undefined ||
    (provider === "trivy" && isTrivyReportHeader(parsed.report)) ||
    (provider === "tenable" && parsed.report["format"] === tenableReportFormat)
  )
    return parsed.findings;
  return { findings: parsed.findings, report: reportForJson(parsed.report) };
}

function validatePublicationFindings(parsed: ExternalFindings) {
  validateExternalReport(parsed.report);
  const ids = new Set<string>();
  for (const finding of parsed.findings) {
    const id = finding.source_finding_id;
    if (!id.trim() || id.includes("\0") || Buffer.byteLength(id) > 512)
      throw new CodexSecurityError(
        "Source finding id must contain 1–512 UTF-8 bytes and no NUL characters.",
      );
    if (ids.has(id))
      throw new CodexSecurityError(
        `Duplicate source finding id ${JSON.stringify(id)}.`,
      );
    ids.add(id);
    finding.evidence = validateExternalEvidence(finding.evidence);
  }
}

function normalizedPublicationInput(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: NormalizedExternalPublicationOptions["provider"],
): PublicationSelection {
  const current = snapshotNormalizedFindings(input, undefined, "cloud");
  // Repository and format declarations can be non-enumerable SDK getters.
  for (const key of [
    "sourceFormat",
    "semgrepPlatformScope",
    "snykRestContext",
    ...(provider === "semgrep" || provider === "snyk"
      ? ["sourceRepositoryUrl", "sourceRepositoryPlatform"]
      : []),
  ]) {
    if (
      !(key in current) &&
      !Object.prototype.propertyIsEnumerable.call(input, key) &&
      key in input
    )
      Object.assign(current, {
        [key]: structuredClone(Reflect.get(input, key)),
      });
  }
  const parsed: ExternalFindings & Partial<SnykIssuesFindings> = current;
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
  const markedSemgrep =
    "sourceFormat" in parsed && isSemgrepPlatformFormat(parsed.sourceFormat);
  if (markedSemgrep && provider !== "semgrep")
    throw new CodexSecurityError(
      "Semgrep Platform evidence requires the semgrep provider.",
    );
  if (markedSemgrep || "semgrepPlatformScope" in parsed)
    semgrepPlatformReportScope(parsed, provider);
  validatePublicationFindings(current);
  checkFindingProvider(current, provider);
  return { current, currentIdentity: publicationIdentity(current, provider) };
}

function hostedPublication(
  input: ResolvedPublicationInput,
  provider: "semgrep" | "snyk",
  destination: ImportRepository,
  readerSources: readonly ExternalSourceRepository[],
): ResolvedPublicationInput {
  const current: ExternalFindings & Partial<SnykIssuesFindings> = input.current;
  if (provider === "snyk") {
    const first = current.findings.find(isSnykRestFinding);
    if (!first && current.snykRestContext === undefined) return input;
    const originalUrl =
      current.snykRestContext?.["sourceRepositoryUrl"] ??
      current.sourceRepositoryUrl ??
      first?.evidence.source_data?.["sourceRepositoryUrl"];
    // The original spelling reconstructs a lookup key after a catalog rename.
    // Admission validates the input against the saved approval or live destination.
    const retained = structuredClone(current);
    const references = hostedSourceReferences(
      readerSources,
      typeof originalUrl === "string" ? originalUrl : destination.url,
      current.sourceRepositoryPlatform,
    );
    snykRestImportRepository(
      retained,
      provider,
      [],
      references,
      (finding, source) => {
        finding.evidence.source_data = source;
      },
    );
    return {
      ...input,
      current: retained,
      currentIdentity: publicationIdentity(retained),
      nativeIds: retained.findings.flatMap((row) => {
        const id = snykRestCheckpointFindingId(row, references);
        return id ? [id] : [];
      }),
    };
  }
  const originalRow = (finding: ExternalFindings["findings"][number]) =>
    isRecord(finding.evidence.source_data?.["finding"]) &&
    isSemgrepPlatformEvidence(finding, "semgrep");
  const currentBulkRow = (finding: ExternalFindings["findings"][number]) =>
    finding.evidence.source_data?.["format"] === semgrepPlatformFormat;
  const first =
    current.findings.find(originalRow) ??
    current.findings.find((row) => isSemgrepPlatformEvidence(row, "semgrep"));
  if (!first) return input;
  const reportScope = semgrepPlatformReportScope(current, "semgrep");
  const retained = first.evidence.source_data;
  const project = retained?.["project"];
  const retainedUrl =
    current.sourceRepositoryUrl ??
    retained?.["sourceRepositoryUrl"] ??
    (isRecord(project) ? project["url"] : undefined);
  // A renamed repository may need the original spelling to identify its checkpoint.
  // Preparation validates the unmodified report against the authenticated approval.
  const url = typeof retainedUrl === "string" ? retainedUrl : destination.url;
  const references = hostedSourceReferences(
    readerSources,
    url,
    current.sourceRepositoryPlatform,
  );
  const witnesses = semgrepLegacyRepositoryWitnesses(
    current.findings,
    "semgrep",
    references,
    "cloud",
  );
  const nativeIds: string[] = [];
  const findings = current.findings.map((finding) => {
    if (!isSemgrepPlatformEvidence(finding, "semgrep")) return finding;
    const original = originalRow(finding);
    const binding = semgrepPlatformFindingBinding(
      finding,
      "semgrep",
      references,
      witnesses,
      reportScope,
      undefined,
      "cloud",
    );
    if (binding?.nativeId) nativeIds.push(binding.nativeId);
    // The authenticated repository can make an offline backlog row selectable.
    return binding?.sourceData &&
      (original ||
        (currentBulkRow(finding) &&
          binding.sourceData["format"] !== semgrepPlatformFormat))
      ? {
          ...finding,
          evidence: {
            ...finding.evidence,
            ...binding.migration,
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
    nativeIds,
  };
}

async function preparePublicationInput(
  supplied: PreparePublicationInput,
  options: NormalizedExternalPublicationOptions,
  dependencies: ExternalPublicationDependencies,
  readerSources: readonly ExternalSourceRepository[],
  declaredUrl?: string,
  nativePath?: string,
  fileRepositories?: () => readonly ExternalSourceRepository[],
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
  const environment = dependencies.environment ?? process.env;
  dependencies.signal?.throwIfAborted();
  progress({ phase: "reading", completed: 0 });
  const trivyReportUrls =
    options.provider === "trivy" && typeof supplied !== "function"
      ? trivyBatchSourceUrls(
          supplied.current,
          supplied.current.findings.length > 0,
        )
      : undefined;
  if (trivyReportUrls) validateTrivyRepositoryUrl(options.repository);
  const catalogKey = trivyReportUrls
    ? (url: string) => cloudSourceKey(url, "github")
    : cloudRepositoryUrlKey;
  const state = externalPublicationStateDirectory(environment);
  function pendingFile(key: string) {
    return join(state, `${key}.pending.json`);
  }
  function checkSelection(input: PublicationSelection) {
    const parsed = input.current;
    checkFindingProvider(parsed, options.provider);
    if (options.provider === "tenable" && parsed.findings.length)
      tenableSourceRepository(parsed, declaredUrl, readerSources, "cloud");
    checkTrivyReportProvider(options.provider, parsed.report);
    for (const finding of parsed.findings)
      checkRetainedTrivyProvider(options.provider, finding);
    if (!parsed.findings.length) throw new NoPublishableFindingsError(parsed);
  }
  if (typeof supplied !== "function") checkSelection(supplied);
  progress({ phase: "discovering", completed: 0 });
  const apiBaseUrl = cloudBaseUrl(environment);
  const cloudApiUrl = `${apiBaseUrl}/external`;
  // Validate the configured return destination before authentication or uploads.
  cloudFindingsUrl(environment, options.repository);
  const credentials = await (
    dependencies.credentials ??
    (() => readCloudCredentials(environment, dependencies.signal))
  )();
  let importScope: "personal" | "workspace" | undefined;
  let canStartJob = false;
  async function request(
    endpoint: string,
    body?: FindingImportRequest,
  ): Promise<unknown> {
    dependencies.signal?.throwIfAborted();
    // Allow upload and response transport around the server's publication budget.
    const timeout = AbortSignal.timeout(body ? 60_000 : 30_000);
    const repositoryCatalog = endpoint.startsWith("/repositories?");
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
      const detail = payload?.error?.message ?? response.statusText;
      let message = `Cloud import failed (HTTP ${response.status}).`;
      if (detail) message += ` ${detail}`;
      if (repositoryCatalog && response.status === 404) {
        if (!/[.!?]$/u.test(message)) message += ".";
        message +=
          " Cloud import is not available for this account or deployment.";
      }
      if (retryAfter) message += ` Retry-After: ${retryAfter}.`;
      throw new CloudImportError(response.status, message);
    }
    if (repositoryCatalog) {
      const scope = response.headers.get("Codex-Security-Import-Scope");
      if (
        (scope !== "personal" && scope !== "workspace") ||
        (importScope !== undefined && scope !== importScope)
      )
        throw new CodexSecurityError(
          "Cloud returned an invalid import scope for this account.",
        );
      importScope = scope;
      canStartJob =
        response.headers
          .get("Codex-Security-Private-Import-Providers")
          ?.split(",")
          .some((provider) => provider.trim() === options.provider) ?? false;
    }
    return response.json();
  }
  async function discoverDestination(): Promise<ImportRepository> {
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
            catalogKey(item.url) === catalogKey(options.repository),
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
    if (trivyReportUrls) validateTrivyRepositoryUrl(destination.url);
    return destination;
  }
  const destination = await discoverDestination();
  const deferred = typeof supplied === "function";
  const resolved = deferred ? await supplied(destination) : supplied;
  if (deferred) checkSelection(resolved);
  const report: ExternalFindings & Partial<SnykIssuesFindings> =
    resolved.current;
  const source = { provider: options.provider, source_key: options.sourceKey };
  const sourceReportsPath = sourcePath(destination);
  const hosted = options.provider === "snyk" || options.provider === "semgrep";
  const input =
    options.provider === "snyk" || options.provider === "semgrep"
      ? hostedPublication(
          resolved,
          options.provider,
          destination,
          readerSources,
        )
      : resolved;
  const { current: parsed, currentIdentity, recheckFileRepository } = input;
  const inputDigest = jsonDigest(currentIdentity);
  const scope = [
    ...(apiBaseUrl === DEFAULT_CLOUD_BASE_URL ? [] : [apiBaseUrl]),
    credentials.account_id,
    destination.id,
    destination.repo_connector_id,
    source,
  ];
  const key = jsonDigest([...scope, currentIdentity]);
  const sourceLock = `source-${jsonDigest(scope)}`;
  const semgrepScope =
    options.provider === "semgrep"
      ? semgrepPlatformReportScope(report, "semgrep")
      : undefined;
  const scopeDigest =
    options.provider === "semgrep" &&
    parsed.findings.some(
      (row) =>
        !isSemgrepPlatformEvidence(row, "semgrep") &&
        (semgrepScope?.format ||
          hasRetainedSemgrepScope(row.evidence.source_data?.["finding"])),
    )
      ? jsonDigest(
          semgrepScope?.format
            ? [
                semgrepScope.deployment,
                semgrepScope.projectId,
                semgrepScope.ref,
                semgrepScope.product,
              ]
            : null,
        )
      : undefined;
  const submittedIds = new Set(
    parsed.findings.map((row) => row.source_finding_id),
  );
  const nativeIds = new Set(input.nativeIds);
  const pendingPath = pendingFile(key);
  const resultPath = join(state, `${key}.result.json`);
  const privateClient = privateImportClient(
    apiBaseUrl,
    credentials,
    dependencies.fetch ?? globalThis.fetch,
    dependencies.signal,
  );
  const underPublishLocks = <T>(operation: () => Promise<T>) =>
    withImportLock(state, key, dependencies.signal, operation);
  function matchesSavedDestination(requests: FindingImportRequest[]): boolean {
    return (
      requests.length > 0 &&
      requests.every(
        (batch) =>
          batch.repository.id === destination.id &&
          batch.repository.repo_connector_id ===
            destination.repo_connector_id &&
          wireJson(batch.source) === wireJson(source),
      )
    );
  }
  async function confirmReset() {
    // A newer pending request may have been written while the catalog response
    // was in flight. Confirm the reset after observing this immutable request.
    const confirmed = await discoverDestination();
    if (
      confirmed.id !== destination.id ||
      confirmed.repo_connector_id !== destination.repo_connector_id ||
      confirmed.reset_marker !== destination.reset_marker
    )
      throw new CodexSecurityError(
        "The repository changed while preparing this publication. Review the destination again.",
      );
  }
  const unsupportedCheckpoint =
    "This import has a pending request from another SDK version. Resume it with the original CLI and input before publishing this selection.";
  async function readPending() {
    const serialized = await readOptionalFile(pendingPath);
    if (serialized === undefined) return;
    const content = JSON.parse(serialized) as SavedSubmission;
    if (content?.format !== 1)
      throw new CodexSecurityError(unsupportedCheckpoint);
    if (
      content.apiBaseUrl !== apiBaseUrl ||
      content.accountId !== credentials.account_id ||
      content.inputDigest !== inputDigest ||
      typeof content.approvedRepositoryUrl !== "string" ||
      !Array.isArray(content.requests) ||
      !content.requests.length
    )
      throw new CodexSecurityError(
        "Saved import account, destination or input does not match.",
      );
    if (
      content.semgrepScope !== undefined &&
      content.semgrepScope !== scopeDigest
    )
      throw new CodexSecurityError(
        "The supplied Semgrep report scope does not match the approved request.",
      );
    content.requests = content.requests.map(validateImportRequest);
    const rows = submissionFindings(content.requests);
    if (
      !matchesSavedDestination(content.requests) ||
      jsonDigest(rows) !== content.evidenceDigest ||
      rows.length !== parsed.findings.length ||
      rows.some(
        (row, i) =>
          row.source_finding_id !== parsed.findings[i]!.source_finding_id,
      )
    )
      throw new CodexSecurityError(
        "Saved import evidence does not match the selected input.",
      );
    return content;
  }

  // Older SDKs could store the same approval under another filename. An outstanding
  // request for this source and occurrence must be finished with its original SDK.
  async function checkPendingSource() {
    const entries = await readdir(state, { withFileTypes: true }).catch(
      nullIfMissingFile,
    );

    for (const entry of entries ?? []) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.pending\.json$/u.test(entry.name))
        continue;
      const serialized = await readOptionalFile(join(state, entry.name));
      if (!serialized) continue;
      let prior;
      try {
        prior = JSON.parse(serialized);
      } catch {
        continue;
      }
      if (
        (prior?.format === 1 &&
          (!hosted ||
            (!nativeIds.size &&
              !prior.nativeIds?.length &&
              scopeDigest === undefined &&
              prior.semgrepScope === undefined) ||
            prior.apiBaseUrl !== apiBaseUrl ||
            entry.name === `${key}.pending.json`)) ||
        prior?.accountId !== credentials.account_id ||
        !Array.isArray(prior.requests)
      )
        continue;
      if (
        prior.requests.some(
          (batch: FindingImportRequest) =>
            batch?.repository?.id === destination.id &&
            batch.repository.repo_connector_id ===
              destination.repo_connector_id &&
            batch.source?.provider === source.provider &&
            batch.source.source_key === source.source_key &&
            Array.isArray(batch.items) &&
            (batch.items.some(
              (item) =>
                submittedIds.has(item.source_finding_id) ||
                nativeIds.has(item.source_finding_id),
            ) ||
              (Array.isArray(prior.nativeIds) &&
                prior.nativeIds.some(
                  (id: string) => nativeIds.has(id) || submittedIds.has(id),
                ))),
        )
      )
        throw new CodexSecurityError(
          prior.format === 1
            ? "This source has a pending hosted Cloud request for the same finding. Finish that approved request before changing its evidence."
            : unsupportedCheckpoint,
        );
    }
  }
  async function readCompletedPublication(requests: FindingImportRequest[]) {
    const serialized = await readOptionalFile(resultPath);
    if (serialized === undefined) return;
    const completed = JSON.parse(serialized) as ExternalPublicationResult;
    if (
      (completed?.status === "complete" || completed?.status === "partial") &&
      completed.receipts?.length === requests.length &&
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
  const saved = await readPending();
  if (!saved) await checkPendingSource();
  if (
    saved?.requests.some(
      ({ repository }) => repository.reset_marker !== destination.reset_marker,
    )
  ) {
    await underPublishLocks(async () => {
      await confirmReset();
      const current = await readPending();
      if (current && sameSubmission(current, saved)) await rm(pendingPath);
    });
    throw new CloudImportError(
      409,
      "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.",
    );
  }
  if (saved?.inspectorProjectMapRequired && !inspectorProjectMap)
    throw new CodexSecurityError(
      "Supply the verified Inspector project binding again to resume.",
    );

  // Existing repository submissions keep their original request bodies and receipts.
  const privatePath = join(state, `${key}.private-import.json`);
  const privateSaved = await readOptionalFile(privatePath);
  const usePrivateImport = importScope === "workspace";
  if (
    (usePrivateImport && saved) ||
    (!usePrivateImport && privateSaved !== undefined)
  )
    throw new CodexSecurityError(
      "The saved import belongs to a different Cloud destination. Use the account and scope shown in its preview.",
    );
  if (usePrivateImport && !canStartJob && privateSaved === undefined)
    throw new CodexSecurityError(
      "Private findings import is unavailable for this account or provider.",
    );
  async function preparePrivateAttempt() {
    const context = await privateClient.context();
    if (source.source_key.trim() !== source.source_key)
      throw new CodexSecurityError(
        "A private source key cannot have leading or trailing whitespace.",
      );
    const report = await selectPrivateReport(
      parsed,
      source.provider,
      nativePath,
      context,
      privateSaved,
      resolved.requiresStructuredReport,
    );
    const binding = {
      format: report.format,
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
    return { context, report, binding };
  }
  function acceptsJob(
    context: PrivateImportContext,
    format: PrivateImportFormat,
  ) {
    return context.can_create_import_jobs && context.formats.includes(format);
  }
  // Use an earlier catalog URL only after the account, connector, repository,
  // inbox context and exact upload digest all match the immutable checkpoint.
  const existingPrivate =
    usePrivateImport && privateSaved !== undefined
      ? await preparePrivateAttempt()
      : undefined;
  const previous =
    existingPrivate &&
    readPrivateCheckpoint(privateSaved, existingPrivate.binding);
  const retryOfJobId =
    unsuccessfulJob(previous?.receipt) &&
    canStartJob &&
    existingPrivate?.context.can_upload &&
    acceptsJob(existingPrivate.context, existingPrivate.report.format)
      ? previous?.jobId
      : undefined;
  const resumed = previous !== undefined && retryOfJobId === undefined;
  const privateApproval = resumed ? previous : undefined;
  const privateUrl = privateApproval?.approvedRepositoryUrl;
  const approvedPlatform =
    saved?.approvedRepositoryPlatform ??
    privateApproval?.approvedRepositoryPlatform;

  // Supplemental repository declarations must agree with the source approved for these bytes.
  const sourceFor = (url: string, platform?: "other") =>
    hostedRepositoryMatcher(
      platform ? { ...report, sourceRepositoryPlatform: platform } : report,
      options.provider,
      declaredUrl,
      { url },
      readerSources,
    );
  const approvedUrl =
    saved?.approvedRepositoryUrl ?? privateUrl ?? destination.url;
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
  await recheckFileRepository?.(approvedUrl, approvedPlatform);
  const hostedSource = hosted
    ? sourceFor(approvedUrl, approvedPlatform)
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

  const trivyTarget = approvedUrl;
  function requireTrivyRemote(url: string, id?: string) {
    if (trivyRemoteKey(url, trivyTarget) !== catalogKey(trivyTarget)) {
      const label =
        id === undefined ? "Source report" : `Finding ${JSON.stringify(id)}`;
      throw new CodexSecurityError(
        `${label} belongs to ${JSON.stringify(url)}, which does not match the selected Cloud repository ${JSON.stringify(trivyTarget)}. Verify the source repository mapping before publishing.`,
      );
    }
  }
  if (trivyReportUrls) {
    for (const url of trivyReportUrls) requireTrivyRemote(url);
    if (parsed !== resolved.current)
      for (const url of trivyBatchSourceUrls(parsed, true))
        requireTrivyRemote(url);
  }

  function checkRepositories({
    findings,
    report,
  }: Pick<ExternalFindings, "findings" | "report">) {
    const { provider } = options;
    checkFindingProvider({ findings, report }, provider);
    if (provider === "tenable") {
      const source = tenableSourceRepository(
        { findings, report },
        declaredUrl,
        readerSources,
        "cloud",
      );
      if (catalogKey(source.url) !== catalogKey(approvedUrl))
        throw new CodexSecurityError(
          "Tenable's source repository does not match the selected Cloud repository.",
        );
    }
    checkTrivyReportProvider(provider, report);
    const sameCatalog =
      hosted &&
      cloudSourceKey(approvedUrl, "github") ===
        cloudSourceKey(destination.url, "github");
    const liveUrl = sameCatalog ? approvedUrl : (privateUrl ?? destination.url);
    const comparisonKey =
      sameCatalog && approvedPlatform === "other"
        ? (url: string) => cloudSourceKey(url, undefined)
        : catalogKey;
    function requireDestination(
      id: string,
      url: string | null | undefined,
      expected = liveUrl,
    ) {
      if (
        url &&
        (matchesHostedRepository
          ? !matchesHostedRepository(url) || !matchesHostedRepository(expected)
          : comparisonKey(url) !== comparisonKey(expected))
      )
        throw new CodexSecurityError(
          `Finding ${JSON.stringify(id)} belongs to ${JSON.stringify(url)}, which does not match the selected Cloud repository ${JSON.stringify(destination.url)}. Verify the source repository mapping before publishing.`,
        );
    }
    if (report?.["format"] === guardianSelectionFormat)
      requireDestination(
        "Guardian source",
        declaredScannerRepositoryUrl(report["repositoryUrl"], "Guardian"),
        approvedUrl,
      );
    // Extra file declarations cannot authorize new rows in an immutable request.
    if (!saved)
      for (const { url } of fileRepositories?.() ?? [])
        requireDestination(
          "Source report",
          provider === "snyk"
            ? normalizeHostedGitRepositoryUrl(url, approvedUrl, true)
            : url,
        );
    for (const url of sonarRepositoryUrls(provider, findings, report, "cloud"))
      requireDestination("Sonar source", url);
    const checkmarx = checkmarxSelection(provider, findings, report, "cloud");
    requireDestination("Checkmarx source", checkmarx.reportUrl);
    const blackDuck = blackDuckReportRepositories(provider, findings, "cloud");
    const checkmarxRepository = checkmarx.repositories();
    for (const repositories of [
      veracodeReportRepositories,
      continuumReportRepositories,
    ])
      for (const [id, source] of repositories(provider, findings, "cloud"))
        requireDestination(id, source.url);
    const inspector = inspectorReportRepository(
      provider,
      findings,
      "cloud",
      inspectorProjectMap,
    );
    if (inspector) requireDestination(inspector.findingId, inspector.url);
    for (const finding of findings) {
      const { source_finding_id: id, evidence } = finding;
      const guardian = guardianFindingRepository(finding, "cloud");
      if (guardian) {
        requireDestination(id, guardian, approvedUrl);
        requireDestination(id, evidence.details?.repository?.url, approvedUrl);
      }
      checkRetainedTrivyProvider(provider, finding);
      if (trivyReportUrls) {
        const remote = trivyRepositoryUrl(
          retainedTrivyReport(finding),
          trivyTarget,
        );
        if (remote) requireTrivyRemote(remote, id);
      }
      const blackDuckUrl = blackDuck
        ? blackDuck.get(id)?.url
        : projectedBlackDuckRepositoryUrl(finding, "cloud");
      const hasProjection =
        !!blackDuckUrl || checkmarx.projections.has(finding);
      let urls = [
        blackDuckUrl,
        checkmarxRepository(finding)?.url,
        evidence.details?.repository?.url,
      ];
      if (provider === "wiz") {
        const native =
          hasProjection || isWizPackageFinding(evidence.source_data);
        urls.push(
          native
            ? wizFindingRepository(evidence, "cloud")?.url
            : wizCsvRepositoryUrl(evidence),
        );
      } else if (provider === "snyk") {
        urls = urls.concat(
          snykRepositoryUrls(evidence.source_data, {
            cloudRepositoryUrl: approvedUrl,
          }),
        );
      } else if (provider === "endor") {
        urls = urls.concat(
          endorRepositoryUrls(
            evidence.source_data,
            !blackDuck && !blackDuckUrl,
          ),
        );
      } else if (provider === "github") {
        urls.push(retainedGitHubRepository(finding));
        urls.push(dependabotRepository(finding));
      }
      const verifyLive =
        hasProjection ||
        [
          "blackduck",
          "inspector",
          "veracode",
          "checkmarx",
          "continuum",
          "sonar",
        ].includes(provider);
      for (const url of urls)
        requireDestination(id, url, verifyLive ? liveUrl : approvedUrl);
    }
  }
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
  if (!usePrivateImport) {
    checkRepositories(parsed);
    if (
      saved &&
      saved.evidenceDigest !== jsonDigest(parsed.findings.map(wireFinding))
    ) {
      if (options.provider !== "wiz" || !nativePath)
        throw new CodexSecurityError(
          "Saved import evidence does not match the selected input.",
        );
      checkRepositories({
        ...parsed,
        findings: submissionFindings(saved.requests),
      });
    }
  }
  if (usePrivateImport) {
    const client = privateClient;
    const { context, report, binding } =
      existingPrivate ?? (await preparePrivateAttempt());
    function requireAccess(value: typeof context, saved: typeof previous) {
      if (
        !value.can_read ||
        (!saved && !canStartJob) ||
        (!saved?.jobId &&
          ((!saved?.fileId && !value.can_upload) ||
            !acceptsJob(value, report.format)))
      )
        throw new CodexSecurityError(
          "Private findings import is unavailable for this account or report format.",
        );
    }
    checkRepositories(parsed);
    requireAccess(context, previous);
    const privateImport = {
      format: report.format,
      contextVersion: binding.contextVersion,
      sha256: report.digest,
      bytes: Buffer.byteLength(report.bytes),
      ...(retryOfJobId ? { retryOfJobId } : {}),
    };
    const preview: ExternalPublicationPreview = {
      ...parsed,
      cloudApiUrl: `${apiBaseUrl}/finding-imports`,
      accountId: credentials.account_id,
      destination,
      source,
      resumed,
      requests: [],
      privateImport,
    };
    return {
      preview: structuredClone(preview),
      publish: () =>
        underPublishLocks(async () => {
          const current = await client.context();
          if (current.context_version !== binding.contextVersion)
            throw new CodexSecurityError(
              "The private inbox changed. Run the command again to review the new destination.",
            );
          const stored = readPrivateCheckpoint(
            await readOptionalFile(privatePath),
            binding,
          );
          if (resumed && !stored)
            throw new CodexSecurityError(
              "The saved private import changed. Run the command again to preview this report.",
            );
          // Only a preview of this terminal job can start a new attempt.
          const retrying =
            retryOfJobId !== undefined && stored?.receipt?.id === retryOfJobId;
          const active = retrying ? undefined : stored;
          requireAccess(current, active);
          if (await readPending())
            throw new CodexSecurityError(
              "A repository submission is pending. Review its saved request before continuing.",
            );
          const checkpoint = active ?? {
            ...binding,
            approvedRepositoryUrl: destination.url,
            approvedRepositoryPlatform:
              hostedSource?.github === false ? ("other" as const) : undefined,
            uploadRequestId: randomUUID(),
            jobRequestId: randomUUID(),
            fileId: undefined,
            jobId: undefined,
            receipt: undefined,
            previousReceipt: retrying ? stored?.receipt : undefined,
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
          function acknowledge(job: PrivateImportJob) {
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
            result.privateJob = job;
            result.counts = { created, updated, unchanged, error };
            result.unacknowledged = result.ready - processed;
            result.status =
              job.status === "completed" && !error && !parsed.excluded.length
                ? "complete"
                : "partial";
            if (job.error) result.error = job.error.message;
            else delete result.error;
          }
          try {
            const savedReceipt =
              checkpoint.receipt ?? checkpoint.previousReceipt;
            if (savedReceipt) acknowledge(savedReceipt);
            if (!active) await writeAtomicJson(privatePath, checkpoint);
            if (!checkpoint.fileId) {
              progress({ phase: "uploading", completed: 0 });
              checkpoint.fileId = await client.upload({
                requestId: checkpoint.uploadRequestId,
                contextVersion: binding.contextVersion,
                ...report,
                recovering: active !== undefined,
              });
              await writeAtomicJson(privatePath, checkpoint);
            }
            progress({ phase: "verifying", completed: 0 });
            const job = await client.job(
              {
                requestId: checkpoint.jobRequestId,
                contextVersion: binding.contextVersion,
                fileId: checkpoint.fileId,
                format: report.format,
                source,
                repository: binding.repository,
                jobId: checkpoint.jobId,
              },
              async (id) => {
                checkpoint.jobId = id;
                await writeAtomicJson(privatePath, checkpoint);
              },
            );
            acknowledge(job);
            checkpoint.jobId = job.id;
            checkpoint.receipt = job;
            await writeAtomicJson(privatePath, checkpoint);
            return result;
          } catch (error) {
            result.status = "interrupted";
            result.error =
              error instanceof Error ? error.message : String(error);
            result.savedSubmission = privatePath;
            throw new ExternalPublicationError(result.error, result, error);
          }
        }),
    };
  }

  if (!parsed.findings.length) throw new NoPublishableFindingsError(parsed);
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
    format: 1,
    apiBaseUrl,
    accountId: credentials.account_id,
    requests,
    receipts: saved?.receipts,
    inputDigest,
    evidenceDigest: jsonDigest(submissionFindings(requests)),
    semgrepScope: scopeDigest,
    nativeIds: nativeIds.size ? [...nativeIds] : undefined,
    approvedRepositoryUrl: approvedUrl,
    approvedRepositoryPlatform:
      approvedPlatform ??
      (hostedSource && !hostedSource.github ? "other" : undefined),
    inspectorProjectMapRequired: inspectorProjectMap ? true : undefined,
  };
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
      return await underPublishLocks(async () => {
        acquired = true;
        let pending = await readPending().catch((error: unknown) => {
          if (!submission.receipts?.length) throw error;
          throw interruptedPreview(errorMessage(error), error);
        });
        if (!pending || !sameSubmission(pending, submission)) {
          const completed = await readCompletedPublication(requests);
          if (completed) return result(completed.receipts, completed.verified);
          if (saved || pending)
            throw interruptedPreview(
              pending
                ? "Another publication prepared this input. Run the command again to review and resume that saved request."
                : "The saved publication changed after preview. Review its result before publishing again.",
            );
          if ((await readOptionalFile(privatePath)) !== undefined)
            throw new CodexSecurityError(
              "A private import already owns this selection. Review its saved job before continuing.",
            );
        }
        const current = pending ?? submission;
        if (current.inspectorProjectMapRequired && !inspectorProjectMap)
          throw new CodexSecurityError(
            "Supply the verified Inspector project binding again to resume.",
          );
        const tightenBinding =
          (submission.inspectorProjectMapRequired &&
            !current.inspectorProjectMapRequired) ||
          (submission.approvedRepositoryPlatform === "other" &&
            !current.approvedRepositoryPlatform);
        if (submission.inspectorProjectMapRequired)
          current.inspectorProjectMapRequired = true;
        if (submission.approvedRepositoryPlatform)
          current.approvedRepositoryPlatform =
            submission.approvedRepositoryPlatform;
        requireApprovedSource(
          current.approvedRepositoryUrl,
          current.approvedRepositoryPlatform,
        );
        const cached = (current.receipts ?? []).map(validateImportReceipt);
        if (cached.length > requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged: FindingImportReceipt[] = [];
        let verified = 0;
        try {
          if (!pending) {
            const save = async () => {
              await checkPendingSource();
              await writeAtomicJson(pendingPath, current);
            };
            if (hosted)
              await withImportLock(
                state,
                sourceLock,
                dependencies.signal,
                save,
              );
            else await save();
            pending = current;
          } else if (tightenBinding) {
            await writeAtomicJson(pendingPath, current);
          }
          progress({
            phase: "uploading",
            completed: 0,
            total: parsed.findings.length,
          });
          let acknowledgedCount = 0;
          for (const [batchIndex, batch] of requests.entries()) {
            const receipt = validatePublicationReceipt(
              cached[batchIndex] ?? (await request("/finding_imports", batch)),
              batch,
            );
            acknowledged.push(receipt);
            acknowledgedCount += receipt.item_count;
            progress({
              phase: "uploading",
              completed: acknowledgedCount,
              total: parsed.findings.length,
            });
            if (batchIndex >= cached.length) {
              // Acknowledged batches must not consume another POST quota on retry.
              // Readback can still resume after this checkpoint without replaying writes.
              await writeAtomicJson(pendingPath, {
                ...current,
                receipts: acknowledged,
              });
            }
          }
          // Verify readable source records without mistaking a newer concurrent
          // observation for failure of the original, immutable import receipt.
          const readbacks = acknowledged.flatMap((receipt, batchIndex) => {
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
                  !matchesRepositoryEvidence(
                    expected.evidence,
                    report.evidence,
                  ))) ||
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
          await writeAtomicJson(resultPath, {
            ...completed,
            report: reportForJson(completed.report),
          });
          await rm(pendingPath, { force: true });
          return completed;
        } catch (error) {
          if (error instanceof CloudImportError && error.status === 409) {
            await rm(pendingPath, { force: true });
            pending = undefined;
          }
          const message = `${error instanceof Error ? error.message : String(error)} ${error instanceof CloudImportError && error.status === 409 ? "The old submission was retired. Rediscover and approve a fresh publication." : pending ? `Repeat the same command to resume the saved request. Saved submission: ${pendingPath}` : "No resumable request was saved. Correct the error and review the input before retrying."}`;
          throw new ExternalPublicationError(
            message,
            {
              ...result(acknowledged, verified),
              status: "interrupted",
              error: message,
              ...(pending ? { savedSubmission: pendingPath } : {}),
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
