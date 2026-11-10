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
import {
  isBoxedPrimitive,
  isNativeError,
  isProxy,
  isStringObject,
} from "node:util/types";
import {
  privateImportClient,
  privateJobVersions,
  selectPrivateReport,
  type PrivateImportFormat,
  readPrivateCheckpoint,
  parsePrivateCheckpoint,
  type PrivateImportContext,
  unsuccessfulJob,
  type PrivateImportJob,
} from "./private-finding-import.js";
import { readCloudCredentials } from "./cloud-publish.js";
import type { LocalExternalImportOptions } from "./external-findings-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import { tenableReportFormat } from "./tenable-findings.js";
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
  type RuntimeDatabase,
} from "./runtime.js";
import {
  EXTERNAL_FINDINGS_PROVIDERS,
  readExternalFindings,
  requireCloudReader,
  semgrepSarifRepositories,
  snykFileRepositories,
  type CloudFindingsReader,
} from "./external-findings-read.js";
import {
  canSnapshotWithoutGetters,
  canonicalJson,
  isRecord,
} from "./record.js";
import { notify } from "./value.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { isWizPackageFinding, wizFindingRepository } from "./wiz-findings.js";
import { getOpenGrepSourcePositions } from "./opengrep-findings.js";
import {
  previousReaderSelection,
  hasPreviousCloudProjection,
} from "./reader-selection.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import { retainedGitHubRepository } from "./github-findings.js";
import {
  normalizePreviousSemgrepFindings,
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
  parseSemgrepResponse,
  semgrepLegacyRepositoryWitnesses,
  semgrepNativeProjectUrl,
  semgrepPlatformFindingBinding,
  semgrepPlatformRepositoryReference,
  semgrepPlatformReportScope,
} from "./semgrep-platform-findings.js";
import { semgrepV1Id } from "./semgrep-platform-v1.js";
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
  nativeErrorStackGetter,
  snapshotNormalizedFindings,
  type ExternalFinding,
  type ExternalFindings,
  type ExternalPublicationInput,
} from "./external-findings.js";
import {
  canonicalNumber,
  cloudRepositoryUrlKey,
  CloudEvidenceDepthError,
  validateImportRequest,
  validateExternalEvidence,
  validatePreviousCloudEvidence,
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
  /** Full Inspector project ARNs mapped to independently verified repository URLs. */
  inspectorProjectMap?: ReadonlyMap<string, string>;
}

/** File readers accepted by the Cloud publisher. */
export interface ExternalPublicationOptions extends LocalExternalImportOptions {
  provider: CloudFindingsReader;
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
  accountId: string;
  trivyRepositoryUrl?: string;
  requests: FindingImportRequest[];
  receipts?: FindingImportReceipt[];
  inputProjection?: {
    repositorySeverities?: string[];
    retainedHostedSelection?: true;
    semgrepPartialScopeDigest?: string;
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
  /** Catalog URL when this source selection was approved, before any repository rename. */
  approvedRepositoryUrl?: string;
  approvedRepositoryPlatform?: "other";
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

function jsonDigest(value: unknown, serialize = wireJson): string {
  return hash("sha256", serialize(value));
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

function isCompleteUnscoredOpenGrepReport(report: ExternalFindings) {
  let rows = report.excluded.length;
  for (const { evidence } of report.findings) {
    const traces = evidence.source_data?.["results"];
    if (
      evidence.details?.scanner_origin !== "OpenGrep" ||
      evidence.severity !== "unknown" ||
      !Array.isArray(traces)
    )
      return false;
    rows += traces.length;
  }
  return rows === report.read;
}

function repositoryFindings(
  report: ExternalFindings,
  severities: readonly string[] | undefined,
) {
  return severities
    ? report.findings.filter(({ evidence }) =>
        severities.includes(evidence.severity),
      )
    : report.findings;
}

function repositorySelection(
  report: ExternalFindings,
  severities: readonly string[] | undefined,
  sourcePositions: PublicationSelection["sourcePositions"],
): ExternalFindings {
  const findings = repositoryFindings(report, severities);
  if (findings.length === report.findings.length) return report;
  const excluded = [...report.excluded];
  const skipped = new Set(excluded.map(({ position }) => position));
  function exclude(position: number, id: string | null, severity: string) {
    excluded.push({
      position,
      source_finding_id: id,
      reason: `The repository publisher does not accept severity ${JSON.stringify(severity)}. A local import or an available private inbox can retain this finding.`,
    });
  }
  // Serialized OpenGrep selections retain every trace but lose the reader's
  // position map. All these traces have unknown severity, so the remaining
  // source rows are provably excluded even when their individual IDs are lost.
  if (!sourcePositions && isCompleteUnscoredOpenGrepReport(report)) {
    const id =
      report.findings.length === 1
        ? report.findings[0]!.source_finding_id
        : null;
    for (let row = 1; row <= report.read; row++)
      if (!skipped.has(row)) exclude(row, id, "unknown");
  } else {
    const retained = new Set(findings);
    let position = 0;
    for (const finding of report.findings) {
      do {
        position++;
      } while (skipped.has(position));
      if (retained.has(finding)) continue;
      const { source_finding_id, evidence } = finding;
      for (const row of sourcePositions?.get(source_finding_id) ?? [position])
        exclude(row, source_finding_id, evidence.severity);
    }
  }
  return {
    ...report,
    findings,
    excluded: excluded.sort((a, b) => a.position - b.position),
  };
}

function sameSubmission(
  left: SavedSubmission,
  right: SavedSubmission,
): boolean {
  return (
    left.accountId === right.accountId &&
    left.trivyRepositoryUrl === right.trivyRepositoryUrl &&
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

function sameLegacyJson(
  saved: unknown,
  current: unknown,
  equivalent: (saved: unknown, current: unknown) => boolean,
): boolean {
  if (saved === current || equivalent(saved, current)) return true;
  if (Array.isArray(saved) && Array.isArray(current))
    return (
      saved.length === current.length &&
      saved.every((child, i) => sameLegacyJson(child, current[i], equivalent))
    );
  if (!isRecord(saved) || !isRecord(current)) return false;
  return (
    Object.keys(current).every((key) => Object.hasOwn(saved, key)) &&
    Object.keys(saved).every((key) =>
      sameLegacyJson(saved[key], current[key], equivalent),
    )
  );
}

// A copied reader result can retain the JSON from Buffer.toJSON but lose
// the native Buffer that the previous reader cloned into a Uint8Array.
function previousBufferJson(saved: unknown, current: unknown): boolean {
  if (
    !isRecord(current) ||
    current["type"] !== "Buffer" ||
    !Array.isArray(current["data"])
  )
    return false;
  return (
    isRecord(saved) &&
    Object.keys(current).length === 2 &&
    Object.keys(saved).length === current["data"].length &&
    current["data"].every(
      (byte, index) =>
        Number.isInteger(byte) &&
        byte >= 0 &&
        byte <= 255 &&
        saved[index] === byte,
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
  const openDatabase = sqliteDatabaseOpener();
  const guards: RuntimeDatabase[] = [];
  try {
    for (const key of [...new Set(keys)].sort()) {
      const path = join(state, `${key}.lock.sqlite`);
      const metadata = await lstat(path).catch(nullIfMissingFile);
      if (metadata && !metadata.isFile())
        throw new CodexSecurityError(
          "The publication lock is not a regular file.",
        );
      const guard = openDatabase(path);
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

type ResolvedPublicationInput = PublicationSelection & {
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
  input: ExternalFindings,
  provider: Provider,
): void {
  function checkFormat(format: unknown) {
    if (format === tenableReportFormat)
      requireCloudReader({ provider: "tenable" });
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
  requireCloudReader(settings);
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
      const selection = normalizedPublicationInput(findings, provider);
      if (semgrep && hasPreviousCloudProjection(findings))
        selection.readPreviousFindings = () =>
          normalizePreviousSemgrepFindings(report, semgrepOptions);
      return selection;
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
    checkFindingProvider(parsed.findings, provider);
    input =
      parsed.publication ??
      normalizedPublicationInput(parsed.findings, provider);
    input.readPreviousFindings = parsed.previousFindings;
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
  requireCloudReader(settings);
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
      undefined,
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
    const data = finding.evidence.source_data;
    const sarif = semgrepSarifRepositories(finding, hasNativeSource);
    for (const { url } of sarif)
      claims.add(hostedRepositoryUrl(url, "Semgrep source repository"));
    const project = data?.["project"];
    if (
      !allowOpaqueLegacyRows ||
      !isSemgrepPlatformEvidence(finding, provider) ||
      (isRecord(project) &&
        project["id"] != null &&
        project["name"] != null &&
        data?.["deployment"] != null &&
        data["ref"] != null &&
        data["product"] != null &&
        ((isRecord(data["finding"]) && data["finding"]["id"] != null) ||
          typeof data["semgrepPlatformFindingJson"] === "string"))
    ) {
      nativeRows.push({ finding, sarif });
      continue;
    }
    // Released SDKs could save partial native records. Retain any source still
    // identifiable on that row while validating complete siblings under the new mapping.
    if (!data) continue;
    if (reportScope?.projectId !== undefined) {
      const id = isRecord(project) ? project["id"] : undefined;
      if (
        (id != null &&
          id !== reportScope.projectId &&
          semgrepV1Id(id) !== reportScope.projectId) ||
        (["deployment", "ref", "product"] as const).some(
          (field) => data[field] != null && data[field] !== reportScope[field],
        )
      )
        throw new CodexSecurityError(
          "The retained Semgrep finding does not match the supplied report scope.",
        );
    }
    const rows = [data["finding"]];
    const raw = data["semgrepPlatformFindingJson"];
    if (typeof raw === "string") {
      try {
        rows.push(parseSemgrepResponse(raw));
      } catch {
        // An unreadable historical row contributes no URL. Check the remaining claims.
      }
    }
    const nativeUrls = [isRecord(project) ? project["url"] : undefined];
    if (data["format"] === semgrepPlatformFormat)
      nativeUrls.push(data["nativeProjectUrl"]);
    for (const row of rows) {
      if (!isRecord(row)) continue;
      if (
        reportScope?.ref !== undefined &&
        row["ref"] !== undefined &&
        row["ref"] !== reportScope.ref
      )
        throw new CodexSecurityError(
          "The retained Semgrep finding does not match the supplied report scope.",
        );
      const repository = row["repository"];
      if (isRecord(repository)) nativeUrls.push(repository["url"]);
    }
    const urls = nativeUrls.map((url) =>
      semgrepNativeProjectUrl(url, references),
    );
    for (const url of [...urls, data["sourceRepositoryUrl"]]) {
      if (typeof url !== "string") continue;
      original ??= url;
      claims.add(url);
    }
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
      allowOpaqueLegacyRows,
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
  sourcePositions?: ReadonlyMap<string, readonly number[]>;
  readPreviousFindings?: () => ExternalFindings;
  original?: {
    parsed: ExternalFindings;
    identity: unknown;
    wire: string;
    hasBoxedScalars: boolean;
  };

  potentialIds?: (string | undefined)[] | null;
  uncertainFindingIds?: string[];
  unprovenOccurrenceCount?: number;
  knownFindings?: ExternalFindings["findings"];
  unprovenIdPrefixes?: string[];
  freshError?: Error;
}

function ownData(value: unknown, key: string) {
  return isRecord(value) && !isProxy(value)
    ? (Object.getOwnPropertyDescriptor(value, key)?.value as unknown)
    : undefined;
}

// When native capture would invoke caller code, only the original data
// properties can identify the earlier selection. Unknown IDs cannot rule it out.
function previousFindingIds(
  input: ExternalFindings,
): (string | undefined)[] | null {
  const rows = ownData(input, "findings");
  if (!Array.isArray(rows) || isProxy(rows)) return null;
  return Array.from({ length: rows.length }, (_, index) => {
    const row: unknown = Object.getOwnPropertyDescriptor(rows, index)?.value;
    const id = ownData(row, "source_finding_id");
    return typeof id === "string" ? id : undefined;
  });
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
const nativeDiagnosticPrototypes = new Set<unknown>([
  Error.prototype,
  EvalError.prototype,
  RangeError.prototype,
  ReferenceError.prototype,
  SyntaxError.prototype,
  TypeError.prototype,
  URIError.prototype,
]);

function previousDiagnosticMessage(diagnostic: Error): string | undefined {
  const stack = Object.getOwnPropertyDescriptor(diagnostic, "stack");
  const message = ownData(diagnostic, "message");
  const cause = Object.getOwnPropertyDescriptor(diagnostic, "cause");
  const name = Object.getOwnPropertyDescriptor(diagnostic, "name");
  if (
    !nativeDiagnosticPrototypes.has(Object.getPrototypeOf(diagnostic)) ||
    typeof message !== "string" ||
    (stack?.get && stack.get !== nativeErrorStackGetter) ||
    (name && typeof name.value !== "string") ||
    (cause &&
      (!Object.hasOwn(cause, "value") ||
        !canSnapshotWithoutGetters(cause.value)))
  )
    return;
  return message;
}

function previousDiagnosticInput(
  input: ExternalFindings,
  nativeDiagnostics: Map<number, Error>,
): ExternalFindings {
  const report = ownData(input, "report");
  const errors = ownData(report, "errors");
  if (!isRecord(report) || !Array.isArray(errors) || isProxy(errors))
    return input;
  let entries: PropertyDescriptorMap | undefined;
  for (let index = 0; index < errors.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(errors, index);
    const diagnostic: unknown = descriptor?.value;
    if (!descriptor || !isNativeError(diagnostic)) continue;
    const message = previousDiagnosticMessage(diagnostic);
    if (message === undefined) return input;
    nativeDiagnostics.set(index, diagnostic);
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
  nativeDiagnostics: Map<number, Error>,
  observe: (value: object) => void,
): ExternalFindings | undefined {
  input = previousDiagnosticInput(input, nativeDiagnostics);
  if (!canSnapshotWithoutGetters(input, observe)) return;
  // Object spread skips a hidden report, but explicitly reading it could run a getter.
  const reportField = Object.getOwnPropertyDescriptor(input, "report");
  if (reportField && !Object.hasOwn(reportField, "value")) return;
  const { report, ...parsed } = input;
  const snapshot: ExternalFindings = structuredClone(parsed);
  if (report !== undefined) snapshot.report = structuredClone(report);
  return snapshot;
}

function publicationIdentity(
  parsed: ExternalFindings,
  provider?: NormalizedExternalPublicationOptions["provider"],
) {
  // For Trivy, the independently checked header binds the repository. Files
  // and normalized rows use the same checkpoint when their findings agree.
  if (
    parsed.report === undefined ||
    (provider === "trivy" && isTrivyReportHeader(parsed.report))
  )
    return parsed.findings;
  return { findings: parsed.findings, report: reportForJson(parsed.report) };
}

function validatePublicationFindings(
  parsed: ExternalFindings,
  validateEvidence: typeof validateExternalEvidence,
) {
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
    finding.evidence = validateEvidence(finding.evidence);
  }
}

function historicalPublication(
  native: ExternalFindings | undefined,
): PublicationSelection["original"] {
  if (!native) return;
  try {
    // Older SDKs detached all raw records before Cloud validation added defaults.
    for (const finding of native.findings)
      if (finding.evidence.source_data !== undefined)
        finding.evidence.source_data = structuredClone(
          finding.evidence.source_data,
        );
    validatePublicationFindings(native, validatePreviousCloudEvidence);
    const identity = publicationIdentity(native);
    let hasBoxedScalars = false;
    const wire = canonicalJson(identity, undefined, (value) => {
      if (!isBoxedPrimitive(value)) return false;
      hasBoxedScalars = true;
      return true;
    });
    return { parsed: native, identity, wire, hasBoxedScalars };
  } catch {
    // The caller may export valid JSON even if the native candidate cannot be
    // validated or hashed, for example when an unused row property holds a BigInt.
    return;
  }
}

function normalizedPublicationInput(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: NormalizedExternalPublicationOptions["provider"],
): PublicationSelection {
  const nativeDiagnostics = new Map<number, Error>();
  let native: ExternalFindings | undefined;
  let plainJson = true;
  try {
    native = previousNormalizedFindings(input, nativeDiagnostics, (value) => {
      if (!plainJson) return;
      const prototype = Object.getPrototypeOf(value);
      plainJson =
        (prototype === null ||
          prototype === Object.prototype ||
          prototype === Array.prototype) &&
        !("toJSON" in value);
    });
  } catch {
    /* A valid JSON export can contain an uncloneable value. */
  }
  let priorIds = native ? undefined : previousFindingIds(input);
  let current: ExternalFindings;
  let freshError: Error | undefined;
  try {
    current = snapshotNormalizedFindings(input, undefined, "cloud");
  } catch (error) {
    if (
      (!isNativeError(error) && !(error instanceof Error)) ||
      !native?.findings.length
    )
      throw error;
    freshError = error;
    current = { read: native.read, findings: [], excluded: [] };
  }
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
  if (native && nativeDiagnostics.size) {
    const historical = native.report!["errors"] as Error[];
    const exported = current.report?.["errors"];
    for (const [index, source] of nativeDiagnostics) {
      const message = historical[index]!.message;
      let diagnostic: unknown = Array.isArray(exported) && exported[index];
      // A failed export may never reach the report. Its hooks have already run,
      // so check the original descriptors again before native cloning reads a stack.
      if (freshError && previousDiagnosticMessage(source) === message)
        diagnostic = source;
      if (
        isNativeError(diagnostic) &&
        Object.getPrototypeOf(diagnostic) === Object.getPrototypeOf(source)
      ) {
        try {
          const copy = structuredClone(diagnostic);
          if (copy.message === message) {
            historical[index] = copy;
            continue;
          }
        } catch {
          // A failed native clone cannot establish a historical report.
        }
      }
      if (freshError) throw freshError;
      priorIds = previousFindingIds(native);
      native = undefined;
      break;
    }
  }
  // A Cloud depth error can interrupt a local reader's JSON export. Its plain,
  // independently captured output can still verify the original reader selection.
  const readerOutput = freshError
    ? freshError instanceof CloudEvidenceDepthError &&
      plainJson &&
      !nativeDiagnostics.size &&
      native
    : current;
  const reader = readerOutput
    ? previousReaderSelection(input, readerOutput, native ?? null)
    : undefined;
  if (reader) native = reader.snapshot;
  const original = historicalPublication(native);
  if (original) checkFindingProvider(original.parsed, provider);
  try {
    validatePublicationFindings(current, validateExternalEvidence);
  } catch (error) {
    if (!(error instanceof Error) || !original?.parsed.findings.length)
      throw error;
    freshError = error;
  }
  if (freshError) {
    if (!original) throw freshError;
    // Only the old selection can be reviewed when fresh validation failed.
    current = { read: original.parsed.read, findings: [], excluded: [] };
  }
  checkFindingProvider(current, provider);
  const identity = publicationIdentity(current, provider);
  return {
    current,
    legacy: current,
    currentIdentity: identity,
    legacyIdentity: identity,
    sourcePositions: getOpenGrepSourcePositions(ownData(input, "findings")),
    original,
    freshError,
    unprovenIdPrefixes: reader?.unprovenIdPrefixes,
    uncertainFindingIds: reader?.uncertainFindingIds,
    unprovenOccurrenceCount: reader?.unprovenOccurrenceCount,
    knownFindings: reader?.knownFindings,
    potentialIds:
      reader?.sourceFindingIds ??
      (original
        ? undefined
        : (native?.findings.map((row) => row.source_finding_id) ?? priorIds)),
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

// Prefer the current native evidence for new publications. The original SDK input
// remains a candidate so an approved request can resume under its exact digest.
function* hostedPublicationProjections(
  input: ResolvedPublicationInput,
  provider: "semgrep" | "snyk",
  destination: ImportRepository,
  readerSources: readonly ExternalSourceRepository[],
): Generator<ResolvedPublicationInput> {
  const current: ExternalFindings & Partial<SnykIssuesFindings> = input.current;
  if (provider === "snyk") {
    const first = current.findings.find(isSnykRestFinding);
    if (!first && current.snykRestContext === undefined) return;
    // A previous publisher may have approved the exact raw selection.
    yield input;
    const originalUrl =
      current.snykRestContext?.["sourceRepositoryUrl"] ??
      current.sourceRepositoryUrl ??
      first?.evidence.source_data?.["sourceRepositoryUrl"];
    // The original spelling reconstructs a lookup key after a catalog rename.
    // Admission validates the input against the saved approval or live destination.
    const retained = structuredClone(current);
    try {
      snykRestImportRepository(
        retained,
        provider,
        [],
        hostedSourceReferences(
          readerSources,
          typeof originalUrl === "string" ? originalUrl : destination.url,
          current.sourceRepositoryPlatform,
        ),
        (finding, source) => {
          finding.evidence.source_data = source;
        },
      );
    } catch (error) {
      // A headerless input can still identify an already-approved opaque request.
      if (current.snykRestContext !== undefined) throw error;
      return;
    }
    yield {
      ...input,
      current: retained,
      // The raw input above owns its historical native checkpoint.
      original: undefined,
      currentIdentity: publicationIdentity(retained),
    };
    return;
  }
  const originalRow = (finding: ExternalFindings["findings"][number]) =>
    isRecord(finding.evidence.source_data?.["finding"]) &&
    isSemgrepPlatformEvidence(finding, "semgrep");
  const currentBulkRow = (finding: ExternalFindings["findings"][number]) =>
    finding.evidence.source_data?.["format"] === semgrepPlatformFormat;
  const first =
    current.findings.find(originalRow) ?? current.findings.find(currentBulkRow);
  if (!first) return;
  const reportScope = semgrepPlatformReportScope(current, "semgrep");
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
        const original = originalRow(finding);
        if (!original && !currentBulkRow(finding)) return finding;
        const binding = semgrepPlatformFindingBinding(
          finding,
          "semgrep",
          references,
          witnesses,
          reportScope,
          undefined,
          "cloud",
        );
        // The authenticated repository can make an offline backlog row selectable.
        return binding?.sourceData &&
          (original || binding.sourceData["format"] !== semgrepPlatformFormat)
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
      yield {
        ...input,
        current: upgraded,
        original: undefined,
        currentIdentity: publicationIdentity(upgraded),
      };
    } catch {
      // The released SDK also accepted partial original records; keep the raw
      // identity as a fallback so its exact saved request remains recoverable.
    }
  }
  yield input;
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
  let previousFindings: ExternalFindings | undefined;
  async function previousFindingsIfSaved(
    input: PublicationSelection,
    currentKey?: string,
  ) {
    if (!input.readPreviousFindings || previousFindings)
      return previousFindings;
    // An empty state directory (or just this current receipt) needs only the
    // current reader for its preview.
    const entries = (await readdir(state).catch(nullIfMissingFile)) ?? [];
    if (
      entries.some(
        (name) =>
          /^[a-f0-9]{64}\.(?:pending|private-import)\.json$/u.test(name) &&
          name.split(".", 1)[0] !== currentKey,
      )
    )
      previousFindings = input.readPreviousFindings();
    return previousFindings;
  }
  async function checkSelection(input: PublicationSelection) {
    const parsed = input.current;
    checkTrivyReportProvider(options.provider, parsed.report);
    for (const finding of parsed.findings)
      checkRetainedTrivyProvider(options.provider, finding);
    if (
      !parsed.findings.length &&
      !input.original?.parsed.findings.length &&
      input.potentialIds !== null &&
      !input.potentialIds?.length &&
      !input.uncertainFindingIds?.length &&
      !input.unprovenOccurrenceCount &&
      !input.unprovenIdPrefixes?.length &&
      !(await previousFindingsIfSaved(input))?.findings.length
    )
      throw new NoPublishableFindingsError(parsed);
  }
  if (typeof supplied !== "function") await checkSelection(supplied);
  progress({ phase: "discovering", completed: 0 });
  const apiBaseUrl = cloudBaseUrl(environment);
  const cloudApiUrl = `${apiBaseUrl}/external`;
  // Validate the configured return destination before authentication or uploads.
  cloudFindingsUrl(environment, options.repository);
  const credentials = await (
    dependencies.credentials ?? (() => readCloudCredentials(environment))
  )();
  let canStartJob = false;
  let repositorySeverities: string[] | undefined;
  const jobVersionHeader = "Codex-Security-Private-Import-Job-Version";
  const providerJobVersion = privateJobVersions[options.provider];
  // Older services recognize an exact v2 request for AWS. Only ask for v3
  // when publishing a provider introduced by that contract.
  const requestedJobVersion = String(providerJobVersion ?? 2);
  let jobApiVersion: typeof providerJobVersion;
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
          ...(repositoryCatalog
            ? { [jobVersionHeader]: requestedJobVersion }
            : {}),
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
      const advertised = (header: string) =>
        response.headers
          .get(header)
          ?.split(",")
          .map((item) => item.trim());
      repositorySeverities = advertised(
        "Codex-Security-Repository-Import-Severities",
      );
      canStartJob =
        advertised("Codex-Security-Private-Import-Providers")?.includes(
          options.provider,
        ) ?? false;
      jobApiVersion =
        response.headers.get(jobVersionHeader) === requestedJobVersion
          ? providerJobVersion
          : undefined;
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
  if (deferred) await checkSelection(resolved);
  const report: ExternalFindings & Partial<SnykIssuesFindings> =
    resolved.current;
  const source = { provider: options.provider, source_key: options.sourceKey };
  const importPrefix = source.provider === "sonar" ? "/v2" : "";
  const sourceReportsPath = importPrefix + sourcePath(destination);
  const checkpointIdentity = [
    // Keep existing production checkpoints readable; other deployments must
    // never share a saved request or receipt with the production default.
    ...(apiBaseUrl === DEFAULT_CLOUD_BASE_URL ? [] : [apiBaseUrl]),
    credentials.account_id,
    destination.id,
    destination.repo_connector_id,
    source,
  ];
  function scopeKey(identity: unknown, serialize = wireJson) {
    return jsonDigest([...checkpointIdentity, identity], serialize);
  }
  function localeKey(rows: ExternalFindings["findings"]) {
    return hash(
      "sha256",
      canonicalJson([...checkpointIdentity, rows], (left, right) =>
        left.localeCompare(right),
      ),
    );
  }
  const hosted = options.provider === "snyk" || options.provider === "semgrep";
  // Different selections can share native occurrences. Serialize their checkpoint
  // creation under the authenticated source and release before calling Cloud.
  const sourceLock =
    "source-" + hash("sha256", canonicalJson(checkpointIdentity));
  const withSourceAdmission = (operation: () => Promise<void>) =>
    hosted ? underLocks([sourceLock], operation) : operation();
  let projection = resolved;
  let capturedPending: string | undefined;
  const projectionKeys = new Set<string>();
  if (options.provider === "semgrep" || options.provider === "snyk") {
    for (const candidate of hostedPublicationProjections(
      resolved,
      options.provider,
      destination,
      readerSources,
    )) {
      const candidateKey = scopeKey(candidate.currentIdentity);
      if (projectionKeys.has(candidateKey)) continue;
      // New imports use the first reconstructed projection; an exact pending key
      // takes precedence, including an earlier SDK's unmodified original input.
      capturedPending = await readOptionalFile(pendingFile(candidateKey));
      if (projection === resolved || capturedPending !== undefined)
        projection = candidate;
      projectionKeys.add(candidateKey);
      if (capturedPending !== undefined) break;
    }
  }
  // Changed reader projections get new keys, but both transports must replay the
  // exact bytes already approved by the earlier reader when a checkpoint exists.
  const privateClient = privateImportClient(
    apiBaseUrl,
    credentials,
    dependencies.fetch ?? globalThis.fetch,
    dependencies.signal,
  );
  let previewContext: PrivateImportContext | undefined;
  const currentReaderKey = resolved.readPreviousFindings
    ? scopeKey(resolved.currentIdentity)
    : undefined;
  let alternateKey: string | undefined;
  let resumingPreviousReader = false;
  function previousCandidateKey(previous: ExternalFindings | undefined) {
    if (!previous?.findings.length) return;
    // The file reader already validated plain JSON evidence for Cloud. Only a
    // matching checkpoint needs the full normalized publication snapshot.
    const previousKey = scopeKey(
      publicationIdentity(previous, options.provider),
    );
    return previousKey !== currentReaderKey ? previousKey : undefined;
  }
  async function alternateCheckpoint(
    key: string,
    context: () => Promise<PrivateImportContext>,
  ): Promise<{ pending: string | undefined } | undefined> {
    const pending = await readOptionalFile(pendingFile(key));
    if (pending !== undefined) return { pending };
    const saved = await readOptionalFile(
      join(state, key + ".private-import.json"),
    );
    if (saved === undefined) return;
    const checkpoint = parsePrivateCheckpoint(saved);
    // A completed import cannot acknowledge findings newly admitted by the
    // current reader. Pending uploads and jobs always retain their original bytes.
    if (
      !resumingPreviousReader &&
      previousFindings &&
      checkpoint.receipt?.status === "completed" &&
      !sameFindingSelection(
        previousFindings.findings,
        resolved.current.findings,
      )
    )
      return;
    if (checkpoint.contextVersion === (await context()).context_version)
      return { pending };
  }
  async function assertNoAlternateCheckpoint(
    context = () => privateClient.context(),
  ) {
    if (alternateKey && (await alternateCheckpoint(alternateKey, context)))
      throw new CodexSecurityError(
        resumingPreviousReader
          ? "Both reader versions have saved publications for this report. Resume either one using its original normalized findings."
          : "Another publication prepared this input. Run the command again to review and resume the saved request.",
      );
  }
  if (currentReaderKey)
    alternateKey = previousCandidateKey(
      await previousFindingsIfSaved(resolved, currentReaderKey),
    );
  if (alternateKey && previousFindings) {
    const context = async () =>
      (previewContext ??= await privateClient.context());
    const checkpoint = await alternateCheckpoint(alternateKey, context);
    capturedPending = checkpoint?.pending;
    if (checkpoint) {
      projection = normalizedPublicationInput(
        previousFindings,
        options.provider,
      );
      resumingPreviousReader = true;
      alternateKey = currentReaderKey;
      await assertNoAlternateCheckpoint(context);
    }
  }
  const input = projection;
  let {
    current: parsed,
    legacy: legacyParsed,
    currentIdentity,
    legacyIdentity,
    recheckFileRepository,
  } = input;
  const scopedSemgrepReport =
    options.provider === "semgrep" &&
    "sourceFormat" in parsed &&
    isSemgrepPlatformFormat(parsed.sourceFormat);
  const original = input.original;
  const originalParsed = original?.parsed ?? parsed;
  const originalIdentity = original?.identity ?? currentIdentity;
  const hasBoxedScalars = original?.hasBoxedScalars === true;
  const changedCapture =
    original && original.wire !== wireJson(currentIdentity);
  const originalKey =
    changedCapture || hasBoxedScalars
      ? scopeKey(originalIdentity, canonicalJson)
      : undefined;
  let historicalOnly = false;
  const originalWireKey = changedCapture
    ? scopeKey(originalIdentity)
    : undefined;
  if (changedCapture && originalKey && originalWireKey) {
    // A released SDK could stage either spelling. A modern approval for the
    // fresh JSON can occupy the very same historical filename.
    for (const pathKey of new Set([
      originalKey,
      originalWireKey,
      localeKey(original.parsed.findings),
    ])) {
      const bytes = await readOptionalFile(pendingFile(pathKey));
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
              jsonDigest(originalIdentity, canonicalJson)))
      ) {
        parsed = legacyParsed = original.parsed;
        currentIdentity = legacyIdentity = original.identity;
        historicalOnly = true;
        break;
      }
    }
  }
  if (input.freshError && !historicalOnly) throw input.freshError;
  const inputDigest = jsonDigest(currentIdentity);
  const legacyInputDigest =
    currentIdentity === legacyIdentity
      ? inputDigest
      : jsonDigest(legacyIdentity);
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
  const originalHostedRetry =
    "This source has a pending hosted Cloud request. Resume it with the SDK build that created it and the original input before publishing another selection.";
  const unknownHostedRetry =
    "A pending hosted request matches this provider and repository, but its deployment could not be established. Resume it with the SDK build that created it, on the original deployment, using the full original input and metadata.";
  function originalHostedPending(
    content: SavedSubmission,
    filenameKey: string,
  ) {
    const projection = content.inputProjection;
    if (
      (options.provider !== "semgrep" && options.provider !== "snyk") ||
      content.accountId !== credentials.account_id ||
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
    if (filenameKey === scopeKey(legacyIdentity))
      identities.unshift(legacyIdentity);
    const identity = identities.find(
      (value) => filenameKey === scopeKey(value),
    );
    const digest = (value: unknown) => hash("sha256", canonicalJson(value));
    const semgrep = options.provider === "semgrep";
    const isHosted = (row: (typeof findings)[number]) =>
      semgrep
        ? isSemgrepPlatformEvidence(row, "semgrep")
        : isSnykRestFinding(row);
    const scannerId = (row: (typeof findings)[number]) =>
      isHosted({
        ...row,
        evidence: { ...row.evidence, source_data: undefined },
      });
    const hasNativeEvidence = (row: (typeof findings)[number]) => {
      const data = row.evidence.source_data;
      // A discriminator alone cannot identify a native occurrence.
      return (
        data &&
        isHosted({
          source_finding_id: "",
          evidence: {
            ...row.evidence,
            source_data: { ...data, format: undefined },
          },
        })
      );
    };
    const references = hostedSourceReferences(
      readerSources,
      content.approvedRepositoryUrl ?? destination.url,
      content.approvedRepositoryPlatform,
    );
    const occurrenceIds = (rows: typeof findings) => {
      const ids = new Set(rows.map((row) => row.source_finding_id));
      let native = false;
      let unresolved = false;
      for (const row of rows) {
        if (!hasNativeEvidence(row)) continue;
        native = true;
        try {
          const id = semgrep
            ? semgrepPlatformFindingBinding(
                { ...row, source_finding_id: "" },
                "semgrep",
                references,
                undefined,
                undefined,
                undefined,
                "cloud",
              )?.nativeId
            : snykRestCheckpointFindingId(row, references);
          if (id) {
            ids.add(id);
            continue;
          }
        } catch {
          // An earlier SDK may have accepted a partial native projection.
        }
        if (!scannerId(row)) unresolved = true;
      }
      return { ids, native, unresolved };
    };
    const previous = occurrenceIds(findings);
    const requested = occurrenceIds(parsed.findings);
    const hostedSelection =
      projection.retainedHostedSelection ||
      scopedSemgrepReport ||
      previous.native ||
      requested.native;
    // Submitted and native IDs share one namespace even when one side drops its raw evidence.
    const couldOverlap =
      (hostedSelection &&
        Array.from(requested.ids).some((id) => previous.ids.has(id))) ||
      (previous.native &&
        requested.native &&
        (previous.unresolved || requested.unresolved));
    if (content.approvedRepositoryUrl && !projection.retainedHostedSelection) {
      if (!couldOverlap) return false;
      if (identity)
        return projection.inputDigest === digest(identity) && "verified";
      // The filename includes metadata omitted from the saved request. A reproducible
      // original digest under another filename proves this is another deployment.
      return (
        !identities.some((value) => digest(value) === projection.inputDigest) &&
        "unidentified"
      );
    }
    if (identity && projection.inputDigest !== digest(identity))
      return (
        (couldOverlap || !previous.native || !requested.native) && "verified"
      );

    if (!couldOverlap) return false;
    if (!identity) {
      // If the saved selections reconstruct an old input digest but not its scoped
      // filename, the pending request belongs to another deployment. The older
      // publisher included its repository comparison flags in the digest.
      const repositories = new Set([destination.url]);
      for (const { evidence } of findings) {
        const data = evidence.source_data;
        const project = data?.["project"];
        const retained =
          (semgrep && isRecord(project) ? project["url"] : undefined) ??
          data?.["sourceRepositoryUrl"];
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
    return "verified";
  }
  function wasReset(content: SavedSubmission) {
    return content.requests.some(
      ({ repository }) => repository.reset_marker !== destination.reset_marker,
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
  function suppliedSemgrepScopeDigest() {
    const scope = semgrepPlatformReportScope(report, options.provider);
    return hash(
      "sha256",
      canonicalJson(
        scope?.format
          ? [
              scope.deployment,
              canonicalNumber(scope.projectId),
              scope.ref,
              scope.product,
            ]
          : null,
      ),
    );
  }
  async function retireIfReset(
    content: SavedSubmission,
    retire: () => Promise<void>,
  ) {
    if (wasReset(content)) {
      if (hosted) await confirmReset();
      await retire();
      throw new CloudImportError(
        409,
        "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.",
      );
    }
  }
  function retirePendingIfReset(
    content: SavedSubmission,
    keys: string[],
    path: string,
    remove = () => rm(path),
  ) {
    return retireIfReset(content, () =>
      underLocks(keys, async () => {
        const bytes = await readOptionalFile(path);
        if (bytes !== undefined && sameSubmission(JSON.parse(bytes), content))
          await remove();
      }),
    );
  }
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
    for (const finding of submissionFindings(content.requests))
      checkRetainedTrivyProvider(options.provider, finding);
    if (!matchesSavedDestination(content.requests))
      throw new Error("Saved import destination does not match.");
    if (source.provider === "trivy" && !content.trivyRepositoryUrl)
      throw new CodexSecurityError(
        "This build cannot verify the original repository for this pending Trivy import. Check its destination before resuming with the build that created it.",
      );
    return content;
  }

  function validateSaved(
    record: SavedSubmission | null | undefined,
    legacy = false,
    filenameKey = key,
  ): SavedSubmission {
    const content = readSaved(record);
    const saved = submissionFindings(content.requests);
    const wire = wireJson(saved);
    const projection = content.inputProjection;
    const expected = repositoryFindings(
      legacy ? legacyParsed : parsed,
      projection?.repositorySeverities,
    );
    if (
      projection &&
      (!sameFindingSelection(saved, expected) ||
        projection.inputDigest !== (legacy ? legacyInputDigest : inputDigest) ||
        projection.savedEvidenceDigest !== hash("sha256", wire))
    ) {
      const status = originalHostedPending(content, filenameKey);
      if (status === "unidentified")
        throw new CodexSecurityError(unknownHostedRetry);
      if (status) {
        if (wasReset(content)) return content;
        throw new CodexSecurityError(originalHostedRetry);
      }
      throw new Error(
        "Saved import evidence does not match the selected input.",
      );
    }
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
      !verifiableLegacyMetadata(originalParsed, true)
    )
      throw unmatchedPreviousNumbers();
    checkFindingProvider({ ...parsed, findings: saved }, options.provider);
    const approvedScope = content.inputProjection?.semgrepPartialScopeDigest;
    if (
      approvedScope !== undefined &&
      !wasReset(content) &&
      approvedScope !== suppliedSemgrepScopeDigest()
    )
      throw new CodexSecurityError(
        "The supplied Semgrep report scope does not match the approved request.",
      );
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
    const saved = submissionFindings(content.requests);
    const savedWire = wireJson(saved);
    const wireDigest = hash("sha256", savedWire);
    if (projection?.inputDigest !== jsonDigest(originalIdentity, canonicalJson))
      throw unmatchedPreviousNumbers();
    if (projection.identityFormat === 2) {
      // A current writer may own the old filename for an ordinary object.
      if (projection.savedEvidenceDigest === wireDigest) return undefined;
      throw unmatchedPreviousNumbers();
    }
    const selected = originalParsed.findings.map(wireFinding);
    if (projection.savedEvidenceDigest !== jsonDigest(selected, canonicalJson))
      throw unmatchedPreviousNumbers();
    if (savedWire !== wireJson(selected)) {
      // A genuinely empty object at this key is a separate ordinary selection.
      if (wireDigest === projection.savedEvidenceDigest) return undefined;
      return "different-wire";
    }
    if (
      (changedCapture && !historicalOnly) ||
      !verifiableLegacyMetadata(originalParsed, false)
    )
      throw unmatchedPreviousNumbers();
    checkFindingProvider({ ...parsed, findings: saved }, options.provider);
    content.legacyApproval = true;
    content.inputProjection = {
      ...content.inputProjection,
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
  const key = scopeKey(currentIdentity);
  const stagingKey = originalKey ?? key;
  const canonicalPath = pendingFile(key);
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
  const legacyIdentityKey = scopeKey(legacyIdentity);
  const legacyKeys = new Set([legacyIdentityKey, historicalKey]);
  function underLocks<T>(keys: string[], operation: () => Promise<T>) {
    return withImportLocks(state, keys, dependencies.signal, operation);
  }
  let recovered: SavedSubmission | undefined;
  for (const legacyKey of legacyKeys) {
    if (legacyKey === key || legacyKey === originalKey) continue;
    const legacyPath = pendingFile(legacyKey);
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
          legacyKey !== legacyIdentityKey &&
          prior?.inputProjection &&
          prior.inputProjection.inputDigest !== legacyInputDigest
        ) {
          const projection = prior.inputProjection;
          const rows = legacyParsed.findings;
          if (
            projection.identityFormat === 2 ||
            (projection.inputDigest === jsonDigest(rows) &&
              projection.savedEvidenceDigest ===
                jsonDigest(submissionFindings(prior.requests)))
          )
            return;
          // The released SDK hashed report-free rows as an array and boxed scores as {}.
          const originalRows = original?.parsed.findings ?? rows;
          if (
            hasBoxedScalars &&
            legacyParsed.report !== undefined &&
            legacyKey === scopeKey(originalRows, canonicalJson) &&
            projection.inputDigest ===
              jsonDigest(originalRows, canonicalJson) &&
            projection.savedEvidenceDigest ===
              jsonDigest(originalRows.map(wireFinding), canonicalJson) &&
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
          legacyKey,
        );
        if (!sameFindingSelection(legacyParsed.findings, parsed.findings))
          throw new CodexSecurityError(
            "The saved import selects different findings from this input. Resume the original selection before publishing this selection.",
          );
        await retireIfReset(content, async () => {
          if (serialized !== undefined) await rm(legacyPath);
        });
        const savedEvidenceDigest =
          content.inputProjection?.savedEvidenceDigest ??
          jsonDigest(legacyParsed.findings);
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
        await withSourceAdmission(async () => {
          if (!rebindProjection) {
            await rename(legacyPath, canonicalPath);
          } else {
            // Bind the new input projection to the original immutable evidence,
            // so later inventory reordering still resumes these exact requests.
            await writeAtomicJson(canonicalPath, content);
            await rm(legacyPath);
          }
        });
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
    input.potentialIds === undefined && changedCapture
      ? original.parsed.findings.map((row) => row.source_finding_id)
      : input.potentialIds;
  const unprovenPrefixes = new Set(input.unprovenIdPrefixes);
  const uncertainIds = new Set(input.uncertainFindingIds);
  const uncertainMembership =
    input.unprovenOccurrenceCount ||
    uncertainIds.size > 0 ||
    unprovenPrefixes.size > 0;
  function uncertainId(id: string) {
    return (
      uncertainIds.has(id) ||
      unprovenPrefixes.has(id.replace(/\/[a-f0-9]{64}$/u, "/"))
    );
  }
  const stableIds = uncertainMembership
    ? (
        potentialIds ?? parsed.findings.map((row) => row.source_finding_id)
      ).filter((id) => id === undefined || !uncertainId(id))
    : undefined;
  const knownMembership = input.unprovenOccurrenceCount
    ? new Set(stableIds)
    : undefined;
  const knownRows = new Map(
    input.knownFindings?.map((row) => [
      row.source_finding_id,
      wireFinding(row),
    ]),
  );
  let originalInputDigest: string | undefined;
  const cannotCaptureOriginal =
    !input.original &&
    (potentialIds === null || !!(potentialIds?.length || uncertainMembership));
  const possibleBufferExport =
    options.provider === "github" && original && !changedCapture;
  function potentialOriginal(record: SavedSubmission, fileKey: string) {
    const projection = record.inputProjection;
    if (record.accountId !== credentials.account_id) return false;
    if (!projection) {
      // Locale-era requests had no projection. Their scoped occurrence IDs
      // can stop an opaque retry but cannot authorize replay.
      if (!cannotCaptureOriginal || record.wireKey !== undefined) return false;
    } else if (
      !/^[a-f0-9]{64}$/u.test(projection.inputDigest) ||
      !/^[a-f0-9]{64}$/u.test(projection.savedEvidenceDigest) ||
      (projection.identityFormat === 2 && !record.legacyApproval)
    )
      return false;
    try {
      // Older evidence may fail today's limits. Scope and selection can still
      // identify an outstanding approval and prevent a duplicate submission.
      if (!matchesSavedDestination(record.requests)) return false;
      const rows = submissionFindings(record.requests);
      const savedWire = wireJson(rows);
      const evidenceMatches =
        projection &&
        projection.savedEvidenceDigest === hash("sha256", savedWire);
      if (evidenceMatches) {
        // Matching old digests reconstruct its scoped filename. A report from
        // this caller is useful only when the saved digest independently binds it.
        const reportFree =
          projection.inputDigest === projection.savedEvidenceDigest;
        const identity = reportFree
          ? rows
          : parsed.report !== undefined
            ? { findings: rows, report: reportForJson(parsed.report) }
            : undefined;
        if (
          identity &&
          (reportFree || projection.inputDigest === jsonDigest(identity))
        ) {
          if (
            record.wireKey
              ? record.wireKey !== scopeKey(identity)
              : fileKey !== scopeKey(identity, canonicalJson) &&
                fileKey !== localeKey(rows)
          )
            return false;
          if (
            possibleBufferExport &&
            projection.inputDigest !== inputDigest &&
            sameLegacyJson(identity, currentIdentity, previousBufferJson)
          ) {
            return true;
          }
        }
        if (
          !record.wireKey &&
          reportFree &&
          original &&
          original.wire !== savedWire
        )
          return false;
      }
      if (record.wireKey && !cannotCaptureOriginal) return false;
      if (
        projection &&
        original &&
        fileKey !== stagingKey &&
        fileKey !== originalWireKey &&
        projection.inputDigest ===
          (originalInputDigest ??= jsonDigest(
            original.identity,
            canonicalJson,
          )) &&
        fileKey !== localeKey(original.parsed.findings) &&
        projection.savedEvidenceDigest ===
          jsonDigest(
            original.parsed.findings.map(wireFinding),
            canonicalJson,
          ) &&
        savedWire === wireJson(original.parsed.findings.map(wireFinding))
      )
        return false;
      if (stableIds) {
        // An opaque occurrence may have had a different old ID. Compare all
        // definite members and count the remaining IDs without claiming them.
        const certain = rows.filter(
          (row) => !uncertainId(row.source_finding_id),
        );
        const stableSaved = knownMembership
          ? certain.filter((row) => knownMembership.has(row.source_finding_id))
          : certain;
        if (
          certain.length - stableSaved.length >
          (input.unprovenOccurrenceCount ?? 0)
        )
          return false;
        return (
          rows.length > 0 &&
          stableSaved.length === stableIds.length &&
          stableSaved.every((row, i) => {
            const known = knownRows.get(row.source_finding_id);
            return (
              row.source_finding_id === stableIds[i] &&
              (!known || wireJson(row) === wireJson(known))
            );
          })
        );
      }
      const candidates = originalParsed.findings;
      const ids =
        potentialIds === undefined
          ? parsed.findings.map((row) => row.source_finding_id)
          : potentialIds;
      if (
        ids &&
        (!ids.length ||
          rows.length !== ids.length ||
          !rows.every(
            (row, i) =>
              ids[i] === undefined || row.source_finding_id === ids[i],
          ))
      )
        return false;
      // An opaque serializer can add a report or replace every visible field.
      // Only scoped, independently known occurrences can rule out its old request.
      if (cannotCaptureOriginal || !projection) return true;
      if (
        projection.inputDigest === projection.savedEvidenceDigest &&
        parsed.report !== undefined
      )
        return false;
      if (potentialIds === undefined && (hasBoxedScalars || evidenceMatches))
        return false;
      return (
        !sameFindingSelection(rows, candidates) ||
        rows.every((row, i) => {
          const { source_data: savedData, ...savedFields } = row.evidence;
          const { source_data: selectedData, ...selectedFields } =
            candidates[i]!.evidence;
          if (wireJson(savedFields) !== wireJson(selectedFields)) return false;
          // Once the original SDK discarded boxed positions, a plain JSON export
          // alone cannot attribute a new numeric spelling to that saved request.
          return sameLegacyJson(
            savedData,
            selectedData,
            (value) => typeof value === "number",
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
    ).catch(nullIfMissingFile);
    if (!directory) return undefined;
    const known = new Set(
      [key, originalKey, knownFileKey].filter((value) => value !== undefined),
    );
    let unidentified = false;
    let unprovenOriginal = false;
    let incomplete = false;
    let stagingPathOccupied = false;
    async function readCandidate(
      fileKey: string,
      selected?: Checkpoint,
      contents?: string,
    ): Promise<Checkpoint | undefined> {
      const path = pendingFile(fileKey);
      const serialized =
        contents ??
        (selected?.fileKey === key && !known.has(fileKey)
          ? await readOptionalRegularFile(path)
          : await readOptionalFile(path)) ??
        (preparing && fileKey === key ? capturedPending : undefined);
      if (serialized === undefined) {
        if (!known.has(fileKey)) incomplete = true;
        return selected;
      }
      if (fileKey === stagingKey) stagingPathOccupied = true;
      let record: SavedSubmission | null;
      try {
        record = JSON.parse(serialized) as SavedSubmission | null;
      } catch (error) {
        if (known.has(fileKey)) throw error;
        incomplete = true;
        return selected;
      }
      // A migrated checkpoint records the wire identity it belongs to even
      // when a separate input hashes to its historical filename.
      const tag = record?.wireKey;
      const tagged = tag !== undefined;
      const ownerKey = tagged ? tag : fileKey;
      const historical = !tagged && fileKey === originalKey && fileKey !== key;
      if (ownerKey !== key && !historical) {
        if (hosted && record?.inputProjection) {
          let status;
          try {
            status = originalHostedPending(record, ownerKey);
          } catch {
            // An unrelated or unreadable checkpoint cannot identify this source.
          }
          if (status === "unidentified")
            throw new CodexSecurityError(unknownHostedRetry);
          if (status) {
            if (wasReset(record)) {
              if (!preparing)
                throw new CodexSecurityError(
                  "The pending request and this preview have different repository reset markers. Review the destination again.",
                );
              await retirePendingIfReset(record, [fileKey], path);
            }
            throw new CodexSecurityError(originalHostedRetry);
          }
        }
        if (
          record &&
          (!tagged || cannotCaptureOriginal || possibleBufferExport) &&
          potentialOriginal(record, fileKey)
        )
          unprovenOriginal = true;
        // Some early locale filenames carry no deployment identity. Never guess their target.
        if (
          !tagged &&
          record &&
          !record.inputProjection &&
          !legacyKeys.has(fileKey)
        ) {
          try {
            // A different locale cannot authorize replay, even when the
            // original native capture proves these rows were selected.
            if (
              !original ||
              wireJson(submissionFindings(readSaved(record).requests)) !==
                wireJson(original.parsed.findings.map(wireFinding))
            )
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
        unprovenOriginal = true;
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
          if (first) {
            if (await readCandidate(fileKey)) throw conflict;
            if (sameSubmission(first.content, selected.content)) return first;
          }
          return completedCheckpoint(selected);
        });
      }
      return { fileKey, content, historical };
    }
    let selected: Checkpoint | undefined;
    for (const fileKey of known)
      selected = await readCandidate(fileKey, selected);
    // A known file that disappeared can be checked against its completed receipt.
    if (!selected && knownFileKey !== undefined && !hosted) return undefined;
    const hint = await lookupFileKey();
    if (hint && !known.has(hint)) {
      const contents = await readOptionalRegularFile(pendingFile(hint));
      if (contents !== undefined) {
        selected = await readCandidate(hint, selected, contents);
        known.add(hint);
      }
    }
    // A released publisher could stage the canonical request while another SDK
    // tagged its old filename but had not yet written the optional lookup.
    if (
      selected &&
      !cannotCaptureOriginal &&
      !selected.historical &&
      (selected.fileKey !== key ||
        selected.content.canonicalChecked ||
        selected.content.inputProjection?.identityFormat === 2)
    )
      return selected;
    const entries =
      (await readdir(state, { withFileTypes: true }).catch(
        nullIfMissingFile,
      )) ?? [];
    for (const entry of entries) {
      if (!entry.isFile() || !/^[a-f0-9]{64}\.pending\.json$/u.test(entry.name))
        continue;
      const fileKey = entry.name.slice(0, -".pending.json".length);
      if (!known.has(fileKey))
        selected = await readCandidate(fileKey, selected);
    }
    if (unprovenOriginal && (!selected || cannotCaptureOriginal))
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
  async function completedCheckpoint(observed: Checkpoint) {
    if (
      await readCompletedPublication(
        observed.content.requests,
        observed.fileKey,
      )
    )
      return observed;
    throw new CodexSecurityError(
      "The saved publication changed while preparing this input. Review it again.",
    );
  }
  function occupiedCheckpoint() {
    return new CodexSecurityError(
      "Finish the other pending import at this checkpoint first, then review this input again.",
    );
  }
  let selected = await selectedCheckpoint(recovered ? key : undefined, true);
  const fileKey = selected?.fileKey ?? (recovered ? key : stagingKey);
  const pendingPath = pendingFile(fileKey);
  async function rememberFile() {
    if (fileKey !== key && (await lookupFileKey()) !== fileKey)
      await writeAtomicJson(lookupPath, fileKey).catch(() => undefined);
  }
  async function removePending() {
    await rm(pendingPath, { force: true });
    if (fileKey !== key && (await lookupFileKey()) === fileKey)
      await rm(lookupPath, { force: true }).catch(() => undefined);
  }

  const lockKeys = [key, fileKey, stagingKey];
  if (alternateKey) lockKeys.push(alternateKey);
  async function underPublishLocks<T>(operation: () => Promise<T>) {
    // An older publisher may already hold its lock before its checkpoint exists.
    // Derive that key for actual writes, even after a checkpoint-free preview.
    if (resolved.readPreviousFindings && !previousFindings) {
      previousFindings = resolved.readPreviousFindings();
      alternateKey = previousCandidateKey(previousFindings);
      if (alternateKey) lockKeys.push(alternateKey);
    }
    return underLocks(lockKeys, operation);
  }
  if (selected?.historical) {
    const observed = selected;
    selected = await underLocks(lockKeys, async () => {
      const current = await selectedCheckpoint(fileKey);
      if (
        !current ||
        current.fileKey !== fileKey ||
        !sameSubmission(current.content, observed.content)
      )
        return completedCheckpoint(observed);
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
  if (!parsed.findings.length) throw new NoPublishableFindingsError(parsed);
  if (saved)
    await retirePendingIfReset(saved, lockKeys, pendingPath, removePending);
  if (saved?.inspectorProjectMapRequired && !inspectorProjectMap)
    throw new CodexSecurityError(
      "Supply the verified Inspector project binding again to resume.",
    );

  // Existing repository submissions keep their original request bodies and receipts.
  const privatePath = join(state, `${key}.private-import.json`);
  const privateSaved = await readOptionalFile(privatePath);
  if (resumingPreviousReader && !saved && privateSaved === undefined)
    throw new CodexSecurityError(
      "The saved publication changed. Run the command again to preview this report.",
    );
  const usePrivateImport =
    !saved && (canStartJob || privateSaved !== undefined);
  async function preparePrivateAttempt() {
    const context = previewContext ?? (await privateClient.context());
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

  // The findings-only checkpoint key lets projected and native callers resume one immutable
  // request. Supplemental report claims are outside that digest and must still match its source.
  const recheckOriginal =
    options.provider === "semgrep" &&
    projection !== resolved &&
    saved?.approvedRepositoryPlatform === "other";
  // Native Semgrep and OpenGrep files include their required source URL in every
  // saved finding. An exact replay by repository ID survives a catalog rename.
  const recordedFileSource =
    saved &&
    !saved.approvedRepositoryUrl &&
    options.provider === "semgrep" &&
    !deferred &&
    declaredUrl !== undefined &&
    saved.requests.every(({ items }) =>
      items.every(
        ({ evidence }) => evidence.details?.repository?.url === declaredUrl,
      ),
    );
  const declaredSource =
    recheckOriginal ||
    readerSources.length > 0 ||
    (declaredUrl !== undefined && !recordedFileSource) ||
    report.sourceRepositoryUrl !== undefined ||
    report.sourceRepositoryPlatform !== undefined ||
    report.snykRestContext !== undefined;
  let legacyTypedUrl: string | undefined;
  let suppliedReport = report;
  const sourceFor = (url: string, platform?: "other") => {
    try {
      return hostedRepositoryMatcher(
        platform
          ? { ...suppliedReport, sourceRepositoryPlatform: platform }
          : suppliedReport,
        options.provider,
        declaredUrl,
        { url },
        readerSources,
        saved !== undefined,
      );
    } catch (error) {
      if (!recheckOriginal || readerSources.length) throw error;
      // An older strict approval did not distinguish GitLab from another case-sensitive SCM.
      throw new CodexSecurityError(
        `${error instanceof Error ? error.message : String(error)} Resume with the original Semgrep input and SCM repository mapping, or the SDK build that created this request.`,
        { cause: error },
      );
    }
  };
  if (hosted && saved && declaredSource) {
    // The released publisher checked typed repository URLs against its authenticated catalog.
    // Opaque original records could name a different project and cannot establish a rename.
    const findings = submissionFindings(saved.requests);
    if (!saved.approvedRepositoryUrl)
      legacyTypedUrl = findings.find(
        ({ evidence }) => evidence.details?.repository?.url,
      )?.evidence.details?.repository?.url;
    // Supplemental claims must agree with each verifiable row from the immutable request.
    suppliedReport = {
      ...report,
      // The v1 upgrade may drop a redundant mapping using the catalog's GitHub casing.
      findings: recheckOriginal ? [...report.findings, ...findings] : findings,
    };
  }
  // The released request retained its typed finding URL, but only the authenticated
  // catalog or a previously recorded approval can bind a new source declaration.
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
  const hostedSource =
    hosted && (!saved || declaredSource)
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
  if (legacyTypedUrl) requireApprovedSource(legacyTypedUrl);

  const trivyTarget =
    saved?.trivyRepositoryUrl ?? privateUrl ?? destination.url;
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

  function checkRepositories(
    { findings, report }: Pick<ExternalFindings, "findings" | "report">,
    historical = Boolean(saved),
  ) {
    const { provider } = options;
    checkTrivyReportProvider(provider, report);
    // A catalog casing or spelling change keeps the original source comparison target.
    const approved = hosted ? saved?.approvedRepositoryUrl : undefined;
    const sameCatalog =
      approved !== undefined &&
      cloudSourceKey(approved, "github") ===
        cloudSourceKey(destination.url, "github");
    const comparisonUrl = trivyReportUrls
      ? trivyTarget
      : sameCatalog
        ? approved
        : (privateUrl ?? destination.url);
    const key = sameCatalog
      ? (url: string) =>
          cloudSourceKey(
            url,
            saved?.approvedRepositoryPlatform === "other"
              ? undefined
              : "github",
          )
      : catalogKey;
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
    if (report?.["format"] === guardianSelectionFormat)
      requireDestination(
        "Guardian source",
        declaredScannerRepositoryUrl(report["repositoryUrl"], "Guardian"),
      );
    // An immutable retry may refer to an earlier repository name. Additional
    // file declarations outside its saved findings authorize no new writes.
    if (!historical)
      for (const { url } of fileRepositories?.() ?? [])
        requireDestination(
          "Source report",
          provider === "snyk"
            ? normalizeHostedGitRepositoryUrl(url, destination.url, true)
            : url,
        );
    // Historical checkpoints already fixed the provider and request bytes.
    // Recheck any projected source against the destination discovered for this retry.
    const checkNative = (...providers: (typeof provider)[]) =>
      !historical ||
      trivyReportUrls !== undefined ||
      providers.includes(provider);
    if (checkNative("sonar")) {
      for (const url of sonarRepositoryUrls(
        provider,
        findings,
        report,
        "cloud",
      ))
        requireDestination("Sonar source", url);
    }
    const checkmarx = checkmarxSelection(
      provider,
      findings,
      report,
      "cloud",
      historical,
    );
    requireDestination("Checkmarx source", checkmarx.reportUrl);
    const blackDuck = checkNative("blackduck")
      ? blackDuckReportRepositories(provider, findings, "cloud")
      : undefined;
    const checkmarxRepository = checkmarx.repositories();
    for (const [scanner, repositories] of [
      ["veracode", veracodeReportRepositories],
      ["continuum", continuumReportRepositories],
    ] as const) {
      if (!checkNative(scanner)) continue;
      for (const [id, source] of repositories(provider, findings, "cloud"))
        requireDestination(id, source.url);
    }
    if (checkNative("blackduck", "inspector", "veracode")) {
      const binding = inspectorReportRepository(
        provider,
        findings,
        "cloud",
        inspectorProjectMap,
      );
      if (binding) requireDestination(binding.findingId, binding.url);
    }
    const checkOnlyProjected = !checkNative(
      "blackduck",
      "inspector",
      "veracode",
      "checkmarx",
      "continuum",
      "sonar",
    );
    for (const finding of findings) {
      const { source_finding_id: id, evidence } = finding;
      const guardian = guardianFindingRepository(finding, "cloud");
      if (guardian) {
        requireDestination(id, guardian);
        requireDestination(id, evidence.details?.repository?.url);
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
      if (checkOnlyProjected && !hasProjection) continue;
      let urls = [
        blackDuckUrl,
        checkmarxRepository(finding)?.url,
        evidence.details?.repository?.url,
      ];
      if (provider === "wiz") {
        const native =
          hasProjection ||
          (!historical && isWizPackageFinding(evidence.source_data));
        urls.push(
          native
            ? wizFindingRepository(evidence, "cloud")?.url
            : wizCsvRepositoryUrl(evidence),
        );
      } else if (provider === "snyk") {
        urls = urls.concat(
          snykRepositoryUrls(evidence.source_data, {
            cloudRepositoryUrl: destination.url,
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
        if (!historical) urls.push(retainedGitHubRepository(finding));
        urls.push(dependabotRepository(finding));
      }
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
  }
  if (!usePrivateImport) checkRepositories(parsed);
  // A retry sends its saved projection, which may differ from today's reader.
  if (saved) {
    // Only use the report associated with the input digest in the saved checkpoint.
    const report =
      saved.inputProjection?.inputDigest === inputDigest
        ? parsed.report
        : undefined;
    checkRepositories({ findings: submissionFindings(saved.requests), report });
  }

  // An older, genuinely unbound checkpoint first acquires a URL on a matching preview.
  // Retain it at the original path so its bare caller can still recover the same request.
  if (saved && !saved.approvedRepositoryUrl && hostedSource) {
    await underLocks(lockKeys, async () => {
      const serialized = await readOptionalFile(pendingPath);
      if (serialized === undefined) return;
      const current = validateSaved(JSON.parse(serialized));
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
          originalHostedPending(current, current.wireKey ?? fileKey) ===
            "verified"
        )
          current.inputProjection.retainedHostedSelection = true;
        current.approvedRepositoryUrl = approvedUrl;
        await writeAtomicJson(pendingPath, current);
      }
      saved.inputProjection = current.inputProjection;
      saved.approvedRepositoryUrl = current.approvedRepositoryUrl;
      saved.approvedRepositoryPlatform = current.approvedRepositoryPlatform;
    });
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
    checkRepositories(parsed, resumed);
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
          await assertNoAlternateCheckpoint(async () => current);
          const stored = readPrivateCheckpoint(
            await readOptionalFile(privatePath),
            binding,
          );
          if (
            !stored &&
            (resumingPreviousReader ||
              (privateUrl && privateUrl !== destination.url))
          )
            throw new CodexSecurityError(
              "The saved private import changed. Run the command again to preview this report.",
            );
          // Only a preview of this terminal job can start a new attempt.
          const retrying =
            retryOfJobId !== undefined && stored?.receipt?.id === retryOfJobId;
          const active = retrying ? undefined : stored;
          if (resumed && !active) checkRepositories(parsed);
          requireAccess(current, active);
          if (await selectedCheckpoint())
            throw new CodexSecurityError(
              "A repository submission is pending. Review its saved request before continuing.",
            );
          // Both routes share request IDs. A server upgrade can promote an
          // existing job, and its saved route also survives gate rollback.
          const checkpoint = {
            ...(active ?? {
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
            }),
            jobApiVersion: stored?.jobApiVersion ?? jobApiVersion,
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
            if (!active || active.jobApiVersion !== checkpoint.jobApiVersion)
              await writeAtomicJson(privatePath, checkpoint);
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
                jobApiVersion: checkpoint.jobApiVersion,
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

  // The original selection and request bytes govern a retry even if discovery changes.
  const severities = saved
    ? saved.inputProjection?.repositorySeverities
    : repositorySeverities;
  const direct = repositorySelection(parsed, severities, input.sourcePositions);
  if (!direct.findings.length) throw new NoPublishableFindingsError(direct);
  let requests = saved?.requests;
  if (!requests) {
    let preparedCount = 0;
    progress({
      phase: "preparing",
      completed: 0,
      total: direct.findings.length,
    });
    const previousReports = await readInBatches(
      direct.findings,
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
          total: direct.findings.length,
        });
        return previous;
      },
    );
    requests = [];
    let current: FindingImportRequest | undefined;
    let currentBytes = 0;
    for (const [index, finding] of direct.findings.entries()) {
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
  const bindSemgrepScope =
    !saved &&
    options.provider === "semgrep" &&
    report.findings.some(
      (finding) =>
        !isSemgrepPlatformEvidence(finding, "semgrep") &&
        (scopedSemgrepReport ||
          hasRetainedSemgrepScope(finding.evidence.source_data?.["finding"])),
    );
  const submission: SavedSubmission = {
    accountId: credentials.account_id,
    ...(trivyReportUrls && { trivyRepositoryUrl: trivyTarget }),
    requests,
    receipts: saved?.receipts,
    legacyApproval: saved?.legacyApproval,
    wireKey: saved?.wireKey ?? (fileKey === key ? undefined : key),
    inputProjection: saved?.inputProjection ?? {
      ...(direct !== parsed && { repositorySeverities: severities }),
      identityFormat: saved ? undefined : 2,
      ...(scopedSemgrepReport && { retainedHostedSelection: true }),
      ...(bindSemgrepScope && {
        semgrepPartialScopeDigest: suppliedSemgrepScopeDigest(),
      }),
      inputDigest,
      savedEvidenceDigest: jsonDigest(submissionFindings(requests)),
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
    (hostedSource && !hostedSource.github)
  )
    submission.approvedRepositoryPlatform = "other";
  if (inspectorProjectMap) submission.inspectorProjectMapRequired = true;
  const preview: ExternalPublicationPreview = {
    ...direct,
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
            direct.excluded.length || counts.error ? "partial" : "complete",
          read: parsed.read,
          ...(parsed.report === undefined
            ? {}
            : snapshotNormalizedFindings({ report: parsed.report })),
          ready: direct.findings.length,
          excluded: direct.excluded,
          receipts: acknowledged,
          counts,
          failures,
          unacknowledged:
            direct.findings.length -
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
        await assertNoAlternateCheckpoint();
        // Re-read under the lock to keep checkpoints from another publisher.
        const selected = await selectedCheckpoint(
          saved ? fileKey : undefined,
        ).catch((error: unknown) => {
          if (!submission.receipts?.length) throw error;
          throw interruptedPreview(errorMessage(error), error);
        });
        let pending = selected?.content;
        const current = pending ?? submission;
        const adoptProjectMap =
          submission.inspectorProjectMapRequired &&
          current.inspectorProjectMapRequired === undefined;
        if (adoptProjectMap) current.inspectorProjectMapRequired = true;
        if (current.approvedRepositoryUrl)
          requireApprovedSource(
            current.approvedRepositoryUrl,
            current.approvedRepositoryPlatform,
          );
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
          if ((await readOptionalFile(privatePath)) !== undefined)
            throw new CodexSecurityError(
              "A private import already owns this selection. Review its saved job before continuing.",
            );
          if ((await readOptionalFile(pendingPath)) !== undefined)
            throw occupiedCheckpoint();
        }
        // A preview can pin the catalog URL. Tighten its SCM comparison only
        // once the caller confirms publication, including when resuming a request.
        const adoptStrictRepository =
          submission.approvedRepositoryPlatform === "other" &&
          !current.approvedRepositoryPlatform;
        if (adoptStrictRepository) current.approvedRepositoryPlatform = "other";
        const cached = (current.receipts ?? []).map(validateImportReceipt);
        if (cached.length > requests.length)
          throw new CodexSecurityError(
            "Saved publication has more receipts than requests.",
          );
        const acknowledged: FindingImportReceipt[] = [];
        let verified = 0;
        try {
          if (selected?.checkedCanonical) current.canonicalChecked = true;
          if (pending === undefined) {
            await withSourceAdmission(async () => {
              if (hosted) {
                for (const otherKey of new Set([
                  ...projectionKeys,
                  ...legacyKeys,
                ])) {
                  if (
                    otherKey !== key &&
                    otherKey !== fileKey &&
                    (await readOptionalFile(pendingFile(otherKey))) !==
                      undefined
                  )
                    throw new CodexSecurityError(
                      "Another publication prepared this input. Run the command again to review and resume that saved request.",
                    );
                }
                if (await selectedCheckpoint())
                  throw new CodexSecurityError(
                    "Another publication prepared this input. Run the command again to review and resume that saved request.",
                  );
              }
              await writeAtomicJson(pendingPath, current);
            });
            pending = current;
          } else if (adoptProjectMap || adoptStrictRepository) {
            await writeAtomicJson(pendingPath, current);
          } else if (selected?.checkedCanonical) {
            // The existing approval and receipts are usable if caching the scan fails.
            await writeAtomicJson(pendingPath, current).catch(() => undefined);
          }
          await rememberFile();
          progress({
            phase: "uploading",
            completed: 0,
            total: direct.findings.length,
          });
          let acknowledgedCount = 0;
          for (const [batchIndex, batch] of requests.entries()) {
            const receipt = validatePublicationReceipt(
              cached[batchIndex] ??
                (await request(`${importPrefix}/finding_imports`, batch)),
              batch,
            );
            acknowledged.push(receipt);
            acknowledgedCount += receipt.item_count;
            progress({
              phase: "uploading",
              completed: acknowledgedCount,
              total: direct.findings.length,
            });
            if (batchIndex >= cached.length) {
              // Acknowledged batches must not consume another POST quota on retry.
              // Readback can still resume after this checkpoint without replaying writes.
              await writeAtomicJson(pendingPath, {
                ...submission,
                canonicalChecked: current.canonicalChecked,
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
          await writeAtomicJson(join(state, `${key}.result.json`), {
            ...completed,
            report: reportForJson(completed.report),
          });
          await removePending();
          return completed;
        } catch (error) {
          if (error instanceof CloudImportError && error.status === 409) {
            await removePending();
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
