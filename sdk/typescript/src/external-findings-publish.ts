import { hash, randomUUID } from "node:crypto";
import { chmodSync } from "node:fs";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
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
import {
  codexSecurityStateDirectory,
  validatePreparedOutputDir,
} from "./runtime.js";
import { readVendorFindings, type VendorFindings } from "./wiz-findings.js";
import {
  validateImportRequest,
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

/** CLI and plugin callers prepare the same immutable request before approval. */
export interface ExternalPublicationOptions {
  repository: string;
  provider: "wiz";
  sourceKey: string;
}

/** @internal Injectable transport and account for offline integration tests. */
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
  ready: number;
  excluded: VendorFindings["excluded"];
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
}

export interface ExternalPublicationPreview extends VendorFindings {
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

function repositoryUrl(value: string): string {
  return value.replace(/\/$/u, "").replace(/\.git$/u, "");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, child: unknown) => {
    if (child !== null && typeof child === "object" && !Array.isArray(child)) {
      return Object.fromEntries(
        Object.entries(child).sort(([a], [b]) => a.localeCompare(b)),
      );
    }
    return child;
  });
}

function sameSubmission(
  left: SavedSubmission,
  right: SavedSubmission,
): boolean {
  return (
    left.accountId === right.accountId &&
    canonicalJson(left.requests) === canonicalJson(right.requests)
  );
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

async function withImportLock<T>(
  state: string,
  key: string,
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  await mkdir(state, { recursive: true, mode: 0o700 });
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
  const progress = (event: ExternalPublicationProgress): void => {
    try {
      dependencies.onProgress?.(event);
    } catch {
      // Optional progress must not interrupt preparation or publication.
    }
  };
  if (!options.sourceKey.trim() || Buffer.byteLength(options.sourceKey) > 512) {
    throw new CodexSecurityError(
      "The source key must contain 1–512 UTF-8 bytes. Use a stable Wiz tenant/finding namespace, such as TENANT_ID/vulnerability-finding, across exports.",
    );
  }
  progress({ phase: "reading", completed: 0 });
  const parsed = await readVendorFindings(path);
  if (parsed.findings.length === 0) {
    throw new CodexSecurityError(
      `No supported findings are ready to publish. ${parsed.excluded.map((item) => `Item ${item.position}: ${item.reason}`).join(" ")}`,
    );
  }
  progress({ phase: "discovering", completed: 0 });
  const environment = dependencies.environment ?? process.env;
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
          repositoryUrl(item.url) === repositoryUrl(options.repository),
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
  const state = join(
    codexSecurityStateDirectory(environment),
    "external-finding-publications",
  );
  const key = hash(
    "sha256",
    canonicalJson([
      // Keep existing production checkpoints readable; other deployments must
      // never share a saved request or receipt with the production default.
      ...(apiBaseUrl === DEFAULT_CLOUD_BASE_URL ? [] : [apiBaseUrl]),
      credentials.account_id,
      destination.id,
      destination.repo_connector_id,
      source,
      parsed.findings,
    ]),
  );
  const pendingPath = join(state, `${key}.pending.json`);
  let saved: SavedSubmission | undefined;
  try {
    const serialized = await readFile(pendingPath, "utf8");
    const content = JSON.parse(serialized) as SavedSubmission;
    if (
      content.accountId !== credentials.account_id ||
      !Array.isArray(content.requests) ||
      content.requests.length === 0
    )
      throw new Error("Saved import account or requests do not match.");
    content.requests = content.requests.map(validateImportRequest);
    if (
      canonicalJson(
        content.requests.flatMap((batch) =>
          batch.items.map(({ source_finding_id, evidence }) => ({
            source_finding_id,
            evidence,
          })),
        ),
      ) !== canonicalJson(parsed.findings)
    ) {
      throw new Error(
        "Saved import evidence does not match the selected input.",
      );
    }
    for (const submission of content.requests) {
      if (
        submission.repository.id !== destination.id ||
        submission.repository.repo_connector_id !==
          destination.repo_connector_id ||
        canonicalJson(submission.source) !== canonicalJson(source)
      )
        throw new Error("Saved import destination does not match.");
      if (submission.repository.reset_marker !== destination.reset_marker) {
        // The old request is never sent after reset. A subsequent explicit
        // invocation prepares a fresh submission and asks for approval again.
        await withImportLock(state, key, dependencies.signal, async () => {
          const current = await readFile(pendingPath, "utf8").catch(
            (error: NodeJS.ErrnoException) => {
              if (error.code === "ENOENT") return undefined;
              throw error;
            },
          );
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
    saved = content;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  let requests = saved?.requests;
  if (!requests) {
    for (const finding of parsed.findings) {
      const sourceRepository = finding.evidence.details?.repository;
      if (
        sourceRepository &&
        repositoryUrl(sourceRepository.url) !== repositoryUrl(destination.url)
      )
        throw new CodexSecurityError(
          `Finding ${JSON.stringify(finding.source_finding_id)} belongs to ${JSON.stringify(sourceRepository.url)}, which does not match the selected Cloud repository ${JSON.stringify(destination.url)}. Verify the source repository mapping before publishing.`,
        );
    }
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
    for (const [index, finding] of parsed.findings.entries()) {
      const previous = previousReports[index];
      const environmentId =
        previous?.environment_id ?? destination.import_environment_id;
      if (environmentId == null)
        throw new CodexSecurityError(
          "Configure an authorized Cloud environment for this repository before importing findings.",
        );
      const repository = {
        id: destination.id,
        repo_connector_id: destination.repo_connector_id,
        environment_id: environmentId,
        reset_marker: destination.reset_marker,
      };
      const item = {
        client_id: `item-${index + 1}`,
        source_finding_id: finding.source_finding_id,
        expected_version: previous?.version ?? 0,
        evidence: finding.evidence,
      };
      if (
        current &&
        (current.repository.environment_id !== environmentId ||
          current.items.length === 100 ||
          Buffer.byteLength(
            JSON.stringify({ ...current, items: [...current.items, item] }),
          ) > MAX_REQUEST_BYTES)
      ) {
        requests.push(validateImportRequest(current));
        current = undefined;
      }
      current ??= { request_id: randomUUID(), repository, source, items: [] };
      current.items.push(item);
    }
    if (current) requests.push(validateImportRequest(current));
  }
  const submission: SavedSubmission = {
    accountId: credentials.account_id,
    requests,
    receipts: saved?.receipts,
  };
  const preview: ExternalPublicationPreview = {
    ...parsed,
    cloudApiUrl,
    cloudUrl: cloudFindingsUrl(environment, destination.id),
    accountId: credentials.account_id,
    destination,
    source,
    resumed: saved !== undefined,
    requests,
  };
  return {
    preview,
    async publish() {
      progress({ phase: "waiting", completed: 0 });
      return await withImportLock(state, key, dependencies.signal, async () => {
        // Re-read under the lock to keep checkpoints from another publisher.
        const pending = await readFile(pendingPath, "utf8").catch(
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return undefined;
            throw error;
          },
        );
        const current =
          pending === undefined
            ? submission
            : (JSON.parse(pending) as SavedSubmission);
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
        const result = (): ExternalPublicationResult => {
          const counts = { created: 0, updated: 0, unchanged: 0, error: 0 };
          const failures: ExternalPublicationResult["failures"] = [];
          for (const [index, receipt] of acknowledged.entries()) {
            for (const outcome of Object.keys(
              counts,
            ) as (keyof typeof counts)[])
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
        try {
          if (pending === undefined) {
            await writeAtomicJson(pendingPath, submission);
            persisted = true;
          }
          progress({
            phase: "uploading",
            completed: 0,
            total: parsed.findings.length,
          });
          let acknowledgedCount = 0;
          for (const [batchIndex, batch] of requests.entries()) {
            const receipt = validateImportReceipt(
              receipts[batchIndex] ??
                (await request("/finding_imports", batch)),
            );
            const batchItems = new Map(
              batch.items.map((item) => [item.client_id, item]),
            );
            if (
              receipt.id !== batch.request_id ||
              canonicalJson(receipt.repository) !==
                canonicalJson(batch.repository) ||
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
                `${sourcePath(destination)}/${encodeURIComponent(item.source_report_id!)}`,
              ),
            );
            if (
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
          const completed = result();
          await writeAtomicJson(join(state, `${key}.result.json`), completed);
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
              ...result(),
              status: "interrupted",
              error: message,
              ...(persisted ? { savedSubmission: pendingPath } : {}),
            },
            error,
          );
        }
      });
    },
  };
}
