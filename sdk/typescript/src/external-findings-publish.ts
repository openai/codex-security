import { hash, randomUUID } from "node:crypto";
import { chmodSync } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { readCloudCredentials } from "./cloud-publish.js";
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
} from "./external-import-models.js";

const BASE_URL = "https://chatgpt.com/backend-api/aardvark/external";
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
}

interface SavedSubmission {
  accountId: string;
  requests: FindingImportRequest[];
}

export interface ExternalPublicationPreview extends VendorFindings {
  accountId: string;
  destination: ImportRepository;
  source: FindingImportRequest["source"];
  resumed: boolean;
  requests: FindingImportRequest[];
}

export interface PreparedExternalPublication {
  preview: ExternalPublicationPreview;
  publish(): Promise<{
    receipts: FindingImportReceipt[];
    counts: FindingImportReceipt["counts"];
    cloudUrl: string;
  }>;
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
  if (!options.sourceKey.trim() || Buffer.byteLength(options.sourceKey) > 512) {
    throw new CodexSecurityError(
      "The source key must contain 1–512 UTF-8 bytes and identify the stable vendor namespace.",
    );
  }
  const parsed = await readVendorFindings(path);
  if (parsed.findings.length === 0) {
    throw new CodexSecurityError(
      `No supported findings are ready to publish. ${parsed.excluded.map((item) => `Item ${item.position}: ${item.reason}`).join(" ")}`,
    );
  }
  const environment = dependencies.environment ?? process.env;
  const credentials = await (
    dependencies.credentials ?? (() => readCloudCredentials(environment))
  )();
  async function request(
    endpoint: string,
    body?: FindingImportRequest,
  ): Promise<unknown> {
    dependencies.signal?.throwIfAborted();
    const response = await (dependencies.fetch ?? globalThis.fetch)(
      `${BASE_URL}${endpoint}`,
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
          ? AbortSignal.any([dependencies.signal, AbortSignal.timeout(30_000)])
          : AbortSignal.timeout(30_000),
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
        `/repositories?limit=100${page ? `&page=${encodeURIComponent(page)}` : ""}`,
      ),
    );
    destinations.push(
      ...result.data.filter((item) => item.id === options.repository),
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
        ? "The repository ID matches multiple connectors. Select an unambiguous Cloud repository."
        : "The destination repository is not available to this Cloud account.",
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
      credentials.account_id,
      options.repository,
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
          if (current === serialized) await rm(pendingPath);
        });
        throw new CloudImportError(
          409,
          "The repository was reset after this submission. The saved request was retired without uploading. Review the destination and run the command again to approve a fresh publication.",
        );
      }
      if (
        submission.repository.environment_id !==
        destination.import_environment_id
      ) {
        throw new Error(
          "The Cloud environment changed since this submission. Restore the original destination before resuming the saved request.",
        );
      }
    }
    saved = content;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (destination.import_environment_id == null)
    throw new CodexSecurityError(
      "Configure an authorized Cloud environment for this repository before importing findings.",
    );
  let requests = saved?.requests;
  if (!requests) {
    const repository = {
      id: destination.id,
      repo_connector_id: destination.repo_connector_id,
      environment_id: destination.import_environment_id,
      reset_marker: destination.reset_marker,
    };
    requests = [];
    let current: FindingImportRequest = {
      request_id: randomUUID(),
      repository,
      source,
      items: [],
    };
    for (const [index, finding] of parsed.findings.entries()) {
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
      const item = {
        client_id: `item-${index + 1}`,
        source_finding_id: finding.source_finding_id,
        expected_version: previous?.version ?? 0,
        evidence: finding.evidence,
      };
      if (
        current.items.length > 0 &&
        (current.items.length === 100 ||
          Buffer.byteLength(
            JSON.stringify({ ...current, items: [...current.items, item] }),
          ) > MAX_REQUEST_BYTES)
      ) {
        requests.push(validateImportRequest(current));
        current = { request_id: randomUUID(), repository, source, items: [] };
      }
      current.items.push(item);
    }
    if (current.items.length) requests.push(validateImportRequest(current));
  }
  const submission: SavedSubmission = {
    accountId: credentials.account_id,
    requests,
  };
  const preview: ExternalPublicationPreview = {
    ...parsed,
    accountId: credentials.account_id,
    destination,
    source,
    resumed: saved !== undefined,
    requests,
  };
  return {
    preview,
    async publish() {
      return await withImportLock(state, key, dependencies.signal, async () => {
        // Install a fully written file atomically. A crash during serialization
        // must not leave a partial request that cannot be resumed.
        const pendingTemporary = `${pendingPath}.${randomUUID()}.tmp`;
        const pendingFile = await open(pendingTemporary, "wx", 0o600);
        try {
          await pendingFile.writeFile(JSON.stringify(submission));
          await pendingFile.sync();
        } finally {
          await pendingFile.close();
        }
        try {
          await link(pendingTemporary, pendingPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
          const other = JSON.parse(
            await readFile(pendingPath, "utf8"),
          ) as SavedSubmission;
          if (canonicalJson(other) !== canonicalJson(submission)) {
            throw new CodexSecurityError(
              "Another publication prepared this input. Run the command again to review and resume that saved request.",
            );
          }
        } finally {
          await rm(pendingTemporary, { force: true });
        }
        const receipts: FindingImportReceipt[] = [];
        try {
          for (const batch of requests) {
            const receipt = validateImportReceipt(
              await request("/finding_imports", batch),
            );
            if (
              receipt.id !== batch.request_id ||
              canonicalJson(receipt.repository) !==
                canonicalJson(batch.repository) ||
              canonicalJson(receipt.source) !== canonicalJson(batch.source) ||
              receipt.item_count !== batch.items.length ||
              receipt.results.length !== batch.items.length ||
              receipt.results.some(
                (item, index) =>
                  item.client_id !== batch.items[index]!.client_id,
              )
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
            receipts.push(receipt);
          }
          // Verify readable source records without mistaking a newer concurrent
          // observation for failure of the original, immutable import receipt.
          for (const [batchIndex, receipt] of receipts.entries()) {
            for (const [index, item] of receipt.results.entries()) {
              if (item.outcome === "error") continue;
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
                      canonicalJson(
                        requests[batchIndex]!.items[index]!.evidence,
                      ))) ||
                report.source_finding_id !==
                  requests[batchIndex]!.items[index]!.source_finding_id ||
                report.repo_id !== destination.id ||
                report.repo_connector_id !== destination.repo_connector_id ||
                canonicalJson(report.source) !== canonicalJson(source)
              )
                throw new CodexSecurityError(
                  "Cloud readback did not match the saved finding identity.",
                );
            }
          }
        } catch (error) {
          if (error instanceof CloudImportError && error.status === 409)
            await rm(pendingPath, { force: true });
          throw new CodexSecurityError(
            `${error instanceof Error ? error.message : String(error)} ${error instanceof CloudImportError && error.status === 409 ? "The old submission was retired. Rediscover and approve a fresh publication." : `Repeat the same command to resume the saved request. Saved submission: ${pendingPath}`}`,
            { cause: error },
          );
        }
        const counts = { created: 0, updated: 0, unchanged: 0, error: 0 };
        for (const receipt of receipts)
          for (const outcome of Object.keys(counts) as (keyof typeof counts)[])
            counts[outcome] += receipt.counts[outcome] ?? 0;
        const result = {
          receipts,
          counts,
          cloudUrl: `https://chatgpt.com/codex/cloud/security/findings?repo=${encodeURIComponent(destination.url)}&source=imported&provider=${source.provider}`,
        };
        const temporary = `${pendingPath}.${randomUUID()}.tmp`;
        const file = await open(temporary, "wx", 0o600);
        try {
          await file.writeFile(JSON.stringify(result));
          await file.sync();
        } finally {
          await file.close();
        }
        await rename(temporary, join(state, `${key}.result.json`));
        await rm(pendingPath, { force: true });
        return result;
      });
    },
  };
}
