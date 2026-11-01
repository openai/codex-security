import { z } from "zod";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { isRecord } from "./record.js";
import { CodexSecurityError } from "./errors.js";
import type { PreparedScanPublication } from "./publication.js";
import type { PublishedScanIssue } from "./publish.js";
import {
  codexSecurityStateDirectory,
  resolveWorkbenchRuntime,
  runWorkbench,
} from "./runtime.js";

type StoredIssue = PublishedScanIssue & { scanId: string };

export async function inspectPublicationStore(
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<PublishedScanIssue[]> {
  const receipts = await findingIssues(
    "inspect",
    publication,
    environment,
    [],
    signal,
  );
  return publication.issues.flatMap(({ findingId, occurrenceId }) => {
    // Tracking can reuse an issue across scans. CLI skipping remains specific to
    // the selected occurrence, irrespective of which workflow recorded it.
    const receipt = receipts.find(
      (issue) =>
        issue.scanId === publication.scanId &&
        issue.findingId === findingId &&
        issue.occurrenceId === occurrenceId,
    );
    return receipt === undefined ? [] : [publishedIssue(receipt)];
  });
}

export async function preparePublicationStore(
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
): Promise<void> {
  await findingIssues("prepare", publication, environment);
}

export async function recordPublishedIssues(
  publication: PreparedScanPublication,
  issues: readonly PublishedScanIssue[],
  environment: NodeJS.ProcessEnv,
): Promise<PublishedScanIssue[]> {
  const receipts = await findingIssues(
    "record",
    publication,
    environment,
    issues,
  );
  if (receipts.length !== issues.length) {
    throw invalidPublicationRecords();
  }
  const recorded = new Map<string, StoredIssue>();
  for (const [index, receipt] of receipts.entries()) {
    const expectedIssue = issues[index]!;
    if (
      receipt.scanId !== publication.scanId ||
      receipt.findingId !== expectedIssue.findingId ||
      receipt.occurrenceId !== expectedIssue.occurrenceId ||
      receipt.issueIdentifier !== expectedIssue.issueIdentifier ||
      (expectedIssue.url !== undefined && receipt.url !== expectedIssue.url) ||
      recorded.has(receipt.findingId)
    ) {
      throw invalidPublicationRecords();
    }
    recorded.set(receipt.findingId, receipt);
  }
  const ordered = publication.issues.flatMap(({ findingId }) => {
    const receipt = recorded.get(findingId);
    return receipt === undefined ? [] : [publishedIssue(receipt)];
  });
  if (ordered.length !== issues.length) throw invalidPublicationRecords();
  return ordered;
}

async function findingIssues(
  action: "inspect" | "prepare" | "record",
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  issues: readonly PublishedScanIssue[] = [],
  signal?: AbortSignal,
): Promise<StoredIssue[]> {
  signal?.throwIfAborted();
  const stateDirectory = codexSecurityStateDirectory(environment);
  const database = join(stateDirectory, "workbench.sqlite3");
  const metadata = await stat(database).catch((error: unknown) => {
    if (!isRecord(error) || error["code"] !== "ENOENT") throw error;
    throw new CodexSecurityError(
      "Cannot publish findings because the local Codex Security scan-history database does not exist. Use the state directory where this scan was completed.",
      { cause: error },
    );
  });
  if (!metadata.isFile()) {
    throw new CodexSecurityError(
      "Cannot publish findings because the local Codex Security scan-history database is not a regular file.",
    );
  }
  const [python, pluginRoot] = await resolveWorkbenchRuntime({
    environment,
    protectedRoot: publication.scanDirectory,
    signal,
  });
  signal?.throwIfAborted();
  const result = await runWorkbench(
    {
      python,
      pluginRoot,
      environment,
      signal,
      failureMessage:
        action === "record"
          ? "Could not persist created Linear issues in the local Codex Security scan history"
          : "Cannot publish findings without their existing local Codex Security scan history",
    },
    ["finding-issues"],
    JSON.stringify({
      action,
      scanDirectory: publication.scanDirectory,
      expectedScanId: publication.scanId,
      destination: publication.destination,
      findingIds: publication.issues.map(({ findingId }) => findingId),
      requireHistory: true,
      ...(action === "record"
        ? {
            receipts: issues.map((issue) => ({
              ...issue,
              operation: "create",
            })),
          }
        : {}),
    }),
  );
  const receipts = publicationRecordsSchema.safeParse(result["receipts"]);
  if (
    !matchesPublication(result, publication) ||
    result["findingCount"] !== publication.issues.length ||
    !receipts.success
  ) {
    throw invalidPublicationRecords();
  }
  const selected = new Map(
    publication.issues.map(({ findingId, occurrenceId }) => [
      findingId,
      occurrenceId,
    ]),
  );
  for (const receipt of receipts.data) {
    if (
      !selected.has(receipt.findingId) ||
      (receipt.scanId === publication.scanId &&
        selected.get(receipt.findingId) !== receipt.occurrenceId)
    ) {
      throw invalidPublicationRecords();
    }
  }
  return receipts.data;
}

function publishedIssue(issue: StoredIssue): PublishedScanIssue {
  return {
    findingId: issue.findingId,
    occurrenceId: issue.occurrenceId,
    issueIdentifier: issue.issueIdentifier,
    ...(issue.url === undefined ? {} : { url: issue.url }),
  };
}

function matchesPublication(
  result: Record<string, unknown>,
  publication: PreparedScanPublication,
): boolean {
  const destination = result["destination"];
  return (
    result["scanId"] === publication.scanId &&
    isRecord(destination) &&
    destination["type"] === publication.destination.type &&
    destination["teamId"] === publication.destination.teamId &&
    destination["projectId"] === publication.destination.projectId
  );
}

const publicationRecordsSchema = z
  .object({
    scanId: z.string(),
    findingId: z.string(),
    occurrenceId: z.string(),
    issueIdentifier: z.string().refine((value) => Boolean(value.trim())),
    url: z.string().optional(),
  })
  .array();

function invalidPublicationRecords(): CodexSecurityError {
  return new CodexSecurityError(
    "The workbench returned invalid persisted Linear publication records.",
  );
}
