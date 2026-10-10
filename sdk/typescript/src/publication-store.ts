import { findingEntry } from "./value.js";
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

export async function inspectPublicationStore(
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<PublishedScanIssue[]> {
  const result = await runPublicationWorkbench(
    "inspect-linear-publication",
    publication,
    environment,
    undefined,
    signal,
  );
  const recorded = result["recorded"];
  if (
    !matchesPublication(result, publication) ||
    result["findingCount"] !==
      (publication.sourceFindings ?? publication.issues).length ||
    !Array.isArray(recorded)
  ) {
    throw invalidPublicationRecords();
  }
  const expected = new Map(
    (publication.sourceFindings ?? publication.issues).map((issue) => [
      issue.findingId,
      issue.occurrenceId,
    ]),
  );
  const found = new Map<string, PublishedScanIssue>();
  for (const value of recorded) {
    const issue = readPublicationRecord(value);
    if (
      expected.get(issue.findingId) !== issue.occurrenceId ||
      found.has(issue.findingId)
    ) {
      throw invalidPublicationRecords();
    }
    found.set(issue.findingId, issue);
  }
  return publication.issues.flatMap(({ findingId }) => {
    const issue = found.get(findingId);
    return issue === undefined ? [] : [issue];
  });
}

export async function preparePublicationStore(
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
): Promise<void> {
  const result = await runPublicationWorkbench(
    "prepare-linear-publication",
    publication,
    environment,
  );
  if (
    result["scanId"] !== publication.scanId ||
    result["findingCount"] !==
      (publication.sourceFindings ?? publication.issues).length
  ) {
    throw new CodexSecurityError(
      "The workbench could not verify every finding selected for publication.",
    );
  }
}

export async function recordPublishedIssues(
  publication: PreparedScanPublication,
  issues: readonly PublishedScanIssue[],
  environment: NodeJS.ProcessEnv,
): Promise<PublishedScanIssue[]> {
  const result = await runPublicationWorkbench(
    "record-linear-publications",
    publication,
    environment,
    issues,
  );
  const created = result["created"];
  if (
    !matchesPublication(result, publication) ||
    !Array.isArray(created) ||
    created.length !== issues.length
  ) {
    throw invalidPublicationRecords();
  }

  const expected = new Map(issues.map(findingEntry));
  const ordered = publication.issues.flatMap((issue) => {
    const record = expected.get(issue.findingId);
    return record === undefined ? [] : [record];
  });
  if (expected.size !== issues.length || ordered.length !== issues.length) {
    throw invalidPublicationRecords();
  }

  return created.map((value, index) => {
    const expectedIssue = ordered[index]!;
    const issue = readPublicationRecord(value);
    if (
      issue.findingId !== expectedIssue.findingId ||
      issue.occurrenceId !== expectedIssue.occurrenceId ||
      issue.issueIdentifier !== expectedIssue.issueIdentifier ||
      (expectedIssue.url !== undefined && issue.url !== expectedIssue.url)
    ) {
      throw invalidPublicationRecords();
    }
    return issue;
  });
}

async function runPublicationWorkbench(
  command:
    | "inspect-linear-publication"
    | "prepare-linear-publication"
    | "record-linear-publications",
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  issues?: readonly PublishedScanIssue[],
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
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
    ...(signal === undefined ? {} : { signal }),
  });
  signal?.throwIfAborted();
  const findings = (publication.sourceFindings ?? publication.issues).map(
    ({ findingId, occurrenceId }) => ({
      findingId,
      occurrenceId,
    }),
  );
  return await runWorkbench(
    {
      python,
      pluginRoot,
      environment,
      ...(signal === undefined ? {} : { signal }),
      failureMessage:
        command === "record-linear-publications"
          ? "Could not persist created Linear issues in the local Codex Security scan history"
          : "Cannot publish findings without their existing local Codex Security scan history",
    },
    [command],
    JSON.stringify({
      scanId: publication.scanId,
      scanDirectory: publication.scanDirectory,
      destination: publication.destination,
      findings,
      ...(issues === undefined ? {} : { publications: issues }),
    }),
  );
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

function readPublicationRecord(value: unknown): PublishedScanIssue {
  if (
    !isRecord(value) ||
    typeof value["findingId"] !== "string" ||
    typeof value["occurrenceId"] !== "string" ||
    typeof value["issueIdentifier"] !== "string" ||
    !value["issueIdentifier"].trim() ||
    (value["url"] !== undefined && typeof value["url"] !== "string")
  ) {
    throw invalidPublicationRecords();
  }
  return {
    findingId: value["findingId"],
    occurrenceId: value["occurrenceId"],
    issueIdentifier: value["issueIdentifier"],
    ...(typeof value["url"] === "string" ? { url: value["url"] } : {}),
  };
}

function invalidPublicationRecords(): CodexSecurityError {
  return new CodexSecurityError(
    "The workbench returned invalid persisted Linear publication records.",
  );
}
