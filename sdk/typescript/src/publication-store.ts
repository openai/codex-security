import { mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import type { PreparedScanPublication } from "./publication.js";
import type { PublishedScanIssue } from "./publish.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  requireOutputOutsideRepository,
  resolvePluginPython,
  runWorkbench,
} from "./runtime.js";

type StoredPublicationIssue = PublishedScanIssue & { attemptId?: string };

export async function inspectPublicationStore(
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
  all = false,
): Promise<StoredPublicationIssue[]> {
  const result = await runPublicationWorkbench(
    "inspect-linear-publication",
    publication,
    environment,
    undefined,
    signal,
  );
  const recorded = result[all ? "publications" : "recorded"];
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
  const found = new Map<string, StoredPublicationIssue>();
  for (const value of recorded) {
    const issue = readPublicationRecord(value, all);
    const key = all ? issue.issueIdentifier : issue.findingId;
    if (
      expected.get(issue.findingId) !== issue.occurrenceId ||
      found.has(key)
    ) {
      throw invalidPublicationRecords();
    }
    found.set(key, issue);
  }
  if (all) {
    const selected = new Set(
      publication.issues.map((issue) => issue.findingId),
    );
    return [...found.values()].filter((issue) => selected.has(issue.findingId));
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
  attemptId?: string,
): Promise<PublishedScanIssue[]> {
  const result = await runPublicationWorkbench(
    "record-linear-publications",
    publication,
    environment,
    issues,
    undefined,
    attemptId,
  );
  const created = result["created"];
  if (
    !matchesPublication(result, publication) ||
    !Array.isArray(created) ||
    created.length !== issues.length
  ) {
    throw invalidPublicationRecords();
  }

  const expected = new Map(issues.map((issue) => [issue.findingId, issue]));
  const ordered = publication.issues.flatMap((issue) => {
    const record = expected.get(issue.findingId);
    return record === undefined ? [] : [record];
  });
  if (expected.size !== issues.length || ordered.length !== issues.length) {
    throw invalidPublicationRecords();
  }

  return created.map((value, index) => {
    const expectedIssue = ordered[index];
    const issue = readPublicationRecord(value);
    if (
      expectedIssue === undefined ||
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
  attemptId?: string,
): Promise<Record<string, unknown>> {
  signal?.throwIfAborted();
  const stateDirectory = codexSecurityStateDirectory(environment);
  const database = join(stateDirectory, "workbench.sqlite3");
  try {
    if (!(await stat(database)).isFile()) throw new Error("not a regular file");
  } catch (error) {
    throw new CodexSecurityError(
      "Cannot publish findings because the local Codex Security scan-history database does not exist. Use the state directory where this scan was completed.",
      { cause: error },
    );
  }
  const [python, pluginRoot] = await Promise.all([
    resolvePluginPython({
      environment,
      protectedRoot: publication.scanDirectory,
      ...(signal === undefined ? {} : { signal }),
    }),
    bundledPluginRoot(),
  ]);
  signal?.throwIfAborted();
  const findings = (publication.sourceFindings ?? publication.issues).map(
    ({ findingId, occurrenceId }) => ({
      findingId,
      occurrenceId,
    }),
  );
  let temporaryRoot = stateDirectory;
  if (command === "inspect-linear-publication") {
    temporaryRoot = await realpath(tmpdir());
    const scanRoot = await realpath(publication.scanDirectory);
    requireOutputOutsideRepository(scanRoot, temporaryRoot, "temporary");
  }
  const directory = await mkdtemp(join(temporaryRoot, "publication-"));
  try {
    const input = join(directory, "publication.json");
    await writeFile(
      input,
      JSON.stringify({
        scanId: publication.scanId,
        scanDirectory: publication.scanDirectory,
        destination: publication.destination,
        findings,
        ...(issues === undefined ? {} : { publications: issues }),
        ...(attemptId === undefined ? {} : { attemptId }),
      }),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
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
      [command, "--input-file", input],
    );
  } finally {
    await rm(directory, { recursive: true, force: true }).catch(
      () => undefined,
    );
  }
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

function readPublicationRecord(
  value: unknown,
  includeAttempt = false,
): StoredPublicationIssue {
  if (
    !isRecord(value) ||
    typeof value["findingId"] !== "string" ||
    typeof value["occurrenceId"] !== "string" ||
    typeof value["issueIdentifier"] !== "string" ||
    !value["issueIdentifier"].trim() ||
    (value["url"] !== undefined && typeof value["url"] !== "string") ||
    (includeAttempt &&
      value["attemptId"] !== undefined &&
      (typeof value["attemptId"] !== "string" || !value["attemptId"].trim()))
  ) {
    throw invalidPublicationRecords();
  }
  return {
    findingId: value["findingId"],
    occurrenceId: value["occurrenceId"],
    issueIdentifier: value["issueIdentifier"],
    ...(typeof value["url"] === "string" ? { url: value["url"] } : {}),
    ...(includeAttempt && typeof value["attemptId"] === "string"
      ? { attemptId: value["attemptId"] }
      : {}),
  };
}

function invalidPublicationRecords(): CodexSecurityError {
  return new CodexSecurityError(
    "The workbench returned invalid persisted Linear publication records.",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
