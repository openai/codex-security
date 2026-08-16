import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import type { PreparedScanPublication } from "./publication.js";
import type { PublishedScanIssue } from "./publish.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
} from "./runtime.js";

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
    result["findingCount"] !== publication.issues.length
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
  const destination = result["destination"];
  if (
    result["scanId"] !== publication.scanId ||
    !isRecord(destination) ||
    destination["type"] !== publication.destination.type ||
    destination["teamId"] !== publication.destination.teamId ||
    destination["projectId"] !== publication.destination.projectId ||
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
    if (
      !isRecord(value) ||
      expectedIssue === undefined ||
      value["findingId"] !== expectedIssue.findingId ||
      value["occurrenceId"] !== expectedIssue.occurrenceId ||
      value["issueIdentifier"] !== expectedIssue.issueIdentifier ||
      (value["url"] !== undefined && typeof value["url"] !== "string") ||
      (expectedIssue.url !== undefined && value["url"] !== expectedIssue.url)
    ) {
      throw invalidPublicationRecords();
    }

    return {
      findingId: value["findingId"] as string,
      occurrenceId: value["occurrenceId"] as string,
      issueIdentifier: value["issueIdentifier"] as string,
      ...(typeof value["url"] === "string" ? { url: value["url"] } : {}),
    };
  });
}

async function runPublicationWorkbench(
  command: "prepare-linear-publication" | "record-linear-publications",
  publication: PreparedScanPublication,
  environment: NodeJS.ProcessEnv,
  issues?: readonly PublishedScanIssue[],
): Promise<Record<string, unknown>> {
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
    }),
    bundledPluginRoot(),
  ]);
  const findings = publication.issues.map(({ findingId, occurrenceId }) => ({
    findingId,
    occurrenceId,
  }));
  const directory = await mkdtemp(join(stateDirectory, "publication-"));
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
      }),
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    return await runWorkbench(
      {
        python,
        pluginRoot,
        environment,
        failureMessage:
          command === "prepare-linear-publication"
            ? "Cannot publish findings without their existing local Codex Security scan history"
            : "Could not persist created Linear issues in the local Codex Security scan history",
      },
      [command, "--input-file", input],
    );
  } finally {
    await rm(directory, { recursive: true, force: true }).catch(
      () => undefined,
    );
  }
}

function invalidPublicationRecords(): CodexSecurityError {
  return new CodexSecurityError(
    "The workbench returned invalid persisted Linear publication records.",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
