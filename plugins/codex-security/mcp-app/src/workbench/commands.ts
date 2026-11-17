import { parseJson } from "../helpers/json";
import { openWorkbenchDatabase, workbenchDatabasePath } from "./database";
import { localDedupe, type LocalDedupeRequest } from "./local-dedupe";
import {
  listStoredFindings,
  storeFindings,
  type EmbeddedFinding,
} from "./findings";
import {
  findPotentialDuplicates,
  listDedupeGroups,
  storeDedupeGroups,
} from "./duplicates";
import {
  listExternalFindings,
  listExternalImports,
  storeExternalFindings,
  type ExternalFindingSelection,
  type ExternalFindingsImport,
} from "./external-findings";
import {
  listExternalFindingPublications,
  recordExternalFindingPublications,
  type ExternalPublicationLinks,
} from "./external-finding-publications";

import {
  readSeverityClassification,
  severityCheckpoint,
  type SeverityCheckpoint,
} from "./severity";

export async function workbenchCommand(
  command: string,
  input: string,
  scanId?: string,
): Promise<unknown> {
  const request = parseJson(input) as {
    stateDirectory: string;
    payload: unknown;
  };
  const { stateDirectory, payload } = request;
  if (command === "read-severity-classification") {
    const selectedScanId = scanId ?? (payload as { scanId?: unknown })?.scanId;
    if (typeof selectedScanId !== "string")
      throw new Error("read-severity-classification requires --scan-id.");
    return readSeverityClassification(
      workbenchDatabasePath(stateDirectory),
      selectedScanId,
    );
  }
  const page = payload as { limit: number; offset: number };
  if (
    command === "list-stored-findings" &&
    (!Number.isSafeInteger(page.limit) ||
      page.limit <= 0 ||
      !Number.isSafeInteger(page.offset) ||
      page.offset < 0)
  )
    throw new Error(
      "limit must be a positive integer and offset a non-negative integer.",
    );
  const selection = payload as {
    findingId: string;
    cacheKeys?: Record<string, string>;
    scope?: { repositoryId?: string; allRepositories?: true };
  };
  if (
    (command === "find-potential-duplicates" ||
      command === "list-dedupe-groups") &&
    typeof selection?.findingId !== "string"
  )
    throw new Error("findingId must be a string.");
  if (command === "find-potential-duplicates") {
    const scope = selection.scope;
    if (
      !(
        typeof scope?.repositoryId === "string" &&
        scope.allRepositories === undefined
      ) &&
      !(scope?.allRepositories === true && scope.repositoryId === undefined)
    )
      throw new Error(
        "scope must specify either repositoryId or allRepositories: true.",
      );
  }
  const database = await openWorkbenchDatabase(
    workbenchDatabasePath(stateDirectory),
    {
      deferred:
        command !== "local-dedupe" &&
        command !== "store-findings" &&
        command !== "store-external-findings" &&
        command !== "record-external-finding-publications" &&
        command !== "store-dedupe-groups" &&
        command !== "severity-classification",
    },
  );
  try {
    if (command === "local-dedupe")
      return localDedupe(
        database,
        payload as LocalDedupeRequest,
        new Date().toISOString(),
      );
    if (command === "store-external-findings")
      return storeExternalFindings(
        database,
        payload as ExternalFindingsImport,
        new Date().toISOString(),
      );
    if (command === "read-external-findings")
      return listExternalFindings(
        database,
        payload as ExternalFindingSelection,
      );
    if (command === "list-external-imports")
      return listExternalImports(database, payload as { repository: string });
    if (command === "record-external-finding-publications")
      return recordExternalFindingPublications(
        database,
        payload as ExternalPublicationLinks,
        new Date().toISOString(),
      );
    if (command === "list-external-finding-publications")
      return listExternalFindingPublications(
        database,
        payload as { repository: string; id?: string },
      );
    if (command === "severity-classification")
      return severityCheckpoint(
        database,
        payload as SeverityCheckpoint,
        new Date().toISOString(),
      );
    if (command === "store-findings") {
      const { entries, repositoryId } = payload as {
        entries: EmbeddedFinding[];
        repositoryId?: string;
      };
      return storeFindings(
        database,
        entries,
        new Date().toISOString(),
        repositoryId,
      );
    }
    if (command === "store-dedupe-groups")
      return storeDedupeGroups(
        database,
        (payload as { groups: string[][] }).groups,
        new Date().toISOString(),
        selection.cacheKeys,
      );
    if (command === "list-dedupe-groups")
      return listDedupeGroups(database, selection.findingId);
    if (command === "find-potential-duplicates")
      return findPotentialDuplicates(
        database,
        selection.findingId,
        selection.scope!.repositoryId,
        selection.cacheKeys,
      );
    return listStoredFindings(database, page);
  } finally {
    database.close();
  }
}
