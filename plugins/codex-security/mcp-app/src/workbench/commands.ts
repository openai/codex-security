import { parseJson } from "../helpers/json";
import { openWorkbenchDatabase, workbenchDatabasePath } from "./database";
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

import { dashboard, type DashboardQuery } from "./dashboard";

export async function findingsCommand(
  command: string,
  input: string,
): Promise<unknown> {
  const request = parseJson(input) as {
    stateDirectory: string;
    payload: unknown;
  };
  const { stateDirectory, payload } = request;
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
        command !== "store-findings" && command !== "store-dedupe-groups",
    },
  );
  try {
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
      );
    if (command === "list-dedupe-groups")
      return listDedupeGroups(database, selection.findingId);
    if (command === "find-potential-duplicates")
      return findPotentialDuplicates(
        database,
        selection.findingId,
        selection.scope!.repositoryId,
      );
    if (command === "dashboard")
      return dashboard(database, payload as DashboardQuery);
    return listStoredFindings(database, page);
  } finally {
    database.close();
  }
}
