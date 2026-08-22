import {
  AuthenticationLinearError,
  ForbiddenLinearError,
  LinearClient,
  RatelimitedLinearError,
} from "@linear/sdk";
import type { JsonObject } from "./config.js";
import { CodexSecurityError, safeErrorMessage } from "./errors.js";
import type { LinearPublicationLabel } from "./publication.js";

export interface LinearPublicationCatalogLabel extends LinearPublicationLabel {
  groupId?: string;
  groupName?: string;
}

export type LinearClientFactory<
  Method extends keyof LinearClient = "issue" | "projects",
> = (
  options: ConstructorParameters<typeof LinearClient>[0],
) => Pick<LinearClient, Method>;

export function resolveLinearApiKey(
  environment: NodeJS.ProcessEnv,
  explicit?: string,
): string | undefined {
  return (
    explicit?.trim() ||
    environment["CODEX_SECURITY_LINEAR_API_KEY"]?.trim() ||
    undefined
  );
}

export function createLinearClient<Method extends keyof LinearClient>(
  options: ConstructorParameters<typeof LinearClient>[0],
  factory?: LinearClientFactory<Method>,
): Pick<LinearClient, Method> {
  const configuration = { ...options, redirect: "error" as const };
  return factory ? factory(configuration) : new LinearClient(configuration);
}

export interface LinearPublicationContext {
  labels: LinearPublicationCatalogLabel[];
}

export async function loadLinearPublicationContext(
  client: Pick<LinearClient, "team" | "project" | "issueLabels">,
  teamId: string,
  projectId?: string,
): Promise<LinearPublicationContext> {
  const team = await client.team(teamId);
  if (team === undefined || team.id !== teamId) {
    throw new CodexSecurityError(
      "The selected Linear team was not found or is not accessible.",
    );
  }

  if (projectId !== undefined) {
    const project = await client.project(projectId);
    if (project === undefined || project.id !== projectId) {
      throw new CodexSecurityError(
        "The selected Linear project was not found or is not accessible.",
      );
    }
    const teams = await project.teams({ first: 50 });
    while (teams.pageInfo.hasNextPage) await teams.fetchNext();
    if (!teams.nodes.some(({ id }) => id === teamId)) {
      throw new CodexSecurityError(
        "The selected Linear project does not belong to the selected team.",
      );
    }
  }

  const page = await team.labels({ first: 50 });
  while (page.pageInfo.hasNextPage) await page.fetchNext();
  const workspacePage = await client.issueLabels({
    first: 50,
    filter: { team: { null: true } },
  });
  while (workspacePage.pageInfo.hasNextPage) {
    await workspacePage.fetchNext();
  }
  const applicableLabels = [
    ...page.nodes,
    ...workspacePage.nodes.filter(({ teamId }) => teamId === undefined),
  ];
  const labels = new Map<string, LinearPublicationCatalogLabel>();
  const groupNames = new Map(
    applicableLabels
      .filter(
        (label) =>
          label.isGroup &&
          label.archivedAt === undefined &&
          label.retiredById === undefined,
      )
      .map((label) => [label.id, label.name]),
  );
  for (const label of applicableLabels) {
    if (
      label.isGroup ||
      label.archivedAt !== undefined ||
      label.retiredById !== undefined
    ) {
      continue;
    }
    labels.set(label.id, {
      id: label.id,
      name: label.name,
      ...(label.parentId === undefined ? {} : { groupId: label.parentId }),
      ...(label.parentId === undefined ||
      groupNames.get(label.parentId) === undefined
        ? {}
        : { groupName: groupNames.get(label.parentId)! }),
    });
  }
  return {
    labels: [...labels.values()].sort(
      (left, right) =>
        left.name.localeCompare(right.name) || left.id.localeCompare(right.id),
    ),
  };
}

export interface ImportedIssue {
  source: "linear";
  id: string;
  url: string;
  text: string;
}

export async function importLinearIssues(options: {
  issues: readonly string[];
  project?: string;
  filter?: string;
  apiKey?: string;
  environment: NodeJS.ProcessEnv;
  linearClient?: LinearClientFactory;
}): Promise<ImportedIssue[]> {
  const apiKey =
    resolveLinearApiKey(options.environment, options.apiKey) ||
    options.environment["LINEAR_API_KEY"]?.trim();
  const accessToken = options.environment["LINEAR_ACCESS_TOKEN"]?.trim();
  const credential = apiKey || accessToken;
  if (!credential) {
    throw new CodexSecurityError(
      "Linear access requires CODEX_SECURITY_LINEAR_API_KEY, LINEAR_API_KEY, or LINEAR_ACCESS_TOKEN.",
    );
  }

  const client = createLinearClient(
    apiKey ? { apiKey } : { accessToken },
    options.linearClient,
  );

  try {
    const issues: Awaited<ReturnType<LinearClient["issue"]>>[] = [];
    if (options.project !== undefined) {
      const suppliedFilter = linearIssueFilter(options.filter);
      const filter = Object.hasOwn(suppliedFilter, "state")
        ? suppliedFilter
        : {
            state: { type: { nin: ["completed", "canceled"] } },
            ...suppliedFilter,
          };
      const projects = await client.projects({
        filter: { name: { eqIgnoreCase: options.project } },
        first: 2,
      });
      if (projects.nodes.length !== 1) {
        throw new CodexSecurityError(
          `Linear project "${options.project}" ${projects.nodes.length === 0 ? "was not found or is not accessible" : "is ambiguous"}.`,
        );
      }

      const page = await projects.nodes[0]!.issues({ first: 50, filter });
      while (page.pageInfo.hasNextPage) await page.fetchNext();
      issues.push(...page.nodes);
      if (issues.length === 0) {
        throw new CodexSecurityError(
          `No open Linear issues matched project "${options.project}" and its filter.`,
        );
      }
    } else {
      for (const input of options.issues) {
        const { id, workspace } = linearIssueReference(input);
        const issue = await client.issue(id);
        if (!issue) {
          throw new CodexSecurityError(
            `Linear issue "${id}" was not found or is not accessible.`,
          );
        }
        if (
          workspace !== undefined &&
          linearIssueReference(issue.url).workspace !== workspace
        ) {
          throw new CodexSecurityError(
            "Fetched Linear issue does not match the workspace in the selected URL.",
          );
        }
        issues.push(issue);
      }
    }

    return issues.map(({ identifier, title, url, description }) => ({
      source: "linear",
      id: identifier,
      url,
      text: `Title: ${title}\n\n${description ?? ""}`,
    }));
  } catch (error) {
    if (error instanceof CodexSecurityError) throw error;
    if (
      error instanceof AuthenticationLinearError ||
      error instanceof ForbiddenLinearError
    ) {
      throw new CodexSecurityError("Linear authentication failed.");
    }
    if (error instanceof RatelimitedLinearError) {
      throw new CodexSecurityError(
        "Linear request was rate limited. Wait and retry.",
      );
    }
    throw new CodexSecurityError(
      `Linear request failed: ${safeLinearErrorMessage(error, credential)}`,
    );
  }
}

export function safeLinearErrorMessage(
  error: unknown,
  credential: string | undefined,
): string {
  return redactLinearCredential(safeErrorMessage(error), credential);
}

export function redactLinearCredential(
  message: string,
  credential: string | undefined,
): string {
  return credential === undefined || !message.includes(credential)
    ? message
    : message.replaceAll(credential, "[redacted]");
}

function linearIssueFilter(input: string | undefined): JsonObject {
  if (input === undefined) return {};
  let filter: unknown;
  try {
    filter = JSON.parse(input);
  } catch {
    filter = null;
  }
  if (typeof filter === "object" && filter !== null && !Array.isArray(filter)) {
    return filter as JsonObject;
  }
  throw new CodexSecurityError(
    "--linear-filter must be a JSON Linear issue filter.",
  );
}

function linearIssueReference(input: string): {
  id: string;
  workspace?: string;
} {
  if (!/^https?:\/\//iu.test(input)) return { id: input };
  const url = new URL(input);
  const match = /^\/([^/]+)\/issue\/([A-Z][A-Z0-9]*-\d+)(?:\/|$)/iu.exec(
    url.pathname,
  );
  if (url.hostname !== "linear.app" || match === null) {
    throw new CodexSecurityError("Linear issue URL is invalid.");
  }
  return { id: match[2]!, workspace: match[1]!.toLowerCase() };
}
