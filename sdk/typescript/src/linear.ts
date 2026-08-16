import {
  AuthenticationLinearError,
  ForbiddenLinearError,
  LinearClient,
  RatelimitedLinearError,
} from "@linear/sdk";
import type { JsonObject } from "./config.js";
import { CodexSecurityError, safeErrorMessage } from "./errors.js";

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
    const message = safeErrorMessage(error);
    throw new CodexSecurityError(
      `Linear request failed: ${message.includes(credential) ? "[redacted]" : message}`,
    );
  }
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
