import { LinearClient, LinearError, type LinearSdk } from "@linear/sdk";
import { CodexSecurityError, ConfigurationError } from "./errors.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "./publication.js";

export type LinearClientFactory = (
  options: ConstructorParameters<typeof LinearClient>[0],
) => LinearSdk;

export interface PreparedLinearApiPublication {
  assigneeId: string;
  create(issue: PreparedPublicationIssue): Promise<{
    issueIdentifier: string;
    url?: string;
  }>;
}

export async function prepareLinearApiPublication(
  publication: PreparedScanPublication,
  apiKey: string,
  assigneeId: string | undefined,
  createClient: LinearClientFactory = (options) => new LinearClient(options),
  signal?: AbortSignal,
): Promise<PreparedLinearApiPublication> {
  signal?.throwIfAborted();
  if (
    apiKey.length === 0 ||
    apiKey !== apiKey.trim() ||
    /[\u0000-\u001F\u007F]/u.test(apiKey)
  ) {
    throw new ConfigurationError("A valid Linear API key is required.");
  }
  if (assigneeId !== undefined && !validIdentifier(assigneeId)) {
    throw new ConfigurationError("A valid Linear assignee is required.");
  }

  const client = createClient({
    apiKey,
    redirect: "error",
    ...(signal === undefined ? {} : { signal }),
  });
  const projectId = publication.destination.projectId;
  const viewer = await linearOperation(
    "destination verification",
    signal,
    () => client.viewer,
  );
  const team = await linearOperation("destination verification", signal, () =>
    client.team(publication.destination.teamId),
  );

  if (
    !validIdentifier(viewer?.id) ||
    team?.id !== publication.destination.teamId
  ) {
    throw destinationError(projectId);
  }

  if (projectId !== undefined) {
    const project = await linearOperation(
      "destination verification",
      signal,
      () => client.project(projectId),
    );
    if (project?.id !== projectId) throw destinationError(projectId);
    const projectTeams = await linearOperation(
      "destination verification",
      signal,
      () => project.teams(),
    );
    if (
      !projectTeams.nodes.some(
        (projectTeam) => projectTeam.id === publication.destination.teamId,
      )
    ) {
      throw destinationError(projectId);
    }
  }

  const resolvedAssignee =
    assigneeId === undefined
      ? viewer.id
      : await resolveLinearAssignee(client, assigneeId, signal);
  if (!validIdentifier(resolvedAssignee)) {
    throw new CodexSecurityError("Linear returned an invalid issue assignee.");
  }

  return {
    assigneeId: resolvedAssignee,
    create: async (issue) => {
      const mutation = await linearOperation("issue creation", signal, () =>
        client.createIssue({
          teamId: publication.destination.teamId,
          ...(projectId === undefined ? {} : { projectId }),
          title: issue.title,
          description: issue.description,
          assigneeId: resolvedAssignee,
          ...(issue.priority === undefined ? {} : { priority: issue.priority }),
        }),
      );
      if (mutation.success !== true || !validIdentifier(mutation.issueId)) {
        throw unverifiedIssueError();
      }
      const created = await linearOperation(
        "created issue verification",
        signal,
        () => mutation.issue!,
      );
      if (
        !validIdentifier(created?.identifier) ||
        !validLinearUrl(created.url) ||
        created.title !== issue.title ||
        created.description !== issue.description ||
        (issue.priority === undefined
          ? created.priority !== 0
          : created.priority !== issue.priority) ||
        created.teamId !== publication.destination.teamId ||
        created.projectId !== projectId ||
        created.assigneeId !== resolvedAssignee
      ) {
        throw unverifiedIssueError();
      }
      return {
        issueIdentifier: created.identifier,
        url: created.url,
      };
    },
  };
}

async function resolveLinearAssignee(
  client: LinearSdk,
  assigneeId: string,
  signal?: AbortSignal,
): Promise<string> {
  if (assigneeId.includes("@")) {
    const users = await linearOperation("assignee lookup", signal, () =>
      client.users({
        filter: { email: { eqIgnoreCase: assigneeId } },
        first: 2,
      }),
    );
    const user = users.nodes.length === 1 ? users.nodes[0] : undefined;
    if (
      user === undefined ||
      !validIdentifier(user.id) ||
      user.email.toLowerCase() !== assigneeId.toLowerCase()
    ) {
      throw new CodexSecurityError(
        "Linear could not resolve exactly one matching issue assignee.",
      );
    }
    return user.id;
  }

  const user = await linearOperation("assignee lookup", signal, () =>
    client.user(assigneeId),
  );
  if (user?.id !== assigneeId) {
    throw new CodexSecurityError(
      "Linear could not resolve the requested issue assignee.",
    );
  }
  return assigneeId;
}

async function linearOperation<T>(
  operation: string,
  signal: AbortSignal | undefined,
  execute: () => PromiseLike<T>,
): Promise<T> {
  signal?.throwIfAborted();
  try {
    return await execute();
  } catch (error) {
    signal?.throwIfAborted();
    const status = error instanceof LinearError ? error.status : undefined;
    if (status === 401 || status === 403) {
      throw new CodexSecurityError("Linear rejected the supplied API key.");
    }
    if (
      status === 429 ||
      (error instanceof LinearError &&
        (error.type === "Ratelimited" ||
          error.errors?.some(({ type }) => type === "Ratelimited") ||
          (
            error.raw as
              | {
                  response?: {
                    errors?: Array<{ extensions?: { code?: string } }>;
                  };
                }
              | undefined
          )?.response?.errors?.some(
            ({ extensions }) => extensions?.code === "RATELIMITED",
          )))
    ) {
      throw new CodexSecurityError(
        `Linear rate-limited ${operation}; do not retry until existing issues are checked.`,
      );
    }
    throw new CodexSecurityError(
      error instanceof LinearError
        ? `Linear ${operation} was rejected.`
        : `Linear ${operation} could not be completed.`,
    );
  }
}

function destinationError(projectId: string | undefined): CodexSecurityError {
  return new CodexSecurityError(
    projectId === undefined
      ? "Linear could not verify the authenticated user and team."
      : "Linear could not verify the authenticated user, team, and project.",
  );
}

function unverifiedIssueError(): CodexSecurityError {
  return new CodexSecurityError(
    "Linear returned an unverified created issue; do not retry without checking the destination.",
  );
}

function validIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim().length !== 0 &&
    value === value.trim() &&
    !/[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u.test(value)
  );
}

function validLinearUrl(value: unknown): value is string {
  if (!validIdentifier(value)) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return (
    parsed.protocol === "https:" &&
    parsed.hostname === "linear.app" &&
    parsed.username.length === 0 &&
    parsed.password.length === 0 &&
    parsed.search.length === 0 &&
    parsed.hash.length === 0
  );
}
