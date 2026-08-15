import { CodexSecurityError, ConfigurationError } from "./errors.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "./publication.js";

const LINEAR_GRAPHQL_ENDPOINT = "https://api.linear.app/graphql";

const DESTINATION_QUERY = `query CodexSecurityLinearDestination($teamId: String!, $projectId: String!) {
  viewer { id }
  team(id: $teamId) { id }
  project(id: $projectId) { id teams { nodes { id } } }
}`;

const ASSIGNEE_BY_EMAIL_QUERY = `query CodexSecurityLinearAssigneeByEmail($email: String!) {
  users(filter: { email: { eqIgnoreCase: $email } }, first: 2) { nodes { id email } }
}`;

const ASSIGNEE_BY_ID_QUERY = `query CodexSecurityLinearAssigneeById($id: String!) {
  user(id: $id) { id }
}`;

const CREATE_ISSUE_MUTATION = `mutation CodexSecurityLinearIssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue {
      identifier
      url
      title
      description
      priority
      team { id }
      project { id }
      assignee { id }
    }
  }
}`;

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
  fetchImpl: typeof fetch = fetch,
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

  const destination = await linearRequest(
    DESTINATION_QUERY,
    {
      teamId: publication.destination.teamId,
      projectId: publication.destination.projectId,
    },
    "destination verification",
    apiKey,
    fetchImpl,
    signal,
  );
  const viewer = destination["viewer"];
  const team = destination["team"];
  const project = destination["project"];
  const projectTeams = isRecord(project) ? project["teams"] : undefined;
  const nodes = isRecord(projectTeams) ? projectTeams["nodes"] : undefined;
  if (
    !isRecord(viewer) ||
    !validIdentifier(viewer["id"]) ||
    !isRecord(team) ||
    team["id"] !== publication.destination.teamId ||
    !isRecord(project) ||
    project["id"] !== publication.destination.projectId ||
    !Array.isArray(nodes) ||
    !nodes.some(
      (node) => isRecord(node) && node["id"] === publication.destination.teamId,
    )
  ) {
    throw new CodexSecurityError(
      "Linear could not verify the authenticated user, team, and project.",
    );
  }

  const resolvedAssignee =
    assigneeId === undefined
      ? viewer["id"]
      : await resolveLinearAssignee(assigneeId, apiKey, fetchImpl, signal);
  if (!validIdentifier(resolvedAssignee)) {
    throw new CodexSecurityError("Linear returned an invalid issue assignee.");
  }

  return {
    assigneeId: resolvedAssignee,
    create: async (issue) => {
      signal?.throwIfAborted();
      const data = await linearRequest(
        CREATE_ISSUE_MUTATION,
        {
          input: {
            teamId: publication.destination.teamId,
            projectId: publication.destination.projectId,
            title: issue.title,
            description: issue.description,
            assigneeId: resolvedAssignee,
            ...(issue.priority === undefined
              ? {}
              : { priority: issue.priority }),
          },
        },
        "issue creation",
        apiKey,
        fetchImpl,
        signal,
      );
      const mutation = data["issueCreate"];
      const created = isRecord(mutation) ? mutation["issue"] : undefined;
      const createdTeam = isRecord(created) ? created["team"] : undefined;
      const createdProject = isRecord(created) ? created["project"] : undefined;
      const createdAssignee = isRecord(created)
        ? created["assignee"]
        : undefined;
      if (
        !isRecord(mutation) ||
        mutation["success"] !== true ||
        !isRecord(created) ||
        !validIdentifier(created["identifier"]) ||
        !validLinearUrl(created["url"]) ||
        created["title"] !== issue.title ||
        created["description"] !== issue.description ||
        (issue.priority === undefined
          ? created["priority"] !== 0 && created["priority"] !== null
          : created["priority"] !== issue.priority) ||
        !isRecord(createdTeam) ||
        createdTeam["id"] !== publication.destination.teamId ||
        !isRecord(createdProject) ||
        createdProject["id"] !== publication.destination.projectId ||
        !isRecord(createdAssignee) ||
        createdAssignee["id"] !== resolvedAssignee
      ) {
        throw new CodexSecurityError(
          "Linear returned an unverified created issue; do not retry without checking the destination.",
        );
      }
      return {
        issueIdentifier: created["identifier"],
        url: created["url"],
      };
    },
  };
}

async function resolveLinearAssignee(
  assigneeId: string,
  apiKey: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<string> {
  if (assigneeId.includes("@")) {
    const data = await linearRequest(
      ASSIGNEE_BY_EMAIL_QUERY,
      { email: assigneeId },
      "assignee lookup",
      apiKey,
      fetchImpl,
      signal,
    );
    const users = data["users"];
    const nodes = isRecord(users) ? users["nodes"] : undefined;
    const user = Array.isArray(nodes) && nodes.length === 1 ? nodes[0] : null;
    if (
      !isRecord(user) ||
      !validIdentifier(user["id"]) ||
      typeof user["email"] !== "string" ||
      user["email"].toLowerCase() !== assigneeId.toLowerCase()
    ) {
      throw new CodexSecurityError(
        "Linear could not resolve exactly one matching issue assignee.",
      );
    }
    return user["id"];
  }

  const data = await linearRequest(
    ASSIGNEE_BY_ID_QUERY,
    { id: assigneeId },
    "assignee lookup",
    apiKey,
    fetchImpl,
    signal,
  );
  const user = data["user"];
  if (!isRecord(user) || user["id"] !== assigneeId) {
    throw new CodexSecurityError(
      "Linear could not resolve the requested issue assignee.",
    );
  }
  return assigneeId;
}

async function linearRequest(
  query: string,
  variables: Record<string, unknown>,
  operation: string,
  apiKey: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  signal?.throwIfAborted();
  let response: Response;
  try {
    response = await fetchImpl(LINEAR_GRAPHQL_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: apiKey,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ query, variables }),
      redirect: "error",
      ...(signal === undefined ? {} : { signal }),
    });
  } catch {
    signal?.throwIfAborted();
    throw new CodexSecurityError(`Linear ${operation} could not be completed.`);
  }

  if (response.status === 401 || response.status === 403) {
    throw new CodexSecurityError("Linear rejected the supplied API key.");
  }
  if (response.status === 429) {
    throw new CodexSecurityError(
      `Linear rate-limited ${operation}; do not retry until existing issues are checked.`,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    signal?.throwIfAborted();
    throw new CodexSecurityError(
      `Linear ${operation} returned an unreadable response.`,
    );
  }
  const errors = isRecord(payload) ? payload["errors"] : undefined;
  if (
    Array.isArray(errors) &&
    errors.some((error) => {
      const extensions = isRecord(error) ? error["extensions"] : undefined;
      return isRecord(extensions) && extensions["code"] === "RATELIMITED";
    })
  ) {
    throw new CodexSecurityError(
      `Linear rate-limited ${operation}; do not retry until existing issues are checked.`,
    );
  }
  if (!response.ok || (Array.isArray(errors) && errors.length !== 0)) {
    throw new CodexSecurityError(`Linear ${operation} was rejected.`);
  }
  if (!isRecord(payload) || !isRecord(payload["data"])) {
    throw new CodexSecurityError(
      `Linear ${operation} returned an invalid response.`,
    );
  }
  return payload["data"];
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
