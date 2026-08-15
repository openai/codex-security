import { describe, expect, spyOn, test } from "bun:test";
import { prepareLinearApiPublication } from "../src/linear-api.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "../src/publication.js";
import { mockLinearClient } from "./support/linear-client.js";

const API_KEY = "lin_api_synthetic_test_key";

function publication(): PreparedScanPublication {
  return {
    scanId: "scan-synthetic",
    uploadId: "scan-synthetic",
    scanDirectory: "/synthetic/sealed-scan",
    destination: {
      type: "linear",
      teamId: "team-synthetic",
      projectId: "project-synthetic",
    },
    issues: [
      {
        findingId: "finding-synthetic",
        occurrenceId: "occurrence-synthetic",
        title: "[Codex Security][HIGH] Synthetic finding",
        description: "Sensitive source evidence\n```ts\nunsafe(input)\n```",
        priority: 2,
      },
    ],
  };
}

function teamOnlyPublication(): PreparedScanPublication {
  const prepared = publication();
  delete (prepared.destination as { projectId?: string }).projectId;
  return prepared;
}

function destinationResponse(
  prepared: PreparedScanPublication,
  overrides: Record<string, unknown> = {},
): Response {
  return Response.json({
    data: {
      viewer: { id: "user-self" },
      team: { id: prepared.destination.teamId },
      ...(prepared.destination.projectId === undefined
        ? {}
        : {
            project: {
              id: prepared.destination.projectId,
              teams: { nodes: [{ id: prepared.destination.teamId }] },
            },
          }),
      ...overrides,
    },
  });
}

function issueResponse(
  prepared: PreparedScanPublication,
  issue: PreparedPublicationIssue,
  assigneeId = "user-self",
  overrides: Record<string, unknown> = {},
): Response {
  return Response.json({
    data: {
      issueCreate: {
        success: true,
        issue: {
          identifier: "SEC-123",
          url: "https://linear.app/example/issue/SEC-123/synthetic-finding",
          title: issue.title,
          description: issue.description,
          priority: issue.priority ?? 0,
          team: { id: prepared.destination.teamId },
          project:
            prepared.destination.projectId === undefined
              ? null
              : { id: prepared.destination.projectId },
          assignee: { id: assigneeId },
          ...overrides,
        },
      },
    },
  });
}

interface RecordedRequest {
  url: string;
  options: RequestInit;
  body: {
    query: string;
    variables: Record<string, unknown>;
  };
}

function mockedFetch(responses: Response[]): {
  fetchImpl: Parameters<typeof prepareLinearApiPublication>[3];
  rawFetch: typeof fetch;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  let destination: Record<string, unknown> | undefined;
  let createdIssue: Record<string, unknown> | undefined;
  const fetchImpl = async (
    url: Parameters<typeof fetch>[0],
    options?: Parameters<typeof fetch>[1],
  ): Promise<Response> => {
    const request = {
      url: url.toString(),
      options: options!,
      body: JSON.parse(options!.body as string) as RecordedRequest["body"],
    };
    requests.push(request);
    const operation = request.body.query.match(
      /\b(?:query|mutation)\s+(\w+)/u,
    )?.[1];
    if (operation === "team") {
      return Response.json({ data: { team: destination?.["team"] } });
    }
    if (operation === "project") {
      return Response.json({ data: { project: destination?.["project"] } });
    }
    if (operation === "project_teams") {
      const project = destination?.["project"] as
        | { teams?: { nodes?: unknown[] } }
        | undefined;
      return Response.json({
        data: {
          project: {
            teams: {
              nodes: project?.teams?.nodes ?? [],
              pageInfo: { hasNextPage: false, hasPreviousPage: false },
            },
          },
        },
      });
    }
    if (operation === "issue") {
      return Response.json({
        data: {
          issue: {
            ...createdIssue,
            sharedAccess: { sharedWithUsers: [] },
            reactions: [],
          },
        },
      });
    }

    const response = responses.shift();
    if (response === undefined) throw new Error("Unexpected synthetic request");
    let payload: Record<string, unknown>;
    try {
      payload = (await response.clone().json()) as Record<string, unknown>;
    } catch {
      return response;
    }
    if (Array.isArray(payload["errors"])) return response;
    const data = payload["data"] as Record<string, unknown> | undefined;
    if (operation === "viewer" && response.ok && data !== undefined) {
      destination = data;
      return Response.json({
        data: { viewer: data["viewer"] ?? { id: undefined } },
      });
    }
    if (operation === "users" && response.ok && data !== undefined) {
      const users = data["users"] as { nodes?: unknown[] } | undefined;
      return Response.json({
        data: {
          users: {
            nodes: users?.nodes ?? [],
            pageInfo: { hasNextPage: false, hasPreviousPage: false },
          },
        },
      });
    }
    if (operation === "createIssue" && response.ok && data !== undefined) {
      const mutation = data["issueCreate"] as
        | { success?: boolean; issue?: Record<string, unknown> }
        | undefined;
      createdIssue = {
        id: "issue-synthetic",
        ...mutation?.issue,
      };
      return Response.json({
        data: {
          issueCreate: {
            success: mutation?.success,
            issue: { id: createdIssue["id"] },
          },
        },
      });
    }
    return response;
  };
  return {
    fetchImpl: mockLinearClient(fetchImpl as unknown as typeof fetch),
    rawFetch: fetchImpl as unknown as typeof fetch,
    requests,
  };
}

describe("direct Linear API publication", () => {
  test("uses the official LinearClient for authenticated, abortable issue creation", async () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const controller = new AbortController();
    const { rawFetch, requests } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue),
    ]);
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(rawFetch);
    try {
      const client = await prepareLinearApiPublication(
        prepared,
        API_KEY,
        undefined,
        undefined,
        controller.signal,
      );
      await expect(client.create(issue)).resolves.toHaveProperty(
        "issueIdentifier",
        "SEC-123",
      );
      expect(requests).toHaveLength(6);
      for (const request of requests) {
        expect(new Headers(request.options.headers).get("authorization")).toBe(
          API_KEY,
        );
        expect(request.options.redirect).toBe("error");
        expect(request.options.signal).toBe(controller.signal);
      }
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test("authenticates safely, validates the destination, and assigns findings to the viewer", async () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const controller = new AbortController();
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue),
    ]);

    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      undefined,
      fetchImpl,
      controller.signal,
    );
    expect(client.assigneeId).toBe("user-self");
    await expect(client.create(issue)).resolves.toEqual({
      issueIdentifier: "SEC-123",
      url: "https://linear.app/example/issue/SEC-123/synthetic-finding",
    });
    expect(requests).toHaveLength(6);
    for (const request of requests) {
      expect(request.url).toBe("https://api.linear.app/graphql");
      expect(request.options.method).toBe("POST");
      expect(request.options.redirect).toBe("error");
      expect(request.options.signal).toBe(controller.signal);
      expect(request.options.headers).toEqual({
        Authorization: API_KEY,
        "Content-Type": "application/json",
      });
      expect(request.body.query).not.toContain(API_KEY);
    }
    expect(requests[0]!.body.variables).toEqual({});
    expect(requests[1]!.body.variables).toEqual({
      id: prepared.destination.teamId,
    });
    expect(requests[2]!.body.variables).toEqual({
      id: prepared.destination.projectId,
    });
    const mutation = requests.find(({ body }) =>
      body.query.includes("mutation createIssue"),
    );
    expect(mutation?.body.query).toContain("$input: IssueCreateInput!");
    expect(mutation?.body.query).not.toContain(issue.description);
    expect(mutation?.body.variables).toEqual({
      input: {
        teamId: prepared.destination.teamId,
        projectId: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        priority: 2,
        assigneeId: "user-self",
      },
    });
  });

  test("publishes directly to a team without selecting a project", async () => {
    const prepared = teamOnlyPublication();
    const issue = prepared.issues[0]!;
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue),
    ]);

    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      undefined,
      fetchImpl,
    );
    expect(client.assigneeId).toBe("user-self");
    await expect(client.create(issue)).resolves.toEqual({
      issueIdentifier: "SEC-123",
      url: "https://linear.app/example/issue/SEC-123/synthetic-finding",
    });

    expect(requests).toHaveLength(4);
    expect(requests[0]!.body.query).toContain("query viewer");
    expect(requests[1]!.body.query).toContain("query team");
    expect(requests[1]!.body.variables).toEqual({
      id: prepared.destination.teamId,
    });
    const mutation = requests.find(({ body }) =>
      body.query.includes("mutation createIssue"),
    );
    expect(mutation?.body.variables).toEqual({
      input: {
        teamId: prepared.destination.teamId,
        title: issue.title,
        description: issue.description,
        priority: 2,
        assigneeId: "user-self",
      },
    });
  });

  test("resolves a case-insensitive assignee email before creating any issue", async () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      Response.json({
        data: {
          users: {
            nodes: [{ id: "user-override", email: "person@example.test" }],
          },
        },
      }),
      issueResponse(prepared, issue, "user-override"),
    ]);
    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      "PERSON@example.test",
      fetchImpl,
    );
    expect(client.assigneeId).toBe("user-override");
    const userLookup = requests.find(({ body }) =>
      body.query.includes("query users"),
    );
    expect(userLookup?.body.variables).toEqual({
      filter: { email: { eqIgnoreCase: "PERSON@example.test" } },
      first: 2,
    });
    await expect(client.create(issue)).resolves.toHaveProperty(
      "issueIdentifier",
      "SEC-123",
    );
    const mutation = requests.find(({ body }) =>
      body.query.includes("mutation createIssue"),
    );
    expect(mutation?.body.variables["input"]).toMatchObject({
      assigneeId: "user-override",
    });
  });

  test("resolves an explicit assignee user ID before creating any issue", async () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      Response.json({ data: { user: { id: "user-override" } } }),
      issueResponse(prepared, issue, "user-override"),
    ]);
    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      "user-override",
      fetchImpl,
    );
    const userLookup = requests.find(({ body }) =>
      body.query.includes("query user("),
    );
    expect(userLookup?.body.variables).toEqual({ id: "user-override" });
    await expect(client.create(issue)).resolves.toHaveProperty(
      "issueIdentifier",
      "SEC-123",
    );
  });

  test.each([
    ["missing viewer", { viewer: null }],
    ["different team", { team: { id: "other-team" } }],
    [
      "different project",
      {
        project: {
          id: "other-project",
          teams: { nodes: [{ id: "team-synthetic" }] },
        },
      },
    ],
    [
      "project outside team",
      {
        project: {
          id: "project-synthetic",
          teams: { nodes: [{ id: "other-team" }] },
        },
      },
    ],
  ] as const)("rejects %s before attempting any mutation", async (_, data) => {
    const prepared = publication();
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared, data),
    ]);
    await expect(
      prepareLinearApiPublication(prepared, API_KEY, undefined, fetchImpl),
    ).rejects.toThrow(
      "could not verify the authenticated user, team, and project",
    );
    expect(
      requests.some(({ body }) => body.query.includes("mutation createIssue")),
    ).toBe(false);
  });

  test.each([
    ["missing viewer", { viewer: null }],
    ["different team", { team: { id: "other-team" } }],
  ] as const)(
    "rejects a team-only destination with %s before attempting any mutation",
    async (_, data) => {
      const prepared = teamOnlyPublication();
      const { fetchImpl, requests } = mockedFetch([
        destinationResponse(prepared, data),
      ]);
      await expect(
        prepareLinearApiPublication(prepared, API_KEY, undefined, fetchImpl),
      ).rejects.toThrow("could not verify the authenticated user and team");
      expect(
        requests.some(({ body }) =>
          body.query.includes("mutation createIssue"),
        ),
      ).toBe(false);
      for (const request of requests) {
        expect(request.body.variables).not.toHaveProperty("projectId");
      }
    },
  );

  test.each([
    ["missing email", []],
    [
      "ambiguous email",
      [
        { id: "user-first", email: "person@example.test" },
        { id: "user-second", email: "person@example.test" },
      ],
    ],
    ["different email", [{ id: "user-other", email: "other@example.test" }]],
  ] as const)(
    "rejects a %s without attempting any mutation",
    async (_, nodes) => {
      const prepared = publication();
      const { fetchImpl, requests } = mockedFetch([
        destinationResponse(prepared),
        Response.json({ data: { users: { nodes } } }),
      ]);
      await expect(
        prepareLinearApiPublication(
          prepared,
          API_KEY,
          "person@example.test",
          fetchImpl,
        ),
      ).rejects.toThrow(
        "could not resolve exactly one matching issue assignee",
      );
      expect(
        requests.some(({ body }) =>
          body.query.includes("mutation createIssue"),
        ),
      ).toBe(false);
    },
  );

  test("rejects an explicit assignee whose returned ID does not match", async () => {
    const prepared = publication();
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      Response.json({ data: { user: { id: "user-other" } } }),
    ]);
    await expect(
      prepareLinearApiPublication(
        prepared,
        API_KEY,
        "user-requested",
        fetchImpl,
      ),
    ).rejects.toThrow("could not resolve the requested issue assignee");
    expect(
      requests.some(({ body }) => body.query.includes("mutation createIssue")),
    ).toBe(false);
  });

  test.each([
    ["missing issue identifier", { identifier: undefined }],
    ["terminal-control issue identifier", { identifier: "SEC-123\u001b[31m" }],
    ["different title", { title: "untrusted title" }],
    ["different description", { description: "untrusted description" }],
    ["different priority", { priority: 1 }],
    ["different team", { team: { id: "other-team" } }],
    ["missing project", { project: null }],
    ["different project", { project: { id: "other-project" } }],
    ["different assignee", { assignee: { id: "other-user" } }],
    ["non-HTTPS issue URL", { url: "http://linear.app/issue/SEC-123" }],
    ["different-host issue URL", { url: "https://attacker.test/SEC-123" }],
    [
      "credential-bearing issue URL",
      { url: "https://token:secret@linear.app/issue/SEC-123" },
    ],
    [
      "query-bearing issue URL",
      { url: "https://linear.app/issue/SEC-123?token=secret" },
    ],
    [
      "fragment-bearing issue URL",
      { url: "https://linear.app/issue/SEC-123#x" },
    ],
  ] as const)("rejects a created issue with %s", async (_, overrides) => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const { fetchImpl } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue, "user-self", overrides),
    ]);
    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      undefined,
      fetchImpl,
    );
    await expect(client.create(issue)).rejects.toThrow(
      "unverified created issue; do not retry",
    );
  });

  test("rejects a team-only issue attached to an unexpected project", async () => {
    const prepared = teamOnlyPublication();
    const issue = prepared.issues[0]!;
    const { fetchImpl } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue, "user-self", {
        project: { id: "unexpected-project" },
      }),
    ]);
    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      undefined,
      fetchImpl,
    );
    await expect(client.create(issue)).rejects.toThrow(
      "unverified created issue; do not retry",
    );
  });

  test("omits priority for informational findings and accepts Linear's zero priority", async () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    delete issue.priority;
    const { fetchImpl, requests } = mockedFetch([
      destinationResponse(prepared),
      issueResponse(prepared, issue),
    ]);
    const client = await prepareLinearApiPublication(
      prepared,
      API_KEY,
      undefined,
      fetchImpl,
    );
    await expect(client.create(issue)).resolves.toHaveProperty(
      "issueIdentifier",
      "SEC-123",
    );
    expect(requests[1]!.body.variables["input"]).not.toHaveProperty("priority");
  });

  test.each([
    [
      "unauthorized",
      new Response("secret upstream body", { status: 401 }),
      "Linear rejected the supplied API key.",
    ],
    [
      "forbidden",
      new Response("secret upstream body", { status: 403 }),
      "Linear rejected the supplied API key.",
    ],
    [
      "rate-limited",
      new Response("secret upstream body", { status: 429 }),
      "Linear rate-limited destination verification; do not retry until existing issues are checked.",
    ],
    [
      "GraphQL rate-limited",
      Response.json(
        {
          errors: [
            {
              message: `secret upstream body ${API_KEY}`,
              extensions: { code: "RATELIMITED" },
            },
          ],
        },
        { status: 400 },
      ),
      "Linear rate-limited destination verification; do not retry until existing issues are checked.",
    ],
    [
      "GraphQL partial failure",
      Response.json({
        data: { viewer: { id: "user-self" } },
        errors: [{ message: `secret upstream body ${API_KEY}` }],
      }),
      "Linear destination verification was rejected.",
    ],
    [
      "invalid JSON",
      new Response(`secret upstream body ${API_KEY}`),
      "Linear destination verification could not be completed.",
    ],
  ] as const)(
    "never discloses credentials or response details for %s",
    async (_, response, expectedMessage) => {
      const prepared = publication();
      const { fetchImpl } = mockedFetch([response]);
      let failure: unknown;
      try {
        await prepareLinearApiPublication(
          prepared,
          API_KEY,
          undefined,
          fetchImpl,
        );
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(Error);
      const message = (failure as Error).message;
      expect(message).toBe(expectedMessage);
      expect(message).not.toContain(API_KEY);
      expect(message).not.toContain("secret upstream body");
      expect(message).not.toContain(prepared.issues[0]!.description);
    },
  );

  test("does not leak arbitrary API keys from transport failures", async () => {
    const arbitrarySecret = "synthetic-opaque-super-secret-value";
    const fetchImpl = (async () => {
      throw new Error(`network exposed ${arbitrarySecret}`);
    }) as unknown as typeof fetch;
    try {
      await prepareLinearApiPublication(
        publication(),
        arbitrarySecret,
        undefined,
        mockLinearClient(fetchImpl),
      );
      throw new Error("Expected synthetic failure");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(
        "Linear destination verification could not be completed.",
      );
      expect((error as Error).message).not.toContain(arbitrarySecret);
      expect((error as Error).cause).toBeUndefined();
    }
  });

  test("rejects malformed credentials before issuing any request", async () => {
    for (const apiKey of ["", " synthetic-secret", "synthetic\nsecret"]) {
      const { fetchImpl, requests } = mockedFetch([]);
      await expect(
        prepareLinearApiPublication(
          publication(),
          apiKey,
          undefined,
          fetchImpl,
        ),
      ).rejects.toThrow("A valid Linear API key is required.");
      expect(requests).toHaveLength(0);
    }
  });

  test("rejects terminal-control assignees before issuing any request", async () => {
    const { fetchImpl, requests } = mockedFetch([]);
    await expect(
      prepareLinearApiPublication(
        publication(),
        API_KEY,
        "person@example.test\u001b[31m",
        fetchImpl,
      ),
    ).rejects.toThrow("A valid Linear assignee is required.");
    expect(requests).toHaveLength(0);
  });

  test("rejects a pre-aborted publication before issuing any request", async () => {
    const controller = new AbortController();
    const reason = new Error("synthetic interruption");
    controller.abort(reason);
    const { fetchImpl, requests } = mockedFetch([]);
    await expect(
      prepareLinearApiPublication(
        publication(),
        API_KEY,
        undefined,
        fetchImpl,
        controller.signal,
      ),
    ).rejects.toBe(reason);
    expect(requests).toHaveLength(0);
  });

  test("propagates cancellation without exposing transport details", async () => {
    const controller = new AbortController();
    const reason = new Error("synthetic interruption");
    const fetchImpl = (async (
      _url: Parameters<typeof fetch>[0],
      options?: Parameters<typeof fetch>[1],
    ) => {
      expect(options?.signal).toBe(controller.signal);
      controller.abort(reason);
      throw new Error(`transport exposed ${API_KEY}`);
    }) as unknown as typeof fetch;
    await expect(
      prepareLinearApiPublication(
        publication(),
        API_KEY,
        undefined,
        mockLinearClient(fetchImpl),
        controller.signal,
      ),
    ).rejects.toBe(reason);
  });
});
