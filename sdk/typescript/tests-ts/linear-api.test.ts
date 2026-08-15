import { describe, expect, test } from "bun:test";
import { prepareLinearApiPublication } from "../src/linear-api.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "../src/publication.js";

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

function destinationResponse(
  prepared: PreparedScanPublication,
  overrides: Record<string, unknown> = {},
): Response {
  return Response.json({
    data: {
      viewer: { id: "user-self" },
      team: { id: prepared.destination.teamId },
      project: {
        id: prepared.destination.projectId,
        teams: { nodes: [{ id: prepared.destination.teamId }] },
      },
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
          project: { id: prepared.destination.projectId },
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
  fetchImpl: typeof fetch;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const fetchImpl = async (
    url: Parameters<typeof fetch>[0],
    options?: Parameters<typeof fetch>[1],
  ): Promise<Response> => {
    requests.push({
      url: url.toString(),
      options: options!,
      body: JSON.parse(options!.body as string) as RecordedRequest["body"],
    });
    const response = responses.shift();
    if (response === undefined) throw new Error("Unexpected synthetic request");
    return response;
  };
  return { fetchImpl: fetchImpl as unknown as typeof fetch, requests };
}

describe("direct Linear API publication", () => {
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
    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.url).toBe("https://api.linear.app/graphql");
      expect(request.options.method).toBe("POST");
      expect(request.options.redirect).toBe("error");
      expect(request.options.signal).toBe(controller.signal);
      expect(request.options.headers).toEqual({
        Authorization: API_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
      });
      expect(request.body.query).not.toContain(API_KEY);
    }
    expect(requests[0]!.body.variables).toEqual({
      teamId: prepared.destination.teamId,
      projectId: prepared.destination.projectId,
    });
    expect(requests[1]!.body.query).toContain("$input: IssueCreateInput!");
    expect(requests[1]!.body.query).not.toContain(issue.description);
    expect(requests[1]!.body.variables).toEqual({
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
    expect(requests[1]!.body.query).toContain("eqIgnoreCase: $email");
    expect(requests[1]!.body.variables).toEqual({
      email: "PERSON@example.test",
    });
    await expect(client.create(issue)).resolves.toHaveProperty(
      "issueIdentifier",
      "SEC-123",
    );
    expect(requests[2]!.body.variables["input"]).toMatchObject({
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
    expect(requests[1]!.body.query).toContain("user(id: $id)");
    expect(requests[1]!.body.variables).toEqual({ id: "user-override" });
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
    expect(requests).toHaveLength(1);
  });

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
      expect(requests).toHaveLength(2);
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
    expect(requests).toHaveLength(2);
  });

  test.each([
    ["missing issue identifier", { identifier: undefined }],
    ["terminal-control issue identifier", { identifier: "SEC-123\u001b[31m" }],
    ["different title", { title: "untrusted title" }],
    ["different description", { description: "untrusted description" }],
    ["different priority", { priority: 1 }],
    ["different team", { team: { id: "other-team" } }],
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
      "Linear destination verification returned an unreadable response.",
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
        fetchImpl,
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
        fetchImpl,
        controller.signal,
      ),
    ).rejects.toBe(reason);
  });
});
