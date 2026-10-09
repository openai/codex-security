import { responding } from "./support/responses.js";
import { expect, test, mock } from "bun:test";
import { workflowDestination } from "../src/finding-workflow.js";
import { FindingsClient } from "../src/findings-client.js";
import { rejecting } from "./support/errors.js";

const scope = { repositoryId: "synthetic-repository" };
const neighborhood = {
  finding: { findingId: "synthetic" },
  potentialDuplicates: [],
};

test("lookup preserves the service error code and explanation", async () => {
  const message = "No current embedding exists in the requested repository.";
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () =>
      Response.json(
        { error: "finding_not_indexed", message },
        {
          status: 404,
          headers: { "Content-Type": "Application/JSON; charset=utf-8" },
        },
      ),
  );
  await expect(
    client.potentialDuplicates("synthetic", scope),
  ).rejects.toMatchObject({
    code: "finding_not_indexed",
    status: 404,
    message: expect.stringContaining(message),
  });
});

test("publishing preserves conflict details without retrying", async () => {
  const message = "The finding belongs to another repository.";
  let requests = 0;
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => {
      requests++;
      return Response.json(
        { error: "finding_conflict", message },
        { status: 409 },
      );
    },
  );
  await expect(client.publish([], scope.repositoryId)).rejects.toMatchObject({
    code: "finding_conflict",
    status: 409,
    message: expect.stringContaining(message),
  });
  expect(requests).toBe(1);
});

test("publishing preserves cancellation while reading an error response", async () => {
  const controller = new AbortController();
  const reason = new Error("Synthetic caller cancellation");
  const request = mock(async (_url: URL, init: RequestInit) => {
    expect(init.signal).toBe(controller.signal);
    const response = new Response(null, {
      status: 409,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    });
    response.json = async () => {
      controller.abort(reason);
      throw new DOMException("Synthetic aborted body read", "AbortError");
    };
    return response;
  });
  const client = new FindingsClient(
    "http://synthetic.test",
    controller.signal,
    request,
  );
  await expect(client.publish([], scope.repositoryId)).rejects.toBe(reason);
  expect(request).toHaveBeenCalledTimes(1);
});

test.each([
  "<html>Gateway unavailable</html>",
  '{"error":',
  "null",
  '{"error":"finding_conflict","message":123}',
])(
  "keeps the HTTP diagnostic for a non-contract response: %s",
  async (body) => {
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      async () => new Response(body, { status: 409 }),
    );
    await expect(client.storeDedupeGroups([["a", "b"]])).rejects.toMatchObject({
      status: 409,
      code: undefined,
      message: "Findings API POST /v1/dedupe-groups failed (HTTP 409).",
    });
  },
);

test("preserves an error code when the service omits a message", async () => {
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => Response.json({ error: "not_found" }, { status: 404 }),
  );
  await expect(client.publish([], scope.repositoryId)).rejects.toMatchObject({
    code: "not_found",
    status: 404,
    message: "Findings API POST /v1/bulk/findings failed (HTTP 404).",
  });
});

test("structured errors preserve retries and Retry-After", async () => {
  const delays: number[] = [];
  let requests = 0;
  const message = "Embedding credentials are unavailable.";
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => {
      requests++;
      return Response.json(
        { error: "embedding_unavailable", message },
        { status: 503, headers: { "Retry-After": "12" } },
      );
    },
    {
      wait: async (delay) => {
        delays.push(delay);
      },
      random: () => 0,
    },
  );
  await expect(client.storeDedupeGroups([["a", "b"]])).rejects.toMatchObject({
    code: "embedding_unavailable",
    status: 503,
    retryAfter: "12",
    message: expect.stringContaining(message),
  });
  expect(requests).toBe(3);
  expect(delays).toEqual([12000, 12000]);
});

test("lookup retries rate limits and honors Retry-After before continuing", async () => {
  let requests = 0;
  const delays = mock(async (_delay: number) => {});
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => {
      requests++;
      return requests === 1
        ? new Response("busy", {
            status: 429,
            headers: { "Retry-After": "12" },
          })
        : Response.json(neighborhood);
    },
    {
      wait: delays,
      random: () => 0,
    },
  );
  expect(
    (await client.potentialDuplicates("synthetic", scope)).finding.findingId,
  ).toBe("synthetic");
  expect(requests).toBe(2);
  expect(delays.mock.calls.map(([value]) => value)).toEqual([12000]);
});

test("lookup retries network and truncated JSON responses within the attempt budget", async () => {
  let requests = 0;
  const delays: number[] = [];
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => {
      requests++;
      if (requests === 1) throw new TypeError("fetch failed");
      if (requests === 2) return new Response('{"finding":');
      return Response.json(neighborhood);
    },
    {
      wait: async (delay) => {
        delays.push(delay);
      },
      random: () => 0,
    },
  );
  expect(
    (await client.potentialDuplicates("synthetic", scope)).finding.findingId,
  ).toBe("synthetic");
  expect(requests).toBe(3);
  expect(delays).toHaveLength(2);
  expect(delays[1]!).toBeGreaterThan(delays[0]!);
});

test.each([400, 401, 403, 404, 409, 501])(
  "lookup does not retry HTTP %i",
  async (status) => {
    const observeRequests = mock(responding("failed", status));
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      observeRequests,
      {
        wait: rejecting("Unexpected retry"),
      },
    );
    await expect(
      client.potentialDuplicates("synthetic", scope),
    ).rejects.toThrow(`HTTP ${status}`);
    expect(observeRequests).toHaveBeenCalledTimes(1);
  },
);

test.each([408, 429, 500, 502, 503, 504])(
  "lookup stops after three HTTP %i failures",
  async (status) => {
    const observeRequests = mock(responding("unavailable", status));
    const wait = mock(async () => {});
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      observeRequests,
      {
        wait,
      },
    );
    await expect(
      client.potentialDuplicates("synthetic", scope),
    ).rejects.toThrow(`HTTP ${status}`);
    expect(observeRequests).toHaveBeenCalledTimes(3);
    expect(wait).toHaveBeenCalledTimes(2);
  },
);

test("group write retries the identical payload after a lost acknowledgement", async () => {
  const bodies: unknown[] = [];
  const groups = [["synthetic-a", "synthetic-b"]];
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async (_url, init) => {
      bodies.push(init.body);
      if (bodies.length === 1) throw new TypeError("fetch failed");
      return Response.json({ groups });
    },
    { wait: async () => {} },
  );
  await client.storeDedupeGroups(groups);
  expect(bodies).toEqual([
    JSON.stringify({ groups }),
    JSON.stringify({ groups }),
  ]);
});

test("cancellation interrupts a pending retry and prevents another request", async () => {
  const controller = new AbortController();
  const observeRequests = mock(responding("busy", 429));
  const client = new FindingsClient(
    "http://synthetic.test",
    controller.signal,
    observeRequests,
    {
      wait: async () => {
        controller.abort("synthetic cancellation");
      },
    },
  );
  await expect(client.potentialDuplicates("synthetic", scope)).rejects.toBe(
    "synthetic cancellation",
  );
  expect(observeRequests).toHaveBeenCalledTimes(1);
});

test("Retry-After accepts an HTTP date", async () => {
  const until = "Fri, 01 Jan 2100 00:00:00 GMT";
  let requests = 0;
  const sleep = mock(async (_value: number) => {});
  const client = new FindingsClient(
    "http://synthetic.test",
    undefined,
    async () => {
      requests++;
      return requests === 1
        ? new Response("busy", {
            status: 503,
            headers: { "Retry-After": until },
          })
        : Response.json(neighborhood);
    },
    {
      wait: sleep,
    },
  );
  await client.potentialDuplicates("synthetic", scope);
  expect(sleep.mock.lastCall?.[0] ?? 0).toBeGreaterThan(24 * 60 * 60 * 1000);
});

test.each(["lookup", "publish", "groups"] as const)(
  "%s delivers HTTP failures without waiting for response cleanup",
  async (operation) => {
    const cancel = mock(() => new Promise<void>(() => {}));
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      async () => new Response(new ReadableStream({ cancel }), { status: 503 }),
      { wait: async () => {} },
    );
    const result =
      operation === "lookup"
        ? client.potentialDuplicates("synthetic", scope)
        : operation === "publish"
          ? client.publish([], scope.repositoryId)
          : client.storeDedupeGroups([["synthetic-a", "synthetic-b"]]);
    await expect(result).rejects.toThrow("HTTP 503");
    expect(cancel).toHaveBeenCalledTimes(operation === "publish" ? 1 : 3);
  },
);

test.each([
  "/service",
  "/service/",
  "/service?source=example",
  "/service#example",
  "/service/?source=example",
  "/service ",
])(
  "preserves base pathname %s across requests and workflow identity",
  async (path) => {
    const urls: string[] = [];
    const base = `http://synthetic:password@synthetic.test${path}`;
    const client = new FindingsClient(base, undefined, async (url) => {
      urls.push(url.href);
      return Response.json(
        url.pathname.endsWith("bulk/findings") ? [] : neighborhood,
      );
    });
    await client.publish([], scope.repositoryId);
    await client.potentialDuplicates("a/b", scope);
    await client.storeDedupeGroups([["a", "b"]]);
    expect(urls).toEqual([
      "http://synthetic:password@synthetic.test/service/v1/bulk/findings",
      "http://synthetic:password@synthetic.test/service/v1/finding/a%2Fb/potential-duplicates?repositoryId=synthetic-repository",
      "http://synthetic:password@synthetic.test/service/v1/dedupe-groups",
    ]);
    expect(workflowDestination(base)).toBe("http://synthetic.test/service/");
  },
);
