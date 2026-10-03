import { expect, test } from "bun:test";
import { FindingsClient } from "../src/findings-client.js";

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
      Response.json({ error: "finding_not_indexed", message }, { status: 404 }),
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
  const delays: number[] = [];
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
      wait: async (delay) => {
        delays.push(delay);
      },
      random: () => 0,
    },
  );
  expect(
    (await client.potentialDuplicates("synthetic", scope)).finding.findingId,
  ).toBe("synthetic");
  expect(requests).toBe(2);
  expect(delays).toEqual([12000]);
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
    let requests = 0;
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      async () => {
        requests++;
        return new Response("failed", { status });
      },
      {
        wait: async () => {
          throw new Error("Unexpected retry");
        },
      },
    );
    await expect(
      client.potentialDuplicates("synthetic", scope),
    ).rejects.toThrow(`HTTP ${status}`);
    expect(requests).toBe(1);
  },
);

test.each([408, 429, 500, 502, 503, 504])(
  "lookup stops after three HTTP %i failures",
  async (status) => {
    let requests = 0;
    let waits = 0;
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      async () => {
        requests++;
        return new Response("unavailable", { status });
      },
      {
        wait: async () => {
          waits++;
        },
      },
    );
    await expect(
      client.potentialDuplicates("synthetic", scope),
    ).rejects.toThrow(`HTTP ${status}`);
    expect(requests).toBe(3);
    expect(waits).toBe(2);
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
  let requests = 0;
  const client = new FindingsClient(
    "http://synthetic.test",
    controller.signal,
    async () => {
      requests++;
      return new Response("busy", { status: 429 });
    },
    {
      wait: async () => {
        controller.abort("synthetic cancellation");
      },
    },
  );
  await expect(client.potentialDuplicates("synthetic", scope)).rejects.toBe(
    "synthetic cancellation",
  );
  expect(requests).toBe(1);
});

test("Retry-After accepts an HTTP date", async () => {
  const until = "Fri, 01 Jan 2100 00:00:00 GMT";
  let requests = 0;
  let delay = 0;
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
      wait: async (value) => {
        delay = value;
      },
    },
  );
  await client.potentialDuplicates("synthetic", scope);
  expect(delay).toBeGreaterThan(24 * 60 * 60 * 1000);
});
