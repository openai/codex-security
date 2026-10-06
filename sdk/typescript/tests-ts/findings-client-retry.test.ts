import { responding } from "./support/responses.js";
import { expect, test, mock } from "bun:test";
import { FindingsClient } from "../src/findings-client.js";
import { rejecting } from "./support/errors.js";

const scope = { repositoryId: "synthetic-repository" };
const neighborhood = {
  finding: { findingId: "synthetic" },
  potentialDuplicates: [],
};

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
