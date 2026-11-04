import { PassThrough, Readable } from "node:stream";
import { expect, test } from "bun:test";
import {
  monitorSecurityEvents,
  monitorSecurityEventsInternal,
} from "../src/monitor-events.js";
import {
  reviewSecurityEventsInternal,
  type SecurityEventBatch,
} from "../src/review-events.js";

const event = (id: string) => ({
  id,
  timestamp: "2026-01-01T12:00:00Z",
  action: id,
});
const record = (id: string, group = "session"): SecurityEventBatch => ({
  schemaVersion: 1,
  source: "audit",
  groups: [{ id: group, events: [event(id)] }],
});
const empty: SecurityEventBatch = {
  schemaVersion: 1,
  source: "audit",
  groups: [],
};

test("combines related evidence before screening and only runs Codex for unresolved groups", async () => {
  const later = record("grant");
  later.groups[0]!.contextEvents = [event("login")];
  const requests: SecurityEventBatch["groups"] = [];
  let fullReviews = 0;
  const results = monitorSecurityEventsInternal(
    Readable.from([record("login"), later, record("list", "other")]),
    {
      batchSize: 3,
      screenWithDecisions: true,
      decisionsCutoff: 0.9,
      environment: { OPENAI_API_KEY: "synthetic-key" },
    },
    "sdk",
    (batch, options, surface) =>
      reviewSecurityEventsInternal(
        batch,
        {
          ...options,
          codex: {
            startThread: () => ({
              run: async () => {
                fullReviews++;
                return {
                  finalResponse: JSON.stringify({
                    observations: [
                      {
                        eventIds: ["login", "grant"],
                        disposition: "review",
                        rationale: "Related activity",
                      },
                    ],
                  }),
                };
              },
            }),
          },
        },
        surface,
        async (_, init) => {
          const group = JSON.parse(String(init.body)).input[0].content[0].data
            .group;
          requests.push(group);
          return Response.json({
            answers: [
              {
                type: "choice",
                name: "route",
                choice: group.id === "other" ? "routine" : "investigate",
                confidence: 0.9,
              },
            ],
          });
        },
      ),
  );
  const reviews = await Array.fromAsync(results);
  expect(reviews.map((r) => r.groups.map((g) => g.status))).toEqual([
    ["reviewed", "screened"],
  ]);
  expect(requests[0]).toEqual({
    id: "session",
    events: [event("login"), event("grant")],
    contextEvents: [],
  });
  expect(fullReviews).toBe(1);
});

test("flushes by deadline while stdin stays open, then consumes the outstanding read exactly once", async () => {
  const input = new PassThrough({ objectMode: true });
  const monitor = monitorSecurityEvents(input, {
    batchSize: 10,
    maxWaitSeconds: 0.02,
  });
  try {
    input.write(empty);
    expect((await monitor.next()).value).toMatchObject({
      source: "audit",
      groups: [],
    });
    input.end({ ...empty, source: "later" });
    expect(await Array.fromAsync(monitor)).toEqual([
      {
        schemaVersion: 1,
        source: "later",
        groups: [],
        firstLine: 2,
        lastLine: 2,
      },
    ]);
  } finally {
    input.destroy();
  }
});

test("flushes on source or service-context changes and at EOF", async () => {
  const records = [
    empty,
    { ...empty, serviceContext: "a" },
    { ...empty, serviceContext: "a" },
    { ...empty, source: "other" },
  ];
  expect(
    (await Array.fromAsync(monitorSecurityEvents(Readable.from(records)))).map(
      (r) => r.source,
    ),
  ).toEqual(["audit", "audit", "other"]);
  expect(
    await Array.fromAsync(monitorSecurityEvents(Readable.from([]))),
  ).toEqual([]);
});

test("reports conflicting evidence with the range of unacknowledged lines", async () => {
  const first = record("login");
  const second = record("login");
  second.groups[0]!.events[0] = { ...event("login"), action: "different" };
  await expect(
    monitorSecurityEvents(Readable.from([first, second])).next(),
  ).rejects.toThrow("lines 1–2: Conflicting event login");
});

test("an idle SDK input can be canceled even with a pending read", async () => {
  const controller = new AbortController();
  const input = new PassThrough({ objectMode: true });
  const next = monitorSecurityEvents(input, {
    signal: controller.signal,
  }).next();
  controller.abort(new Error("stop"));
  try {
    await expect(next).rejects.toThrow("stop");
  } finally {
    input.destroy();
  }
});

test.each([
  { batchSize: 0 },
  { batchSize: 1.2 },
  { maxWaitSeconds: 0 },
  { maxWaitSeconds: Infinity },
])("rejects invalid window %j", async (options) => {
  await expect(
    monitorSecurityEvents(Readable.from([]), options).next(),
  ).rejects.toThrow();
});

test("static CEF history example carries the session start into the second window", async () => {
  const { readFileSync } = await import("node:fs");
  const fixture = new URL(
    "../../../examples/live-audit/batches.jsonl",
    import.meta.url,
  );
  const records = readFileSync(fixture, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as SecurityEventBatch);
  const inputs: SecurityEventBatch[] = [];
  const reviews = await Array.fromAsync(
    monitorSecurityEventsInternal(
      Readable.from(records),
      { batchSize: 2 },
      "sdk",
      async (value) => {
        inputs.push(value as SecurityEventBatch);
        return { schemaVersion: 1, source: records[0]!.source, groups: [] };
      },
    ),
  );
  expect(reviews.map((r) => [r.firstLine, r.lastLine])).toEqual([
    [1, 2],
    [3, 4],
  ]);
  expect(inputs[1]!.groups[0]!.contextEvents).toEqual(
    records[0]!.groups[0]!.events,
  );
  expect(inputs[1]!.groups[0]!.events).toEqual([
    ...records[2]!.groups[0]!.events,
    ...records[3]!.groups[0]!.events,
  ]);
});
