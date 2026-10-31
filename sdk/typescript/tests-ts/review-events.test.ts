import { expect, mock, test } from "bun:test";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import {
  reviewSecurityEvents,
  reviewSecurityEventsInternal,
  type SecurityEventBatch,
} from "../src/review-events.js";

const newEvent = {
  id: "grant",
  timestamp: "2026-01-01T12:06:00Z",
  action: "AttachPolicy",
  actor: "deploy-session",
};
const earlier = {
  id: "assume",
  timestamp: "2026-01-01T12:04:00Z",
  action: "AssumeRole",
};
const group = { id: "deploy", events: [newEvent], contextEvents: [earlier] };
const batch: SecurityEventBatch = {
  schemaVersion: 1,
  source: "synthetic-audit",
  serviceContext: "Deploy roles read artifacts.",
  groups: [group],
};
const observation = {
  disposition: "page" as const,
  rationale: "An unexpected grant followed role assumption.",
  eventIds: ["assume", "grant"],
};
function fakeReviewer(observations = [observation]) {
  const run = mock(async (_prompt: string, _turn: TurnOptions) => ({
    finalResponse: JSON.stringify({ observations }),
  }));
  return { run, startThread: mock((_thread: ThreadOptions) => ({ run })) };
}
function answer(choice: string, confidence: number) {
  return Response.json({
    answers: [{ name: "route", type: "choice", choice, confidence }],
  });
}
const environment = { OPENAI_API_KEY: "synthetic-key" };

test("direct review ignores an available screening key and binds the full evidence to a read-only Codex turn", async () => {
  const codex = fakeReviewer();
  const request = mock(async () => {
    throw new Error("Unexpected Decisions request");
  });
  const signal = new AbortController().signal;
  const result = await reviewSecurityEventsInternal(
    batch,
    {
      codex,
      environment,
      decisionsCutoff: 0,
      cyberAccessProgram: "daybreak_blue",
      signal,
    },
    "sdk",
    request,
  );
  expect(request).not.toHaveBeenCalled();
  expect(codex.startThread).toHaveBeenCalledWith(
    expect.objectContaining({
      sandboxMode: "read-only",
      networkAccessEnabled: false,
      threadSource: "security_event_review",
    }),
  );
  expect(codex.run).toHaveBeenCalledWith(
    expect.stringContaining(JSON.stringify(earlier)),
    expect.objectContaining({ cyberAccessProgram: "daybreak_blue", signal }),
  );
  expect(result.groups).toEqual([
    {
      id: "deploy",
      status: "reviewed",
      screening: null,
      observations: [observation],
    },
  ]);
});

test("screens each nonempty group separately and sends only unresolved groups for full review", async () => {
  const codex = fakeReviewer();
  const groups = [
    { id: "no-new", events: [], contextEvents: [earlier] },
    { id: "routine", events: [earlier] },
    group,
  ];
  const signal = new AbortController().signal;
  const request = mock(async (url: string, init: RequestInit) => {
    expect(url).toBe("https://api.openai.com/v1/decisions");
    expect(init.signal).toBe(signal);
    expect(init.headers).toMatchObject({
      Authorization: "Bearer synthetic-key",
    });
    const body = JSON.parse(String(init.body));
    const evidence = body.input[0].content[0].data;
    expect(body).toMatchObject({
      model: "gpt-6-luna",
      input: [{ role: "user", content: [{ type: "input_json" }] }],
      questions: [{ type: "choice", name: "route" }],
    });
    expect(evidence.source).toBe(batch.source);
    expect(evidence.serviceContext).toBe(batch.serviceContext);
    if (evidence.group.id === "routine") return answer("routine", 0.99);
    expect(evidence.group).toEqual(group);
    return answer("investigate", 1);
  });
  const result = await reviewSecurityEventsInternal(
    { ...batch, groups },
    { codex, environment, screenWithDecisions: true, signal },
    "sdk",
    request,
  );
  expect(result.groups.map(({ status }) => status)).toEqual([
    "empty",
    "screened",
    "reviewed",
  ]);
  expect(result.groups[1]?.screening).toEqual({
    choice: "routine",
    confidence: 0.99,
  });
  expect(result.groups[2]?.observations).toEqual([observation]);
  expect(request).toHaveBeenCalledTimes(2);
  expect(codex.run).toHaveBeenCalledTimes(1);
});

test.each([
  ["routine", 0.7],
  ["insufficient_context", 1],
] as const)(
  "routes %s at confidence %d to full review",
  async (choice, confidence) => {
    const codex = fakeReviewer([]);
    const result = await reviewSecurityEventsInternal(
      batch,
      { codex, environment, screenWithDecisions: true },
      "sdk",
      async () => answer(choice, confidence),
    );
    expect(result.groups[0]).toMatchObject({
      status: "reviewed",
      screening: { choice, confidence },
      observations: [],
    });
  },
);

test.each([
  [undefined, 0.94, "reviewed"],
  [undefined, 0.95, "screened"],
  [0.8, 0.8, "screened"],
  [0, 0, "screened"],
  [1, 0.99, "reviewed"],
] as const)(
  "applies cutoff %s to routine confidence %d",
  async (decisionsCutoff, confidence, status) => {
    const codex = fakeReviewer([]);
    const result = await reviewSecurityEventsInternal(
      batch,
      { codex, environment, screenWithDecisions: true, decisionsCutoff },
      "sdk",
      async () => answer("routine", confidence),
    );
    expect(result.groups[0]?.status).toBe(status);
    expect(codex.run).toHaveBeenCalledTimes(status === "reviewed" ? 1 : 0);
  },
);

test.each([-0.01, 1.01, NaN])(
  "rejects invalid SDK cutoff %d before model work",
  async (decisionsCutoff) => {
    await expect(
      reviewSecurityEvents({ ...batch, groups: [] }, { decisionsCutoff }),
    ).rejects.toThrow();
  },
);

test.each([
  () => Response.json({ answers: [{ name: "route", type: "refusal" }] }),
  () => answer("routine", 2),
  () => new Response("try later", { status: 429 }),
])(
  "a screening failure rejects the batch without starting a full review",
  async (response) => {
    const codex = fakeReviewer([]);
    await expect(
      reviewSecurityEventsInternal(
        batch,
        { codex, environment, screenWithDecisions: true },
        "sdk",
        async () => response(),
      ),
    ).rejects.toThrow();
    expect(codex.run).not.toHaveBeenCalled();
  },
);
test("requires explicit API access for a nonempty screen and makes empty batches free", async () => {
  await expect(
    reviewSecurityEvents(batch, { environment: {}, screenWithDecisions: true }),
  ).rejects.toThrow("OPENAI_API_KEY");
  expect(
    await reviewSecurityEvents(
      { ...batch, groups: [] },
      { environment: {}, screenWithDecisions: true },
    ),
  ).toEqual({ schemaVersion: 1, source: batch.source, groups: [] });
});
test.each([{ eventIds: ["absent", "grant"] }, { eventIds: ["assume"] }])(
  "rejects unsupported or exclusively historical citations %j",
  async ({ eventIds }) => {
    const codex = fakeReviewer([{ ...observation, eventIds: [...eventIds] }]);
    await expect(
      reviewSecurityEventsInternal(batch, { codex }, "sdk"),
    ).rejects.toThrow("cite supplied event IDs");
  },
);
test("rejects ambiguous IDs before either model sees the batch", async () => {
  const request = mock(async () => answer("routine", 1));
  const groups = [
    group,
    { id: "other", events: [earlier], contextEvents: [earlier] },
  ];
  await expect(
    reviewSecurityEventsInternal(
      { ...batch, groups },
      { environment, screenWithDecisions: true },
      "sdk",
      request,
    ),
  ).rejects.toThrow("unique");
  expect(request).not.toHaveBeenCalled();
});
test("honors cancellation before making a screening request", async () => {
  await expect(
    reviewSecurityEvents(batch, {
      screenWithDecisions: true,
      signal: AbortSignal.abort(new Error("canceled")),
    }),
  ).rejects.toThrow("canceled");
});
