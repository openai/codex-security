import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { expect, mock, test } from "bun:test";
import {
  parseSecurityEventBatch,
  reviewSecurityEventsInternal,
  securityEventId,
  securityEventInputSchema,
} from "../src/review-events.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

const fixture = (name: string) =>
  JSON.parse(
    readFileSync(
      new URL(`./fixtures/audit-events/${name}.json`, import.meta.url),
      "utf8",
    ),
  );
const trail = fixture("cloudtrail");
const ocsf = fixture("ocsf");
const batch = fixture("batch");

function reviewer(eventIds: string[]) {
  const observations = [
    {
      disposition: "review" as const,
      rationale: "Unexpected policy grant.",
      eventIds,
    },
  ];
  const run = mock(async (_prompt: string) => ({
    finalResponse: JSON.stringify({ observations }),
  }));
  return { codex: { startThread: () => ({ run }) }, run, observations };
}

test.each([trail, trail.Records[1], ocsf, batch])(
  "native input reaches both models unchanged and binds citations",
  async (input) => {
    const parsed = parseSecurityEventBatch(input);
    const group = parsed.groups[0]!;
    const ids = [...(group.contextEvents ?? []), ...group.events].map(
      securityEventId,
    );
    const { codex, run, observations } = reviewer(ids);
    let screened: unknown;
    const result = await reviewSecurityEventsInternal(
      input,
      {
        codex,
        screenWithDecisions: true,
        environment: { OPENAI_API_KEY: "synthetic-key" },
      },
      "sdk",
      async (_url, init) => {
        screened = JSON.parse(String(init.body)).input[0].content[0].data;
        return Response.json({
          answers: [
            {
              name: "route",
              type: "choice",
              choice: "investigate",
              confidence: 1,
            },
          ],
        });
      },
    );
    const prompt = run.mock.calls[0]![0];
    const evidence = JSON.parse(prompt.slice(prompt.indexOf("\n\n") + 2));
    expect(evidence).toEqual(screened);
    expect(evidence.group).toEqual(group);
    expect(result.groups[0]?.observations).toEqual(observations);
    const expectedEvents =
      input === trail
        ? trail.Records
        : input === batch
          ? batch.groups[0].events
          : [input];
    expect(evidence.group.events).toEqual(expectedEvents);
    expect(evidence.eventReferences.events).toEqual(
      group.events.map(securityEventId),
    );
  },
);

test("UID-less OCSF citations are stable across object key order without mutating evidence", async () => {
  const event = structuredClone(ocsf);
  delete event.metadata.uid;
  const reordered = {
    ...Object.fromEntries(Object.entries(event).reverse()),
    metadata: Object.fromEntries(Object.entries(event.metadata).reverse()),
  };
  const [parsed] = parseSecurityEventBatch(event).groups[0]!.events;
  const id = securityEventId(parsed!);
  expect(id).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(
    securityEventId(parseSecurityEventBatch(reordered).groups[0]!.events[0]!),
  ).toBe(id);
  expect(
    securityEventId(
      parseSecurityEventBatch({ ...event, time: event.time + 1 }).groups[0]!
        .events[0]!,
    ),
  ).not.toBe(id);
  const { codex } = reviewer([id]);
  expect(
    (await reviewSecurityEventsInternal(event, { codex }, "sdk")).groups[0]
      ?.observations[0]?.eventIds,
  ).toEqual([id]);
  expect(parsed).toEqual(event);
});

test.each([
  { ...trail.Records[0], eventVersion: "2.0" },
  { ...trail.Records[0], eventTime: "yesterday" },
  { ...ocsf, metadata: { ...ocsf.metadata, version: "2.0.0" } },
  { ...ocsf, time: "2026-01-01T00:00:00Z" },
])(
  "rejects unsupported versions or invalid common fields before reviewing",
  async (input) => {
    const { codex, run } = reviewer([]);
    await expect(
      reviewSecurityEventsInternal(input, { codex }, "sdk"),
    ).rejects.toThrow();
    expect(run).not.toHaveBeenCalled();
  },
);

test.each([trail.Records[0], ocsf])(
  "native IDs reject duplicate evidence and unknown or history-only citations",
  async (event) => {
    const parsed = parseSecurityEventBatch(event);
    const history = event.eventID
      ? { ...event, eventID: "history" }
      : { ...event, metadata: { ...event.metadata, uid: "history" } };
    expect(() =>
      parseSecurityEventBatch({
        ...parsed,
        groups: [{ id: "g", events: [event], contextEvents: [event] }],
      }),
    ).toThrow("unique");
    for (const ids of [["missing"], ["history"]]) {
      const { codex } = reviewer(ids);
      await expect(
        reviewSecurityEventsInternal(
          {
            ...parsed,
            groups: [
              {
                id: "g",
                events: [event],
                contextEvents: [history],
              },
            ],
          },
          { codex },
          "sdk",
        ),
      ).rejects.toThrow("cite supplied event IDs");
    }
  },
);

test("CLI accepts native CloudTrail Records and OCSF through the real reviewer", async () => {
  for (const input of [trail, ocsf]) {
    const deps = dependencies();
    deps.recordsInput = Readable.from([JSON.stringify(input)]);
    deps.reviewSecurityEvents = async (value, options, surface) => {
      const parsed = parseSecurityEventBatch(value);
      const { codex } = reviewer(parsed.groups[0]!.events.map(securityEventId));
      return reviewSecurityEventsInternal(
        value,
        { ...options, codex },
        surface,
      );
    };
    const cli = createCliTest(main);
    expect(
      await cli.runCli(["review-events", "--json"], deps),
      cli.stderr.text(),
    ).toBe(0);
    expect(JSON.parse(cli.stdout.text()).groups[0].status).toBe("reviewed");
    expect(securityEventInputSchema.parse(input)).toEqual(input);
  }
});
