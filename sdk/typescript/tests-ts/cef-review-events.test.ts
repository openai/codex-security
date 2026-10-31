import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { expect, mock, test } from "bun:test";
import { cefEventSchema } from "../src/cef-events.js";
import {
  parseSecurityEventBatch,
  parseSecurityEventInputText,
  reviewSecurityEventsInternal,
  securityEventId,
} from "../src/review-events.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

const records = readFileSync(
  new URL("../../../examples/audit-events/events.cef", import.meta.url),
  "utf8",
)
  .trimEnd()
  .split(/\r?\n/);
const history = records[0]!;
const fresh = records[1]!;
const batch = JSON.parse(
  readFileSync(
    new URL("../../../examples/audit-events/batch.json", import.meta.url),
    "utf8",
  ),
);
const id = (record: string) =>
  `sha256:${createHash("sha256").update(record).digest("hex")}`;

test.each([
  fresh,
  String.raw`CEF:1|Example\|Vendor|Audit\\Service|1.0|role=grant|Role \| granted|Very-High|msg=path C:\\logs has x\=y and | pipe\nnext cs1=value with spaces cs1Label=description`,
  "<134>Oct 28 12:00:00 host " + fresh,
  "<134>1 2026-10-28T12:00:00Z host app - - - " + fresh,
  "CEF:0|Example|Audit|1|100|An event|0|",
])(
  "preserves a native CEF record including headers, extensions and syslog",
  (record) => {
    expect(cefEventSchema.parse(record)).toBe(record);
    expect(parseSecurityEventBatch(record)).toEqual({
      schemaVersion: 1,
      source: "cef",
      groups: [{ id: "events", events: [record] }],
    });
    expect(securityEventId(record)).toBe(id(record));
  },
);

test.each([
  "CEF:2|Example|Audit|1|100|An event|5|",
  "CEF:0|Example|Audit|1|100|An event|11|",
  "CEF:0|Example|Audit|1|100|An event|5",
  "CEF:0||Audit|1|100|An event|5|",
  "CEF:0|Example|Audit|1|100|An event|5|msg=first\nsecond",
])("rejects malformed native framing before model work", async (record) => {
  const run = mock(async () => ({ finalResponse: '{"observations":[]}' }));
  await expect(
    reviewSecurityEventsInternal(
      record,
      { codex: { startThread: () => ({ run }) } },
      "sdk",
    ),
  ).rejects.toThrow();
  expect(run).not.toHaveBeenCalled();
});

test("CEF occurrence IDs do not collapse events sharing a header class ID", () => {
  const a = fresh;
  const b = fresh.replace("1767268920000", "1767268980000");
  expect(securityEventId(a)).not.toBe(securityEventId(b));
  expect(parseSecurityEventBatch([a, b]).groups[0]?.events).toEqual([a, b]);
  expect(() => parseSecurityEventBatch([a, a])).toThrow("unique");
});

test("new and historical CEF reach Decisions and Codex unchanged with citation references", async () => {
  const observations = [
    {
      disposition: "review" as const,
      rationale: "Unexpected role grant.",
      eventIds: [id(history), id(fresh)],
    },
  ];
  let screened: unknown;
  const run = mock(async (_prompt: string) => ({
    finalResponse: JSON.stringify({ observations }),
  }));
  const result = await reviewSecurityEventsInternal(
    batch,
    {
      codex: { startThread: () => ({ run }) },
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
  expect(evidence.group).toEqual(batch.groups[0]);
  expect(evidence.eventReferences).toEqual({
    events: [id(fresh)],
    contextEvents: [id(history)],
  });
  expect(result.groups[0]?.observations).toEqual(observations);
});

test.each([
  { eventIds: [id(history)] },
  { eventIds: ["role-grant"] },
  { eventIds: ["missing"] },
])(
  "rejects unsupported or solely historical CEF citations",
  async ({ eventIds }) => {
    const codex = {
      startThread: () => ({
        run: async () => ({
          finalResponse: JSON.stringify({
            observations: [
              { disposition: "page", rationale: "Unexpected grant", eventIds },
            ],
          }),
        }),
      }),
    };
    await expect(
      reviewSecurityEventsInternal(batch, { codex }, "sdk"),
    ).rejects.toThrow("cite supplied event IDs");
  },
);

test.each([
  records.join("\n") + "\n",
  records.join("\r\n") + "\r\n",
  JSON.stringify(records),
  JSON.stringify(batch),
])(
  "CLI reads native CEF files and JSON envelopes without conversion",
  async (input) => {
    const deps = dependencies();
    deps.recordsInput = Readable.from([input]);
    const evidence: unknown[] = [];
    deps.reviewSecurityEvents = (value, options, surface) => {
      evidence.push(value);
      return reviewSecurityEventsInternal(
        value,
        {
          ...options,
          codex: {
            startThread: () => ({
              run: async () => ({ finalResponse: '{"observations":[]}' }),
            }),
          },
        },
        surface,
      );
    };
    const cli = createCliTest(main);
    expect(
      await cli.runCli(["review-events", "--json"], deps),
      cli.stderr.text(),
    ).toBe(0);
    expect(evidence).toEqual([parseSecurityEventInputText(input)]);
    expect(JSON.parse(cli.stdout.text()).groups[0].status).toBe("reviewed");
  },
);
