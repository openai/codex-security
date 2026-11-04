import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { monitorSecurityEventsInternal } from "../src/monitor-events.js";
import {
  parseSecurityEventBatch,
  type SecurityEventBatch,
} from "../src/review-events.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

const records = readFileSync(
  new URL("../../../examples/live-audit/events.cef", import.meta.url),
  "utf8",
)
  .trimEnd()
  .split(/\r?\n/);

function reviewer() {
  const evidence: SecurityEventBatch[] = [];
  return {
    evidence,
    review: async (value: unknown) => {
      const batch = parseSecurityEventBatch(value);
      evidence.push(batch);
      return { schemaVersion: 1 as const, source: batch.source, groups: [] };
    },
  };
}

test.each(["\n", "\r\n"])(
  "CLI streams native CEF across partial UTF-8 chunks with %j framing",
  async (separator) => {
    const inputRecords = records.map((r) => r.replace("Example", "Exämple"));
    const bytes = Buffer.from(inputRecords.join(separator) + separator);
    const chunks = Array.from(bytes, (byte) => Buffer.from([byte]));
    const deps = dependencies();
    deps.recordsInput = Readable.from(chunks);
    const { evidence, review } = reviewer();
    deps.reviewSecurityEvents = review;
    const cli = createCliTest(main);
    expect(
      await cli.runCli(["review-events", "--live", "--batch-size", "2"], deps),
      cli.stderr.text(),
    ).toBe(0);
    const output = cli.stdout
      .text()
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(
      output.map(({ firstLine, lastLine }) => [firstLine, lastLine]),
    ).toEqual([
      [1, 2],
      [3, 4],
    ]);
    expect(evidence.map((b) => b.groups[0]!.events)).toEqual([
      inputRecords.slice(0, 2),
      inputRecords.slice(2),
    ]);
  },
);

test("live CEF deduplicates exact records and promotes new evidence over identical history", async () => {
  const { evidence, review } = reviewer();
  const history = {
    schemaVersion: 1,
    source: "cef",
    groups: [{ id: "events", events: [], contextEvents: [records[0]] }],
  };
  const output = await Array.fromAsync(
    monitorSecurityEventsInternal(
      Readable.from([history, records[0], records[0], records[1]]),
      {},
      "sdk",
      review,
    ),
  );
  expect(
    output.map(({ firstLine, lastLine }) => [firstLine, lastLine]),
  ).toEqual([[1, 4]]);
  expect(evidence).toEqual([
    {
      schemaVersion: 1,
      source: "cef",
      groups: [
        { id: "events", events: records.slice(0, 2), contextEvents: [] },
      ],
    },
  ]);
});

test("live CEF arrays count as one input and preserve each native record", async () => {
  const { evidence, review } = reviewer();
  const result = await Array.fromAsync(
    monitorSecurityEventsInternal(
      Readable.from([records.slice(0, 2), records.slice(2)]),
      { batchSize: 1 },
      "sdk",
      review,
    ),
  );
  expect(
    result.map(({ firstLine, lastLine }) => [firstLine, lastLine]),
  ).toEqual([
    [1, 1],
    [2, 2],
  ]);
  expect(evidence.map((b) => b.groups[0]!.events)).toEqual([
    records.slice(0, 2),
    records.slice(2),
  ]);
});

test("live JSONL strings and CEF history envelopes use the same native evidence", async () => {
  const batch = {
    schemaVersion: 1,
    source: "cef",
    groups: [
      { id: "events", events: [records[1]], contextEvents: [records[0]] },
    ],
  };
  const deps = dependencies();
  deps.recordsInput = Readable.from([
    JSON.stringify(records[0]) + "\n" + JSON.stringify(batch) + "\n",
  ]);
  const { evidence, review } = reviewer();
  deps.reviewSecurityEvents = review;
  const cli = createCliTest(main);
  expect(
    await cli.runCli(["review-events", "--live"], deps),
    cli.stderr.text(),
  ).toBe(0);
  expect(evidence[0]!.groups).toEqual([
    { id: "events", events: records.slice(0, 2), contextEvents: [] },
  ]);
});

test("malformed CEF identifies the failing input line and preserves prior output", async () => {
  const deps = dependencies();
  deps.recordsInput = Readable.from([records[0] + "\nCEF:0|truncated\n"]);
  const { review } = reviewer();
  deps.reviewSecurityEvents = review;
  const cli = createCliTest(main);
  expect(
    await cli.runCli(["review-events", "--live", "--batch-size", "1"], deps),
  ).toBe(2);
  expect(JSON.parse(cli.stdout.text()).lastLine).toBe(1);
  expect(cli.stderr.text()).toContain("Live input line 2");
});
