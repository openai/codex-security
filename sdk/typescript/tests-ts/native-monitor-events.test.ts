import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { expect, test } from "bun:test";
import { monitorSecurityEventsInternal } from "../src/monitor-events.js";
import {
  parseSecurityEventBatch,
  securityEventId,
  type SecurityEventBatch,
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
const cloudtrail = fixture("cloudtrail");
const ocsf = fixture("ocsf");

async function collect(inputs: unknown[], batchSize = 10) {
  const evidence: SecurityEventBatch[] = [];
  const results = await Array.fromAsync(
    monitorSecurityEventsInternal(
      Readable.from(inputs),
      { batchSize },
      "sdk",
      async (value) => {
        const batch = parseSecurityEventBatch(value);
        evidence.push(batch);
        return { schemaVersion: 1, source: batch.source, groups: [] };
      },
    ),
  );
  return { evidence, results };
}

test.each([
  cloudtrail.Records[0],
  ocsf,
  { ...ocsf, metadata: { ...ocsf.metadata, uid: undefined } },
])(
  "native IDs combine repeated evidence and promote history without modifying records",
  async (input) => {
    // JSON input has no undefined fields.
    const event = JSON.parse(JSON.stringify(input));
    const parsed = parseSecurityEventBatch(event);
    const history = {
      ...parsed,
      groups: [{ id: "events", events: [], contextEvents: [event] }],
    };
    const { evidence, results } = await collect([history, event, event]);
    expect(evidence).toEqual([
      {
        ...parsed,
        groups: [{ id: "events", events: [event], contextEvents: [] }],
      },
    ]);
    expect(
      results.map(({ firstLine, lastLine }) => [firstLine, lastLine]),
    ).toEqual([[1, 3]]);
  },
);

test.each([cloudtrail.Records[0], ocsf])(
  "different evidence with the same native ID rejects the full window",
  async (event) => {
    await expect(
      collect([event, { ...event, additionalEvidence: "changed" }]),
    ).rejects.toThrow(
      `lines 1–2: Conflicting event ${securityEventId(parseSecurityEventBatch(event).groups[0]!.events[0]!)}`,
    );
  },
);

test("CloudTrail Records count as one input and changing native source flushes the window", async () => {
  const { evidence, results } = await collect([
    cloudtrail,
    ocsf,
    { ...ocsf, metadata: { ...ocsf.metadata, uid: "second" } },
  ]);
  expect(evidence[0]!.groups[0]!.events).toEqual(cloudtrail.Records);
  expect(evidence[1]!.groups[0]!.events).toEqual([
    ocsf,
    { ...ocsf, metadata: { ...ocsf.metadata, uid: "second" } },
  ]);
  expect(
    results.map(({ source, firstLine, lastLine }) => [
      source,
      firstLine,
      lastLine,
    ]),
  ).toEqual([
    ["aws.cloudtrail", 1, 1],
    ["ocsf", 2, 3],
  ]);
});

test("CLI live JSONL passes native records through windowing and reports input line ranges", async () => {
  const deps = dependencies();
  const inputs = [cloudtrail.Records[0], cloudtrail.Records[1], ocsf];
  deps.recordsInput = Readable.from(
    inputs.map((event) => JSON.stringify(event) + "\n"),
  );
  const evidence: SecurityEventBatch[] = [];
  deps.reviewSecurityEvents = async (value) => {
    const batch = parseSecurityEventBatch(value);
    evidence.push(batch);
    return { schemaVersion: 1, source: batch.source, groups: [] };
  };
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
    [3, 3],
  ]);
  expect(evidence.map((batch) => batch.groups[0]!.events)).toEqual([
    cloudtrail.Records,
    [ocsf],
  ]);
});
