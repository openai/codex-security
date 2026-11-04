import { PassThrough, Readable, Writable } from "node:stream";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { reviewSecurityEventsInternal } from "../src/review-events.js";
import { loadProjectConfig } from "../src/project-config.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "review-events-config-",
);
afterEach(cleanup);

const batch = {
  schemaVersion: 1,
  source: "synthetic-audit",
  groups: [{ id: "g", events: [] }],
};
test("review-events reads one batch and forwards the explicit screening and reviewer settings", async () => {
  const deps = dependencies();
  deps.recordsInput = Readable.from([JSON.stringify(batch)]);
  deps.reviewSecurityEvents = async (input, options, surface) => {
    expect(input).toEqual(batch);
    expect(options).toMatchObject({
      screenWithDecisions: true,
      cyberAccessProgram: "daybreak_blue",
      model: "fixture-model",
      environment: deps.environment,
    });
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(surface).toBe("cli");
    return reviewSecurityEventsInternal(input, options, surface);
  };
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [
        "review-events",
        "--screen-with-decisions",
        "--cyber-access-program",
        "daybreak_blue",
        "--model",
        "fixture-model",
        "--json",
      ],
      deps,
    ),
    cli.stderr.text(),
  ).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toEqual({
    schemaVersion: 1,
    source: batch.source,
    groups: [{ id: "g", status: "empty", screening: null, observations: [] }],
  });
});

test.each(["{", '{"schemaVersion":2,"source":"demo","groups":[]}'])(
  "invalid stdin fails on stderr without emitting a successful review",
  async (input) => {
    const deps = dependencies();
    deps.recordsInput = Readable.from([input]);
    const cli = createCliTest(main);
    expect(await cli.runCli(["review-events", "--json"], deps)).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).not.toBe("");
  },
);

test("loads the YAML cutoff for SDK and CLI callers and gives explicit CLI options precedence", async () => {
  const directory = await temporaryDirectory();
  const file = join(directory, "review.yaml");
  await writeFile(
    file,
    "review_events:\n  screen_with_decisions: true\n  decisions_cutoff: 0.83\n",
  );
  expect((await loadProjectConfig(file)).reviewEvents).toEqual({
    screenWithDecisions: true,
    decisionsCutoff: 0.83,
  });
  const event = {
    id: "read",
    timestamp: "2026-01-01T12:05:00Z",
    action: "ReadArtifact",
  };
  for (const [args, expectedStatus] of [
    [["-c", file], "reviewed"],
    [["--decisions-cutoff", "0"], "screened"],
  ] as const) {
    const deps = dependencies();
    deps.environment = {
      CODEX_SECURITY_PROJECT_CONFIG: file,
      OPENAI_API_KEY: "synthetic-key",
    };
    deps.recordsInput = Readable.from([
      JSON.stringify({ ...batch, groups: [{ id: "g", events: [event] }] }),
    ]);
    deps.reviewSecurityEvents = (input, options, surface) =>
      reviewSecurityEventsInternal(
        input,
        {
          ...options,
          codex: {
            startThread: () => ({
              run: async () => ({ finalResponse: '{"observations":[]}' }),
            }),
          },
        },
        surface,
        async () =>
          Response.json({
            answers: [
              {
                type: "choice",
                name: "route",
                choice: "routine",
                confidence: 0.8,
              },
            ],
          }),
      );
    const cli = createCliTest(main);
    expect(
      await cli.runCli(["review-events", ...args, "--json"], deps),
      cli.stderr.text(),
    ).toBe(0);
    expect(JSON.parse(cli.stdout.text()).groups[0]).toMatchObject({
      status: expectedStatus,
      screening: { confidence: 0.8 },
    });
  }
  await writeFile(file, "review_events:\n  decisions_cutoff: 1.1\n");
  await expect(loadProjectConfig(file)).rejects.toThrow("decisions_cutoff");
});

test("rejects an out-of-range CLI cutoff", async () => {
  const deps = dependencies();
  deps.recordsInput = Readable.from([JSON.stringify(batch)]);
  const cli = createCliTest(main);
  expect(
    await cli.runCli(["review-events", "--decisions-cutoff", "1.1"], deps),
  ).toBe(2);
});

test("live CLI uses file settings and explicit window overrides before EOF", async () => {
  const file = join(await temporaryDirectory(), "live.yaml");
  await writeFile(
    file,
    "review_events:\n  screen_with_decisions: true\n  decisions_cutoff: 0.88\n  batch_size: 2\n  max_wait_seconds: 600\n",
  );
  const settings = (await loadProjectConfig(file)).reviewEvents;
  expect(settings).toMatchObject({ batchSize: 2, maxWaitSeconds: 600 });
  for (const [args, count] of [
    [[], 2],
    [["--batch-size", "1"], 1],
    [["--max-wait-seconds", "0.02"], 1],
  ] as const) {
    const input = new PassThrough();
    const firstWrite = Promise.withResolvers<string>();
    const out = new Writable({
      write(chunk, _, done) {
        firstWrite.resolve(String(chunk));
        done();
      },
    });
    const deps = dependencies();
    deps.recordsInput = input;
    deps.reviewSecurityEvents = async (data, options, surface) => {
      expect(options).toMatchObject({
        screenWithDecisions: true,
        decisionsCutoff: 0.88,
      });
      return reviewSecurityEventsInternal(data, options, surface);
    };
    const cli = createCliTest(main);
    const run = main(
      ["review-events", "--live", "-c", file, ...args],
      out,
      cli.stderr.stream,
      deps,
    );
    try {
      input.write((JSON.stringify(batch) + "\n").repeat(count));
      expect(JSON.parse(await firstWrite.promise)).toMatchObject({
        firstLine: 1,
        lastLine: count,
      });
    } finally {
      input.end();
    }
    expect(await run, cli.stderr.text()).toBe(0);
  }
});

test("keeps emitted windows on a malformed line and honors output backpressure", async () => {
  const consumed = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const emitted: string[] = [];
  const out = new Writable({
    write(chunk, _, done) {
      emitted.push(String(chunk));
      consumed.resolve();
      void release.promise.then(() => done());
    },
  });
  const deps = dependencies();
  const source = { ...batch, source: "café" };
  const bytes = Buffer.from(
    JSON.stringify(source) + "\r\n" + JSON.stringify(source) + "\n{",
  );
  const split = bytes.indexOf(0xc3) + 1;
  deps.recordsInput = Readable.from([
    bytes.subarray(0, split),
    bytes.subarray(split),
  ]);
  let reviews = 0;
  deps.reviewSecurityEvents = (...args) => {
    reviews++;
    return reviewSecurityEventsInternal(...args);
  };
  const cli = createCliTest(main);
  const run = main(
    ["review-events", "--live", "--batch-size", "1"],
    out,
    cli.stderr.stream,
    deps,
  );
  await consumed.promise;
  try {
    expect(reviews).toBe(1);
  } finally {
    release.resolve();
  }
  expect(await run).toBe(2);
  expect(emitted.map((line) => JSON.parse(line).source)).toEqual([
    "café",
    "café",
  ]);
  expect(cli.stderr.text()).toContain("line 3");
});

test("SIGTERM cancels an active live review and preserves already written output", async () => {
  const signals = new FakeSignals();
  const deps = dependencies({ signals });
  const input = new PassThrough();
  deps.recordsInput = input;
  const started = Promise.withResolvers<void>();
  let reviews = 0;
  deps.reviewSecurityEvents = (data, options, surface) => {
    if (++reviews === 1)
      return reviewSecurityEventsInternal(data, options, surface);
    started.resolve();
    return new Promise((_, reject) =>
      options.signal!.addEventListener(
        "abort",
        () => reject(options.signal!.reason),
        { once: true },
      ),
    );
  };
  const cli = createCliTest(main);
  const run = cli.runCli(
    ["review-events", "--live", "--batch-size", "1"],
    deps,
  );
  input.write((JSON.stringify(batch) + "\n").repeat(2));
  await started.promise;
  signals.emit("SIGTERM");
  expect(await run).toBe(143);
  expect(JSON.parse(cli.stdout.text()).lastLine).toBe(1);
  expect(cli.stderr.text()).toContain("canceled");
  expect(input.destroyed).toBe(true);
});
