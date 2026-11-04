import { Readable } from "node:stream";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { reviewSecurityEventsInternal } from "../src/review-events.js";
import { loadProjectConfig } from "../src/project-config.js";
import { dependencies } from "./cli-fixtures.js";
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
