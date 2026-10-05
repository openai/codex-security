import { expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { throwing, rejecting } from "./support/errors.js";

import {
  createCliTest,
  captureCli,
  runCapturedCli,
} from "./support/cli-run.js";

const args = [
  "dedupe",
  "--scan",
  "latest",
  "--findings-url",
  "http://127.0.0.1:3000",
  "--json",
];

test.each([false, true])(
  "dedupe reports refusals and succeeds even when diagnostic output fails: %j",
  async (brokenLog) => {
    const deps = dependencies();
    const result = {
      scanId: "scan-example",
      uniqueFindingIds: ["finding-one", "finding-two"],
      duplicateGroups: [],
      deduplicationStatus: "completed_with_refusals" as const,
      refusals: [
        {
          decision: "NO_DECISION" as const,
          stage: "pair-review" as const,
          model: "gpt-5.6-sol",
          findingIds: ["finding-one", "finding-two"],
          reason: "The model refused the deduplication review.",
        },
      ],
    };
    deps.deduplicateScan = async () => result;
    const { stdout, stderr, runCli } = createCliTest(main);

    if (brokenLog) stderr.stream.write = throwing("Synthetic logging failure");
    expect(await runCli(args, deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    if (!brokenLog) {
      expect(stderr.text()).toContain("pair-review refused by gpt-5.6-sol");
      expect(stderr.text()).toContain("finding-one, finding-two");
      expect(stderr.text()).toContain("No decision was made");
      expect(stderr.text()).toContain("kept separate");
    }
  },
);

test("dedupe resolves a workflow's pinned scan and passes the workflow ID to the SDK", async () => {
  const deps = dependencies();
  deps.runWorkbench = async (args, input) => {
    expect(args).toEqual(["finding-workflow"]);
    expect(JSON.parse(input!)).toEqual({
      id: "workflow-example",
      action: "get",
    });
    return {
      workflow: {
        id: "workflow-example",
        scanId: "exact-scan",
        scanDir: "/synthetic/artifacts",
      },
    };
  };
  deps.deduplicateScan = async (scanId, options) => {
    expect(scanId).toBe("exact-scan");
    expect(options.workflowId).toBe("workflow-example");
    return {
      scanId,
      uniqueFindingIds: [],
      duplicateGroups: [],
      deduplicationStatus: "completed",
    };
  };
  const stdout = captureCli(main, "stdout");
  expect(
    await stdout.run(
      [
        "dedupe",
        "--workflow-id",
        "workflow-example",
        "--findings-url",
        "http://localhost:3000",
        "--json",
      ],
      deps,
    ),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual({
    scanId: "exact-scan",
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
});

test.each([false, true])(
  "dedupe passes the scan selector, URL, and all-repository scope %j to the SDK",
  async (allRepositories) => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    const result = {
      scanId: "scan-example",
      uniqueFindingIds: ["finding-example"],
      duplicateGroups: [],
      deduplicationStatus: "completed" as const,
    };
    deps.deduplicateScan = async (scanId, options, dependencies) => {
      expect(scanId).toBe("latest");
      expect(options).toEqual({
        findingsUrl: "http://127.0.0.1:3000",
        concurrency: 8,
        allRepositories,
        signal: expect.any(AbortSignal),
      });
      expect(dependencies?.runWorkbench).toBe(deps.runWorkbench);
      return result;
    };
    expect(
      await runCli(
        [...args, ...(allRepositories ? ["--all-repositories"] : [])],
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toBe("");
  },
);

test.each([
  { flags: ["--concurrency", "1"], expected: 1 },
  { flags: ["--concurrency", "3"], expected: 3 },
  { flags: ["--concurrency=3"], expected: 3 },
])("dedupe forwards configured concurrency %j", async ({ flags, expected }) => {
  const deps = dependencies();
  let called = false;
  deps.deduplicateScan = async (scanId, options) => {
    called = true;
    expect(options.concurrency).toBe(expected);
    return {
      scanId,
      uniqueFindingIds: [],
      duplicateGroups: [],
      deduplicationStatus: "completed",
    };
  };
  expect(await runCapturedCli(main, [...args, ...flags], deps)).toBe(0);
  expect(called).toBe(true);
});

test.each(["0", "-1", "1.5", "NaN", "Infinity", "9007199254740992"])(
  "dedupe rejects invalid concurrency %s before calling the SDK",
  async (value) => {
    const deps = dependencies();
    const deduplicateScan = mock(
      rejecting("Invalid concurrency must not reach the SDK"),
    );
    deps.deduplicateScan = deduplicateScan;
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run([...args, "--concurrency", value], deps)).toBe(2);
    expect(stderr.text()).toContain("concurrency");
    expect(deduplicateScan).not.toHaveBeenCalled();
  },
);

test("dedupe requires a value for concurrency", async () => {
  const stderr = captureCli(main, "stderr");
  expect(await stderr.run([...args, "--concurrency"], dependencies())).toBe(2);
  expect(stderr.text()).toContain("Missing value for flag: --concurrency");
});

test("dedupe help and schema expose concurrency and its default", async () => {
  const help = captureCli(main, "stdout");
  expect(await help.run(["dedupe", "--help"], dependencies())).toBe(0);
  expect(help.text()).toContain("--concurrency");
  expect(help.text()).toContain("serial execution");

  const schema = captureCli(main, "stdout");
  expect(
    await schema.run(
      ["dedupe", "--schema", "--format", "json"],
      dependencies(),
    ),
  ).toBe(0);
  expect(
    JSON.parse(schema.text()).options.properties.concurrency,
  ).toMatchObject({
    type: "integer",
    default: 8,
  });
});

test("dedupe requires both explicit inputs and reports SDK failures", async () => {
  const deps = dependencies();
  const deduplicateScan = mock(rejecting("Finding has not been indexed"));
  deps.deduplicateScan = deduplicateScan;
  for (const flags of [
    [],
    ["--scan", "latest"],
    ["--findings-url", "http://127.0.0.1:3000"],
  ]) {
    expect(await runCapturedCli(main, ["dedupe", ...flags], deps)).not.toBe(0);
  }
  expect(deduplicateScan).not.toHaveBeenCalled();
  const { stdout, stderr, runCli } = createCliTest(main);

  expect(await runCli(args, deps)).toBe(2);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toBe("codex-security: Finding has not been indexed\n");
});

test("dedupe forwards cancellation and removes signal handlers", async () => {
  for (const [signal, expectedCode] of [
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const) {
    const signals = new FakeSignals();
    const deps = dependencies();
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    deps.deduplicateScan = async (_scanId, options) => {
      signals.emit(signal);
      options.signal!.throwIfAborted();
      throw new Error("Cancellation must throw");
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(await runCli(args, deps)).toBe(expectedCode);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Deduplication canceled");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  }
});
