import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

const args = [
  "dedupe",
  "--scan",
  "latest",
  "--findings-url",
  "http://127.0.0.1:3000",
  "--json",
];

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
  const stdout = capture();
  expect(
    await main(
      [
        "dedupe",
        "--workflow-id",
        "workflow-example",
        "--findings-url",
        "http://localhost:3000",
        "--json",
      ],
      stdout.stream,
      capture().stream,
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
    const stdout = capture();
    const stderr = capture();
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
      await main(
        [...args, ...(allRepositories ? ["--all-repositories"] : [])],
        stdout.stream,
        stderr.stream,
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
  expect(
    await main([...args, ...flags], capture().stream, capture().stream, deps),
  ).toBe(0);
  expect(called).toBe(true);
});

test.each(["0", "-1", "1.5", "NaN", "Infinity", "9007199254740992"])(
  "dedupe rejects invalid concurrency %s before calling the SDK",
  async (value) => {
    const deps = dependencies();
    let called = false;
    deps.deduplicateScan = async () => {
      called = true;
      throw new Error("Invalid concurrency must not reach the SDK");
    };
    const stderr = capture();
    expect(
      await main(
        [...args, "--concurrency", value],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("concurrency");
    expect(called).toBe(false);
  },
);

test("dedupe requires a value for concurrency", async () => {
  const stderr = capture();
  expect(
    await main(
      [...args, "--concurrency"],
      capture().stream,
      stderr.stream,
      dependencies(),
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("Missing value for flag: --concurrency");
});

test("dedupe help and schema expose concurrency and its default", async () => {
  const help = capture();
  expect(
    await main(
      ["dedupe", "--help"],
      help.stream,
      capture().stream,
      dependencies(),
    ),
  ).toBe(0);
  expect(help.text()).toContain("--concurrency");
  expect(help.text()).toContain("serial execution");

  const schema = capture();
  expect(
    await main(
      ["dedupe", "--schema", "--format", "json"],
      schema.stream,
      capture().stream,
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
  let called = false;
  deps.deduplicateScan = async () => {
    called = true;
    throw new Error("Finding has not been indexed");
  };
  for (const flags of [
    [],
    ["--scan", "latest"],
    ["--findings-url", "http://127.0.0.1:3000"],
  ]) {
    expect(
      await main(
        ["dedupe", ...flags],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).not.toBe(0);
  }
  expect(called).toBe(false);
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(2);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain("Finding has not been indexed");
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
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(
      expectedCode,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Deduplication canceled");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  }
});
