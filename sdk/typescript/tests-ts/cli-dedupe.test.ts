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
  "dedupe passes the scan selector, URL, and all-repository scope %s to the SDK",
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
