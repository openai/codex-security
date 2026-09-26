import { resolve } from "node:path";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

const result = {
  schemaVersion: 1 as const,
  assessedAt: "2026-06-01T00:00:00Z",
  scanId: "scan-example",
  rubricSha256: null,
  knowledgeBaseSha256: null,
  assessments: [],
};

test.each(["latest", "scan_prefix"])(
  "classify-severity accepts saved scan selector %s",
  async (selector) => {
    const deps = dependencies();
    const stdout = capture();
    deps.classifyScanSeverity = async (scanId, options, history, surface) => {
      expect(scanId).toBe(selector);
      expect(options!.rubricPath).toBe(
        resolve(deps.currentDirectory(), "policy.md"),
      );
      expect(options!.knowledgeBasePaths).toEqual([
        resolve(deps.currentDirectory(), "context.md"),
      ]);
      expect(options!.findingIds).toEqual(["finding-one", "finding-two"]);
      expect(options!.reprocess).toBe(true);
      expect(options!.model).toBe("synthetic-model");
      expect(options!.reasoningEffort).toBe("high");
      expect(history?.runWorkbench).toBe(deps.runWorkbench);
      expect(surface).toBe("cli");
      return result;
    };
    expect(
      await main(
        [
          "classify-severity",
          "--scan",
          selector,
          "--rubric",
          "policy.md",
          "--knowledge-base",
          "context.md",
          "--finding-id",
          "finding-one",
          "--finding-id",
          "finding-two",
          "--model",
          "synthetic-model",
          "--effort",
          "high",
          "--reprocess",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
  },
);

test("classify-severity accepts external scan directories and defaults to existing severity", async () => {
  const deps = dependencies();
  let called = false;
  deps.classifyScanDirectorySeverity = async (directory, options, surface) => {
    called = true;
    expect(directory).toBe(resolve(deps.currentDirectory(), "saved scan"));
    expect(options!.rubricPath).toBeUndefined();
    expect(options!.reprocess).toBe(false);
    expect(options!.findingIds).toBeUndefined();
    expect(surface).toBe("cli");
    return result;
  };
  expect(
    await main(
      ["classify-severity", "--scan-dir", "saved scan", "--json"],
      capture().stream,
      capture().stream,
      deps,
    ),
  ).toBe(0);
  expect(called).toBe(true);
});

test("classify-severity rejects missing or conflicting selectors and surfaces SDK errors", async () => {
  const deps = dependencies();
  let calls = 0;
  deps.classifyScanSeverity = async () => {
    calls++;
    throw new Error("The scan is incomplete");
  };
  for (const args of [[], ["--scan", "latest", "--scan-dir", "saved"]]) {
    expect(
      await main(
        ["classify-severity", ...args],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(2);
  }
  expect(calls).toBe(0);
  const stderr = capture();
  expect(
    await main(
      ["classify-severity", "--scan", "latest"],
      capture().stream,
      stderr.stream,
      deps,
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("The scan is incomplete");
});

test.each([
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const)(
  "classification forwards %s and removes listeners",
  async (signal, expectedCode) => {
    const deps = dependencies();
    const signals = new FakeSignals();
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    deps.classifyScanSeverity = async (_scanId, options) => {
      signals.emit(signal);
      options!.signal!.throwIfAborted();
      return result;
    };
    expect(
      await main(
        ["classify-severity", "--scan", "latest"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(expectedCode);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);

test("publication forwards selected finding IDs only to Linear", async () => {
  const deps = dependencies();
  deps.publishScan = async (_directory, options) => {
    expect(options!.findingIds).toEqual(["finding-one", "finding-two"]);
    return {
      scanId: "scan-example",
      uploadId: "scan-example",
      destination: { type: "linear", teamId: "team-example" },
      created: [],
      failed: [],
      counts: { findings: 0, created: 0, failed: 0 },
      dryRun: true,
      issues: [],
    };
  };
  expect(
    await main(
      [
        "publish",
        "scan",
        "--scan-dir",
        "saved",
        "--to",
        "linear",
        "--linear-team",
        "team-example",
        "--finding-id",
        "finding-one",
        "--finding-id",
        "finding-two",
        "--dry-run",
        "--json",
      ],
      capture().stream,
      capture().stream,
      deps,
    ),
  ).toBe(0);
  expect(
    await main(
      [
        "publish",
        "scan",
        "--scan-dir",
        "saved",
        "--to",
        "custom",
        "--findings-url",
        "http://localhost:3000",
        "--finding-id",
        "finding-one",
      ],
      capture().stream,
      capture().stream,
      deps,
    ),
  ).toBe(2);
});
