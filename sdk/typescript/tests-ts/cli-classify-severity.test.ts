import { rejecting } from "./support/errors.js";
import { resolve } from "node:path";
import { expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";

import { captureCli, runCapturedCli } from "./support/cli-run.js";

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
    const stdout = captureCli(main, "stdout");
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
      await stdout.run(
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
    await runCapturedCli(
      main,
      ["classify-severity", "--scan-dir", "saved scan", "--json"],
      deps,
    ),
  ).toBe(0);
  expect(called).toBe(true);
});

test("classify-severity rejects missing or conflicting selectors and surfaces SDK errors", async () => {
  const deps = dependencies();
  const classifyScanSeverity = mock(rejecting("The scan is incomplete"));
  deps.classifyScanSeverity = classifyScanSeverity;
  for (const args of [[], ["--scan", "latest", "--scan-dir", "saved"]]) {
    expect(
      await runCapturedCli(main, ["classify-severity", ...args], deps),
    ).toBe(2);
  }
  expect(classifyScanSeverity).toHaveBeenCalledTimes(0);
  const stderr = captureCli(main, "stderr");
  expect(
    await stderr.run(["classify-severity", "--scan", "latest"], deps),
  ).toBe(2);
  expect(stderr.text()).toBe("codex-security: The scan is incomplete\n");
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
      await runCapturedCli(
        main,
        ["classify-severity", "--scan", "latest"],
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
    await runCapturedCli(
      main,
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
      deps,
    ),
  ).toBe(0);
  expect(
    await runCapturedCli(
      main,
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
      deps,
    ),
  ).toBe(2);
});
