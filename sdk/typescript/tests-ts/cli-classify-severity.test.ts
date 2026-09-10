import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { Writable } from "node:stream";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  SeverityClassificationError,
  severityRetryCommand,
  type SeverityClassificationProgress,
} from "../src/classify-severity.js";
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

test("classification failures explain saved progress and give a pinned retry command without changing stdout", async () => {
  const deps = dependencies();
  const stderr = capture();
  const stdout = capture();
  const progress: SeverityClassificationProgress = {
    status: "failed",
    phase: "classification",
    total: 5,
    completed: 3,
    reused: 1,
    remaining: 2,
    findingId: "finding-failed",
    threadId: "thread-example",
    failure: { stage: "model", message: "Model stream closed" },
    retryArguments: [
      "classify-severity",
      "--scan-dir",
      "/saved/scan one",
      "--rubric",
      "/saved/policy's.md",
    ],
  };
  deps.classifyScanSeverity = async (_scanId, options) => {
    options?.onProgress?.(progress);
    throw new SeverityClassificationError(
      progress,
      new Error("Model stream closed"),
    );
  };
  expect(
    await main(
      ["classify-severity", "--scan", "latest", "--json"],
      stdout.stream,
      stderr.stream,
      deps,
    ),
  ).toBe(2);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain("3/5 completed (1 reused), 2 remaining");
  expect(stderr.text()).toContain("finding-failed");
  expect(stderr.text()).toContain("thread-example");
  expect(stderr.text()).toContain(
    severityRetryCommand(progress.retryArguments!),
  );
  expect(stderr.text()).not.toContain("--scan latest");
});

test("retry commands quote shell interpolation and apostrophes on POSIX and PowerShell", () => {
  expect(
    severityRetryCommand(
      ["--scan-dir", String.raw`/tmp/scan\archive`],
      "linux",
    ),
  ).toContain(String.raw`'/tmp/scan\archive'`);
  const args = ["classify-severity", "--scan-dir", "C:\\saved\\scan '$value'"];
  expect(severityRetryCommand(args, "win32")).toContain(
    "'C:\\saved\\scan ''$value'''",
  );
  expect(
    severityRetryCommand(["--rubric", "policy'$(exit 1).md"], "linux"),
  ).toContain("'policy'\"'\"'$(exit 1).md'");
});

const powershell = Bun.which("pwsh") ?? Bun.which("powershell.exe");
for (const quote of [
  "'",
  "\u2018",
  "\u2019",
  "\u201a",
  "\u201b",
  "\uff07\u2032\u201c\u201d",
]) {
  test.skipIf(powershell === null)(
    `retry commands preserve PowerShell argument values containing ${JSON.stringify(quote)}`,
    () => {
      const args = [
        "classify-severity",
        "--scan",
        "scan-example",
        "--rubric",
        `C:\\policies\\team${quote}s $value $(literal).md`,
        "--knowledge-base",
        `C:\\context\\${quote}${quote}.md`,
      ];
      const script = [
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()",
        "function codex-security { ConvertTo-Json -Compress -InputObject @($args) }",
        severityRetryCommand(args, "win32"),
      ].join("\n");
      const result = spawnSync(
        powershell!,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout.trim())).toEqual(args);
    },
  );
}

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

test("classification continues after asynchronous stderr failure and releases its error listener", async () => {
  const deps = dependencies();
  const stdout = capture();
  const stderr = new Writable({
    write(_chunk, _encoding, callback) {
      setImmediate(() =>
        callback(
          Object.assign(new Error("Closed progress pipe"), { code: "EPIPE" }),
        ),
      );
    },
  });
  let finished = false;
  deps.classifyScanSeverity = async (_scanId, options) => {
    options!.onProgress!({
      status: "running",
      phase: "classification",
      total: 2,
      completed: 1,
      reused: 0,
      remaining: 1,
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    finished = true;
    return result;
  };
  try {
    expect(
      await main(
        ["classify-severity", "--scan", "latest", "--json"],
        stdout.stream,
        stderr,
        deps,
      ),
    ).toBe(0);
    expect(finished).toBe(true);
    expect(JSON.parse(stdout.text())).toEqual(result);
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(stderr.listenerCount("error")).toBe(0);
  } finally {
    stderr.destroy();
  }
});
