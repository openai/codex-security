import { PLUGIN_ROOT } from "./plugin-root.js";
import { spawnSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import type { ScanExecutionAttribution } from "../src/scan-sessions.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";

async function run(args: string[], deps = dependencies()) {
  const { stdout, stderr, runCli } = createCliTest(main);

  const code = await runCli(["feedback", ...args], deps);
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

test("feedback selects the newest saved scan when starts differ by a microsecond", async () => {
  const root = await temporaryDirectory("feedback-history-", true);
  try {
    const python = await resolvePluginPython();
    const repository = join(root, "repository");
    const environment = {
      PATH: process.env["PATH"],
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const workbench = (args: readonly string[]) =>
      runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args);
    const scans: { scanId: string; status: string; startedAt: string }[] = [];
    for (const [index, status] of ["running", "failed", "running"].entries()) {
      const target = index === 2 ? join(root, "other-repository") : repository;
      const scanDir = join(root, `scan-${index}`);
      await mkdir(target, { recursive: true });
      await mkdir(scanDir, { mode: 0o700 });
      const registered = await workbench([
        "register-cli-scan",
        "--repository",
        target,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository: target,
          target: { kind: "repository", paths: [] },
        }),
      ]);
      scans.push({
        scanId: registered["scanId"] as string,
        status,
        startedAt: [
          "2026-01-01T00:00:00Z",
          "2026-01-01T00:00:00.000001Z",
          "2026-01-02T00:00:00Z",
        ][index]!,
      });
    }
    const seeded = spawnSync(
      python,
      [
        "-c",
        `import json, sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    for scan in json.loads(sys.argv[2]):
        connection.execute("UPDATE scans SET started_at = ?, status = ? WHERE id = ?", (scan["startedAt"], scan["status"], scan["scanId"]))`,
        join(environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
        JSON.stringify(scans),
      ],
      { encoding: "utf8" },
    );
    expect(seeded.stderr).toBe("");
    expect(seeded.status).toBe(0);
    const history = await workbench(["list-scans", "--repository", repository]);
    expect(
      (history["scans"] as JsonObject[]).map((scan) => scan["scanId"]),
    ).toEqual([scans[0]!.scanId, scans[1]!.scanId]);
    const deps = dependencies({
      currentDirectory: repository,
      environment,
      onWorkbench: workbench,
    });
    deps.sendFeedback = async ({ scan }) => {
      expect(scan?.scanId).toBe(scans[1]!.scanId);
      return {
        feedbackId: "feedback-1",
        scanId: scan!.scanId,
        includedLogs: true,
      };
    };
    const result = await run(
      ["--reason", "Scan stopped", "--include-logs", "--json"],
      deps,
    );
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout).scanId).toBe(scans[1]!.scanId);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["2026-10-08T01:00:00Z", "2026-10-08T01:00:00.100000Z", 1],
  ["2026-10-08T01:00:00.000001Z", "2026-10-08T01:00:00.000002Z", 1],
  ["2026-10-08T01:00:00.1234567Z", "2026-10-08T01:00:00.1234568Z", 1],
  ["2026-10-08T03:00:00.123400+02:00", "2026-10-08T01:00:00.123401Z", 1],
  ["1969-12-31T23:59:59.000001Z", "1969-12-31T23:59:59.000002Z", 1],
  ["2026-10-08T01:00:00.000000Z", "2026-10-08T01:00:00Z", 0],
  ["2026-10-08T01:00:00.1000000Z", "2026-10-08T03:00:00.1+02:00", 0],
  ["2026-10-08T01:00:00Z", "2026-10-08T01:00:00.000000000000000000001Z", 1],
] as const)(
  "feedback selects by exact start time: %s / %s",
  async (first, second, selected) => {
    const scans = [
      { scanId: "z-first", startedAt: first, status: "running" },
      { scanId: "a-second", startedAt: second, status: "failed" },
    ];
    const expected = scans[selected]!;
    const calls: string[][] = [];
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push([...args]);
        return args[0] === "list-scans"
          ? { scans }
          : { scan: scans.find((scan) => scan.scanId === args[2])! };
      },
    });
    deps.sendFeedback = async ({ scan, includeLogs }) => {
      expect(scan?.scanId).toBe(expected.scanId);
      expect(includeLogs).toBe(true);
      return {
        feedbackId: "feedback-chronology",
        scanId: scan!.scanId,
        includedLogs: true,
      };
    };
    const result = await run(
      ["--reason", "Synthetic scan stopped", "--include-logs", "--json"],
      deps,
    );
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout).scanId).toBe(expected.scanId);
    expect(calls.map((args) => args[0])).toEqual(["list-scans", "get-scan"]);
    expect(calls[1]).toEqual(["get-scan", "--scan-id", expected.scanId]);
  },
);

test("feedback selects a scan prefix", async () => {
  const calls: string[][] = [];
  const scan = { scanId: "scan-prefix-full", progress: { status: "failed" } };
  const deps = dependencies({
    onWorkbench: (args): JsonObject => {
      calls.push([...args]);
      return { scan };
    },
  });
  const report = {
    feedbackId: "feedback-1",
    scanId: scan.scanId,
    includedLogs: true,
  };
  deps.sendFeedback = async (options) => {
    expect(options).toMatchObject({
      reason: "Scan stopped",
      includeLogs: true,
      scan,
    });
    return report;
  };
  const result = await run(
    ["scan-pre", "--reason", "Scan stopped", "--include-logs", "--json"],
    deps,
  );
  expect(result.code).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual(report);
  expect(calls).toEqual([["get-scan", "--scan-id", "scan-pre"]]);
});

for (const includeLogs of [false, true]) {
  test(`feedback requests private execution settings only with log opt-in (${includeLogs})`, async () => {
    const executionAttribution = {
      formatVersion: 1,
      codexHome: "synthetic-recorded-worker-home",
      executionThreadIds: ["discovery-thread", "reducer-thread"],
      owner: {
        threadId: "owner-thread",
        turnId: "owned-turn",
        startedAt: "2026-09-10T10:00:00Z",
      },
      startedAt: "2026-09-10T10:00:00Z",
      completedAt: "2026-09-10T12:00:00Z",
    } satisfies ScanExecutionAttribution;
    const deps = dependencies();
    deps.runWorkbench = async (
      args,
      _input,
      _signal,
      _python,
      _protectedRoot,
      withExecutionSettings,
    ) => {
      expect(args).toEqual(["get-scan", "--scan-id", "scan-pre"]);
      expect(withExecutionSettings === true).toBe(includeLogs);
      return {
        scan: {
          scanId: "scan-pre",
          ...(withExecutionSettings ? { executionAttribution } : {}),
        },
      };
    };
    deps.sendFeedback = async ({ scan }) => {
      expect(scan?.executionAttribution).toEqual(
        includeLogs ? executionAttribution : undefined,
      );
      return {
        feedbackId: "feedback-1",
        scanId: "scan-pre",
        includedLogs: includeLogs,
      };
    };
    const result = await run(
      [
        "scan-pre",
        "--reason",
        "Synthetic scan stopped",
        ...(includeLogs ? ["--include-logs"] : []),
        "--json",
      ],
      deps,
    );
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
  });
}

test("feedback without saved scans sends a general report with logs off", async () => {
  const deps = dependencies();
  deps.sendFeedback = async (options) => {
    expect(options.scan).toBeUndefined();
    expect(options.includeLogs).toBe(false);
    return { feedbackId: "feedback-2", scanId: null, includedLogs: false };
  };
  const result = await run(["--reason", "Install failed", "--json"], deps);
  expect(result.code).toBe(0);
  expect(JSON.parse(result.stdout).feedbackId).toBe("feedback-2");
});

test("Ctrl-C cancels feedback and removes signal listeners", async () => {
  const signals = new FakeSignals();
  const deps = dependencies({ signals });
  deps.sendFeedback = async ({ signal }) => {
    signals.emit("SIGINT");
    signal!.throwIfAborted();
    throw new Error("Must be canceled");
  };
  const result = await run(["--reason", "Problem"], deps);
  expect(result.code).toBe(130);
  expect(result.stderr).toContain("Feedback upload canceled");
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});

for (const args of [
  [],
  ["--reason", " "],
  ["extra", "scan", "--reason", "Problem"],
]) {
  test(`feedback rejects invalid arguments ${JSON.stringify(args)}`, async () => {
    const deps = dependencies({
      onWorkbench: throwing("Must not read scans"),
    });
    deps.sendFeedback = rejecting("Must not upload");
    const result = await run(args, deps);
    expect(result.code).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).not.toContain("Must not");
  });
}

for (const missingScan of [false, true]) {
  test(`feedback reports ${missingScan ? "scan lookup" : "upload"} failures without a success ID`, async () => {
    const deps = dependencies({
      onWorkbench: () => {
        if (missingScan) throw new Error("Scan not found");
        return { scans: [] };
      },
    });
    const upload = mock(rejecting("Upload failed"));
    deps.sendFeedback = upload;
    const result = await run(
      [
        ...(missingScan ? ["unknown-scan"] : []),
        "--reason",
        "Problem",
        "--json",
      ],
      deps,
    );
    expect(result.code).toBe(2);
    expect(result.stdout).toBe("");
    expect(upload).toHaveBeenCalledTimes(missingScan ? 0 : 1);
    expect(result.stderr).toContain(
      missingScan ? "Scan not found" : "Upload failed",
    );
  });
}
