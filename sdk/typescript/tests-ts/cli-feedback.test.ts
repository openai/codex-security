import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

async function run(args: string[], deps = dependencies()) {
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["feedback", ...args],
    stdout.stream,
    stderr.stream,
    deps,
  );
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

test("feedback selects the newest saved scan when an older scan is still running", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "feedback-history-")),
  );
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
        startedAt: `2026-01-0${index + 1}T00:00:00Z`,
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
      onWorkbench: () => {
        throw new Error("Must not read scans");
      },
    });
    deps.sendFeedback = async () => {
      throw new Error("Must not upload");
    };
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
    const upload = mock(async () => {
      throw new Error("Upload failed");
    });
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
