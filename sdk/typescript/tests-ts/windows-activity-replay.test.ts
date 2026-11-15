import { spawnSync } from "node:child_process";
import { mkdtempSync, rmdirSync } from "node:fs";
import { appendFile, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, expect, mock, test } from "bun:test";
import { runScanEvents } from "../src/api.js";
import { ScanCostTracker } from "../src/cost.js";
import { saveLiveActivityPaths } from "../src/observed-activities.js";
import { sameWindowsActivityDirectory } from "../src/scan-activity.js";
import { readScanLogs } from "../src/scan-logs.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("activity-replay-");
afterEach(cleanup);

function caseSensitiveParent() {
  if (process.platform !== "win32") return;
  const parent = mkdtempSync(join(tmpdir(), "case-sensitive-"));
  const fsutil = join(
    process.env["SystemRoot"] ?? "C:\\Windows",
    "System32",
    "fsutil.exe",
  );
  const result = spawnSync(fsutil, [
    "file",
    "setCaseSensitiveInfo",
    parent,
    "enable",
  ]);
  if (result.status === 0) return parent;
  console.warn(
    "Skipping the distinct NTFS sibling fixture because fsutil could not enable directory case sensitivity.",
  );
  rmdirSync(parent);
}
const distinctParent = caseSensitiveParent();
afterAll(async () => {
  if (distinctParent)
    await rm(distinctParent, { recursive: true, force: true });
});

async function checkActivityReplay(checkouts: string, distinct: boolean) {
  const home = await temporaryDirectory();
  const repository = join(checkouts, "Repo");
  const candidate = join(checkouts, "repo");
  await mkdir(repository);
  if (distinct) await mkdir(candidate);
  const selected = await stat(repository, { bigint: true });
  const alternate = await stat(candidate, { bigint: true });
  expect(selected.ino).not.toBe(0n);
  expect(selected.dev === alternate.dev && selected.ino === alternate.ino).toBe(
    !distinct,
  );

  await mkdir(join(candidate, "Src"));
  const path = join(candidate, "Src", "App.ts");
  await writeFile(path, "");
  const expected = distinct ? [] : ["Src/App.ts"];
  const scanId = "scan-activity";
  const threadId = "parent";
  const workerId = "worker";
  const options = {
    codexHome: home,
    model: "gpt-5.6-sol",
    repository,
    activityObservations: { scanId },
  };
  const workerPaths: string[][] = [];
  const verifyWorker = mock(sameWindowsActivityDirectory);
  const tracker = new ScanCostTracker({
    ...options,
    verifyActivityDirectory: verifyWorker,
    onActivity: (activity) => workerPaths.push(activity.paths),
  });
  tracker.beginParentTurn();
  const timestamp = new Date().toISOString();
  const usage = { input_tokens: 1, output_tokens: 1 };
  const parent = await writeSession(home, threadId, usage, { timestamp });
  const worker = await writeSession(home, workerId, usage, {
    timestamp,
    parent: threadId,
  });
  const parentRead = {
    type: "response_item",
    timestamp,
    payload: {
      type: "function_call",
      name: "read_file",
      call_id: "read",
      arguments: JSON.stringify({ path }),
    },
  };
  const workerCommand = {
    type: "response_item",
    timestamp,
    payload: {
      type: "local_shell_call",
      call_id: "argv",
      action: { type: "exec", command: ["type", path] },
    },
  };
  await appendFile(worker, JSON.stringify(workerCommand) + "\n");

  async function* liveEvents() {
    yield { type: "thread.started", thread_id: threadId };
    yield {
      type: "item.started",
      item: {
        type: "mcp_tool_call",
        id: "sdk-read",
        tool: "read_file",
        arguments: { path },
        status: "in_progress",
      },
    };
    yield {
      type: "turn.failed",
      error: { message: "end of activity fixture" },
    };
  }
  const livePaths: string[][] = [];
  await expect(
    runScanEvents({
      scanId,
      thread: { id: null },
      events: liveEvents(),
      signal: new AbortController().signal,
      scanDir: home,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository,
        repositoryRevision: null,
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      verifyActivityDirectory: sameWindowsActivityDirectory,
      recordActivityPaths: (liveThread, occurrence, activity) =>
        saveLiveActivityPaths(home, scanId, liveThread, occurrence, activity),
      onActivity: (activity) => livePaths.push(activity.paths),
    }),
  ).rejects.toThrow("end of activity fixture");
  expect(livePaths).toEqual([expected]);

  tracker.start(threadId);
  try {
    await tracker.refresh();
    expect(workerPaths).toEqual([expected]);
    await rm(repository, { recursive: true });
    if (distinct) await rm(candidate, { recursive: true });
    // The raw parent projection may reach disk after its SDK observer ran.
    await appendFile(parent, JSON.stringify(parentRead) + "\n");
  } finally {
    await tracker.stop();
  }
  expect(verifyWorker).toHaveBeenCalledTimes(1);

  const logs = await readScanLogs({ codexHome: home, threadId, scanId });
  const session = logs.sessions.find((row) => row.threadId === threadId);
  expect(session?.observedActivities ?? []).toEqual(
    distinct
      ? []
      : [
          {
            id: "sdk-read",
            kind: "tool",
            status: "running",
            paths: expected,
          },
        ],
  );
  expect(logs.events).toContainEqual({ threadId, event: parentRead });
  const recorded = distinct ? {} : { paths: expected };
  expect(logs.events).toContainEqual({
    threadId: workerId,
    event: workerCommand,
    ...recorded,
  });
  const replayPaths: string[][] = [];
  const resumed = new ScanCostTracker({
    ...options,
    onActivity: (activity) => replayPaths.push(activity.paths),
  });
  resumed.start(threadId);
  await resumed.stop();
  expect(replayPaths).toEqual([expected]);
}

test.skipIf(process.platform !== "win32")(
  "replays an observed Windows drive directory alias after checkout removal",
  async () => {
    await checkActivityReplay(await temporaryDirectory(), false);
  },
);
test.skipIf(!distinctParent)(
  "excludes a distinct NTFS sibling from live and replayed activity (requires directory case sensitivity)",
  async () => {
    await checkActivityReplay(distinctParent!, true);
  },
);
