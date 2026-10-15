import { spawn } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  writeFile,
  appendFile,
  rm,
  cp,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, spyOn, test } from "bun:test";
import { ScanCostTracker } from "../src/cost.js";
import {
  recordScanLogTurn,
  readSavedScanLogs,
  settleScanLogTurns,
} from "../src/scan-logs.js";

for (const [fixture, description] of [
  [
    "scan-log-io.ts",
    "optional attribution reads cannot hold invocation, events, or completion",
  ],
  [
    "scan-log-owner.ts",
    "client close owns only its writes in a shared credential home",
  ],
])
  test(description!, async () => {
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL(`./fixtures/${fixture}`, import.meta.url))],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    child.stdout.on("data", (data) => {
      output += data;
    });
    child.stderr.on("data", (data) => {
      output += data;
    });
    expect(
      await new Promise<number | null>((resolve) =>
        child.once("close", resolve),
      ),
      output,
    ).toBe(0);
  });

test("attribution write failures preserve scan errors and cancellation", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-log-write-"));
  const pendingWrites = new Set<Promise<void>>();
  try {
    await mkdir(join(home, "sessions"));
    const rollout = join(home, "sessions", "root.jsonl");
    await writeFile(
      rollout,
      JSON.stringify({ type: "session_meta", payload: { id: "root" } }) + "\n",
    );
    await writeFile(join(home, "scan-log-turns"), "unwritable destination");
    for (const cancel of [false, true]) {
      const failure = new Error("original scan failure");
      let warning: unknown;
      const events = recordScanLogTurn(
        {
          scanId: `scan-${cancel}`,
          threadId: () => "root",
          codexHome: home,
          pendingWrites,
          tracker: new ScanCostTracker({ codexHome: home, model: "gpt-5" }),
        },
        async () => ({
          events: (async function* () {
            await appendFile(
              rollout,
              JSON.stringify({
                type: "event_msg",
                timestamp: new Date().toISOString(),
                payload: {
                  type: "task_started",
                  turn_id: `turn-${cancel}`,
                  started_at: Date.now() / 1_000,
                },
              }) + "\n",
            );
            yield { type: "turn.started" };
            throw failure;
          })(),
        }),
        (error) => {
          warning = error;
          throw new Error("warning observer failure");
        },
      );
      await events.next();
      if (cancel) expect((await events.return(undefined)).done).toBe(true);
      else await expect(events.next()).rejects.toBe(failure);
      await settleScanLogTurns(pendingWrites);
      expect(warning).toBeDefined();
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("concurrent scans retain active and saved root/child turns without later work", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-log-owners-"));
  const copy = await mkdtemp(join(tmpdir(), "scan-log-copy-"));
  const pendingWrites = new Set<Promise<void>>();
  const now = Date.parse("2026-08-21T12:00:00Z");
  let currentNow = now;
  const clock = spyOn(Date, "now").mockImplementation(() => currentNow);
  const session = async (
    id: string,
    scanDirectory: string,
    parent?: string,
  ) => {
    await mkdir(join(home, "sessions"), { recursive: true });
    await writeFile(
      join(home, "sessions", `${id}.jsonl`),
      JSON.stringify({
        type: "session_meta",
        payload: {
          id,
          cwd: scanDirectory,
          timestamp: new Date(now - 10_000).toISOString(),
          source: parent
            ? { subagent: { thread_spawn: { parent_thread_id: parent } } }
            : "cli",
        },
      }) + "\n",
    );
  };
  const task = async (id: string, turnId: string) => {
    await appendFile(
      join(home, "sessions", `${id}.jsonl`),
      [
        {
          type: "event_msg",
          timestamp: new Date(currentNow).toISOString(),
          payload: {
            type: "task_started",
            turn_id: turnId,
            started_at: currentNow / 1_000,
          },
        },
        {
          type: "response_item",
          timestamp: new Date(currentNow).toISOString(),
          payload: { type: "message", text: turnId },
        },
      ]
        .map((event) => JSON.stringify(event) + "\n")
        .join(""),
    );
  };
  const saved = (id: string) => ({
    scanId: id,
    continuationThreadId: id,
    executionThreadIds: [id],
    progress: { status: "complete", updatedAt: "2026-08-21T11:59:00Z" },
  });
  const tasks = async (id: string, directory = home) =>
    (await readSavedScanLogs(saved(id), directory)).events.flatMap(
      ({ threadId, event }) => {
        const payload = (event as Record<string, unknown>)["payload"] as {
          type: string;
          turn_id?: string;
        };
        return payload.type === "task_started"
          ? [[threadId, payload.turn_id]]
          : [];
      },
    );
  try {
    const generators = [];
    for (const id of ["one", "two"]) {
      const scanDirectory = join(home, `scan-${id}`);
      await session(id, scanDirectory);
      await session(`${id}-child`, scanDirectory, id);
      const events = recordScanLogTurn(
        {
          scanId: id,
          threadId: () => id,
          codexHome: home,
          pendingWrites,
          tracker: new ScanCostTracker({
            codexHome: home,
            model: "gpt-5",
            scanDirectory,
          }),
        },
        async () => ({
          events: (async function* () {
            await task(id, `${id}-owned`);
            await task(`${id}-child`, `${id}-child-owned`);
            yield { type: "turn.started" };
          })(),
        }),
        (error) => {
          throw error;
        },
      );
      generators.push(events);
    }
    await Promise.all(generators.map((events) => events.next()));
    for (const id of ["one", "two"])
      expect(await tasks(id)).toEqual([
        [id, `${id}-owned`],
        [`${id}-child`, `${id}-child-owned`],
      ]);

    await Promise.all(generators.map((events) => events.next()));
    currentNow = now + 1_000;

    for (const id of ["one", "two"]) {
      await task(id, "unrelated");
      await task(`${id}-child`, "unrelated-child");
      expect(await tasks(id)).toEqual([
        [id, `${id}-owned`],
        [`${id}-child`, `${id}-child-owned`],
      ]);
    }
    await cp(home, copy, { recursive: true });
    for (const id of ["one", "two"])
      expect(await tasks(id, copy)).toEqual(await tasks(id));
  } finally {
    clock.mockRestore();
    await settleScanLogTurns(pendingWrites);
    await rm(home, { recursive: true, force: true });
    await rm(copy, { recursive: true, force: true });
  }
});

test("log reads discover child sessions created while active attribution settles", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-log-active-child-"));
  const scanDirectory = join(home, "scan");
  const pendingWrites = new Set<Promise<void>>();
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5",
    scanDirectory,
  });
  const scanId = "scan-active-child";
  const ownerPath = join(home, "sessions", "owner.jsonl");
  try {
    await mkdir(join(home, "sessions"), { recursive: true });
    await writeFile(
      ownerPath,
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: "owner",
          cwd: scanDirectory,
          timestamp: "2026-09-16T12:00:00Z",
        },
      }) + "\n",
    );
    const events = recordScanLogTurn(
      {
        scanId,
        threadId: () => "owner",
        codexHome: home,
        pendingWrites,
        tracker,
      },
      async () => ({
        events: (async function* () {
          yield { type: "turn.started" };
        })(),
      }),
      (error) => {
        throw error;
      },
    );
    expect((await events.next()).value?.type).toBe("turn.started");

    const logTurns = spyOn(tracker, "logTurns").mockImplementation(async () => {
      const childPath = join(home, "sessions", "child.jsonl");
      await writeFile(
        childPath,
        [
          {
            type: "session_meta",
            payload: {
              id: "child",
              cwd: scanDirectory,
              timestamp: "2026-09-16T12:03:00Z",
              source: {
                subagent: { thread_spawn: { parent_thread_id: "owner" } },
              },
            },
          },
          {
            type: "event_msg",
            timestamp: "2026-09-16T12:03:00Z",
            payload: {
              type: "task_started",
              turn_id: "child-owned",
              started_at: Date.parse("2026-09-16T12:03:00Z") / 1_000,
            },
          },
          {
            type: "response_item",
            timestamp: "2026-09-16T12:03:01Z",
            payload: { type: "message", text: "owned child reply" },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );
      return [{ threadId: "child", turnId: "child-owned" }];
    });

    const logs = await readSavedScanLogs(
      {
        scanId,
        continuationThreadId: "owner",
        executionThreadIds: ["owner"],
        progress: { status: "complete", updatedAt: "2026-09-16T12:02:00Z" },
      },
      home,
    );
    expect(logs.sessions.map(({ threadId }) => threadId)).toContain("child");
    expect(JSON.stringify(logs)).toContain("owned child reply");

    logTurns.mockRestore();
    expect((await events.next()).done).toBe(true);
    await settleScanLogTurns(pendingWrites);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("turn windows include scan workers without claiming unrelated owner descendants", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-log-window-"));
  const scanDirectory = join(home, "scan");
  const sessions = join(home, "sessions");
  const start = Date.parse("2026-09-16T12:00:00Z");
  const end = start + 2_000;
  const writeSession = async (id: string, cwd: string, parent?: string) => {
    await mkdir(sessions, { recursive: true });
    await writeFile(
      join(sessions, `${id}.jsonl`),
      JSON.stringify({
        type: "session_meta",
        payload: {
          id,
          cwd,
          timestamp: new Date(start - 10_000).toISOString(),
          ...(parent === undefined
            ? {}
            : {
                source: {
                  subagent: { thread_spawn: { parent_thread_id: parent } },
                },
              }),
        },
      }) + "\n",
    );
  };
  const task = async (id: string, turnId: string, at: number) => {
    await appendFile(
      join(sessions, `${id}.jsonl`),
      JSON.stringify({
        type: "event_msg",
        timestamp: new Date(at).toISOString(),
        payload: {
          type: "task_started",
          turn_id: turnId,
          started_at: at / 1_000,
        },
      }) + "\n",
    );
  };
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5",
    scanDirectory,
  });
  try {
    await writeSession("desktop-owner", join(home, "workspace"));
    await writeSession(
      "unrelated-child",
      join(home, "workspace"),
      "desktop-owner",
    );
    await writeSession(
      "deep-worker",
      join(
        scanDirectory,
        "artifacts",
        "deep_discovery",
        "workers",
        "w1",
        "output",
      ),
    );
    await task("desktop-owner", "previous", start - 1_000);
    await task("desktop-owner", "owned-owner", start + 500);
    await task("unrelated-child", "private-child", start + 700);
    await task("deep-worker", "owned-worker", start + 900);
    await task("desktop-owner", "later", end + 1_000);

    expect(await tracker.logTurns("desktop-owner", start, end)).toEqual([
      { threadId: "desktop-owner", turnId: "owned-owner" },
      { threadId: "deep-worker", turnId: "owned-worker" },
    ]);
  } finally {
    await tracker.stop();
    await rm(home, { recursive: true, force: true });
  }
});
