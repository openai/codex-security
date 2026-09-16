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
                payload: { type: "task_started", turn_id: `turn-${cancel}` },
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
  const clock = spyOn(Date, "now").mockImplementation(() => now);
  const session = async (id: string, parent?: string) => {
    await mkdir(join(home, "sessions"), { recursive: true });
    await writeFile(
      join(home, "sessions", `${id}.jsonl`),
      JSON.stringify({
        type: "session_meta",
        payload: {
          id,
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
          timestamp: new Date(now).toISOString(),
          payload: { type: "task_started", turn_id: turnId },
        },
        {
          type: "response_item",
          timestamp: new Date(now).toISOString(),
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
      await session(id);
      await session(`${id}-child`, id);
      const events = recordScanLogTurn(
        {
          scanId: id,
          threadId: () => id,
          codexHome: home,
          pendingWrites,
          tracker: new ScanCostTracker({ codexHome: home, model: "gpt-5" }),
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

test("captured byte ranges select native tasks after the shared reader advances", async () => {
  const home = await mkdtemp(join(tmpdir(), "scan-log-cursor-"));
  const tracker = new ScanCostTracker({ codexHome: home, model: "gpt-5" });
  const path = join(home, "sessions", "root.jsonl");
  const task = (turnId: string) =>
    JSON.stringify({
      type: "event_msg",
      payload: { type: "task_started", turn_id: turnId },
    }) + "\n";
  try {
    await mkdir(join(home, "sessions"));
    await writeFile(
      path,
      JSON.stringify({ type: "session_meta", payload: { id: "root" } }) +
        "\n" +
        task("previous"),
    );
    const before = await tracker.sessionOffsets();
    // Exercise byte offsets across UTF-8 and the reader's chunk/partial-line boundary.
    await appendFile(
      path,
      JSON.stringify({
        type: "response_item",
        payload: { text: "é".repeat(40_000) },
      }) +
        "\n" +
        task("owned"),
    );
    const after = await tracker.sessionOffsets();
    await appendFile(path, task("later"));
    tracker.start("root");
    await tracker.refresh();
    expect(await tracker.logTurns("root", before, after)).toEqual([
      { threadId: "root", turnId: "owned" },
    ]);
  } finally {
    await tracker.stop();
    await rm(home, { recursive: true, force: true });
  }
});
