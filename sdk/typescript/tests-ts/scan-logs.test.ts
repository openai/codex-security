import { writeJsonLines } from "./support/json.js";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { unlinkSync } from "node:fs";
import { join } from "node:path";
import { zstdCompressSync } from "node:zlib";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  findScanSession,
  readSavedScanLogs,
  scanRolloutSessions,
  readScanLogs,
} from "../src/scan-logs.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory: temporaryHome, cleanup } = createApiTestFixtures(
  "codex-security-scan-logs-",
);

afterEach(cleanup);

async function writeSession(
  home: string,
  threadId: string,
  events: Record<string, unknown>[],
  parentThreadId?: string,
  startedAt?: string,
  workingDirectory?: string,
): Promise<void> {
  const directory = join(home, "sessions", "2026", "08", "11");
  await mkdir(directory, { recursive: true });
  await writeJsonLines(join(directory, `rollout-${threadId}.jsonl`), [
    {
      type: "session_meta",
      payload: {
        id: threadId,
        ...(startedAt === undefined ? {} : { timestamp: startedAt }),
        ...(workingDirectory === undefined ? {} : { cwd: workingDirectory }),
        ...(parentThreadId === undefined
          ? {}
          : {
              source: {
                subagent: {
                  thread_spawn: { parent_thread_id: parentThreadId },
                },
              },
            }),
      },
    },
    ...events,
  ]);
}

function commandEvent(command: string, id: string, timestamp?: string) {
  return {
    type: "response_item",
    ...(timestamp === undefined ? {} : { timestamp }),
    payload: {
      type: "function_call",
      call_id: id,
      name: "exec_command",
      arguments: JSON.stringify({ cmd: command }),
    },
  };
}

const at = (fraction: string) => "2026-08-11T12:00:00." + fraction + "Z";
const task = (fraction: string, type: string) => ({
  timestamp: at(fraction),
  type: "event_msg",
  payload: { type, started_at: Date.parse(at(fraction)) / 1000 },
});

const user = (message: string, fraction: string) => ({
  type: "event_msg",
  timestamp: at(fraction),
  payload: { type: "user_message", message },
});
const injected = (text: string, fraction: string) => ({
  type: "response_item",
  timestamp: at(fraction),
  payload: {
    type: "message",
    role: "user",
    content: [{ type: "input_text", text }],
  },
});

describe("saved scan logs", () => {
  test("indexes execution threads and exports their finishing turns without unrelated history", async () => {
    const home = await temporaryHome();
    await writeSession(home, "desktop-owner", [], undefined, at("000"));
    await writeSession(home, "sibling", [], "desktop-owner", at("002"));
    await writeJsonLines(
      join(home, "sessions", "2026", "08", "11", "rollout-personal-fork.jsonl"),
      [
        {
          type: "session_meta",
          payload: {
            id: "personal-fork",
            forked_from_id: "root",
            timestamp: at("002"),
          },
        },
        injected("unrelated user fork", "002"),
      ],
    );
    await writeSession(home, "early", [], "root", at("000"));
    await writeSession(home, "late", [], "root", at("0035"));
    await writeSession(home, "late-grandchild", [], "late", at("0038"));
    await writeSession(
      home,
      "root",
      [
        task("000", "task_started"),
        commandEvent("earlier run", "old", at("0012")),
        task("0015", "task_started"),
        user(" SDK request ", "0015"),
        commandEvent("primary", "main"),
        commandEvent("final response", "final", at("004")),
        task("0041", "task_complete"),
        commandEvent("later unmarked event", "later", at("0042")),
        task("005", "task_started"),
        commandEvent("follow-up", "post"),
      ],
      "desktop-owner",
      at("000"),
    );
    await writeSession(
      home,
      "worker",
      [
        { type: "session_meta", payload: { id: "root" } },
        task("0018", "task_started"),
        commandEvent("inherited from root", "copied"),
        task("0022", "task_started"),
        injected("native setup", "0022"),
        user("own work", "0022"),
        commandEvent("worker event", "work"),
        injected("late steer", "0033"),
        commandEvent("private steer result", "steer"),
      ],
      "root",
      at("002"),
    );
    await writeSession(home, "grandchild", [], "worker", at("003"));
    const sessions = await scanRolloutSessions({
      rootThreadId: "root",
      rootPrompt: " SDK request ",
      codexHome: home,
      startedAt: at("001"),
      completedAt: at("0035"),
    });
    expect(sessions.map((s) => [s.threadId, s.parentThreadId])).toEqual([
      ["root", null],
      ["worker", "root"],
      ["grandchild", "worker"],
    ]);
    const outputs = await Promise.all(
      sessions.map(async (session) => {
        const calls = [];
        for await (const event of session.events()) {
          if (event["type"] === "response_item") calls.push(event["payload"]);
        }
        return calls.map((payload) => (payload as { call_id: string }).call_id);
      }),
    );
    expect(outputs).toEqual([["main", "final"], ["work"], []]);
  });

  test("isolates the submitted turn on a reused coordinator when native clock ticks collide", async () => {
    const home = await temporaryHome();
    await writeSession(
      home,
      "root",
      [
        task("000", "task_started"),
        user("historical", "000"),
        commandEvent("old", "old"),
        task("001", "task_started"),
        user("concurrent", "001"),
        commandEvent("outside", "outside"),
        task("001", "task_started"),
        injected("scan", "001"),
        user("scan", "001"),
        commandEvent("inside", "inside"),
        task("003", "task_complete"),
        user("orphan", "003"),
        commandEvent("outside", "orphan", "2026-08-11T12:00:00.003Z"),
        task("003", "task_started"),
        user("unrelated", "003"),
        commandEvent("outside", "late"),
        task("004", "task_started"),
        user("follow-up", "004"),
        commandEvent("outside", "post"),
      ],
      undefined,
      at("000"),
    );
    for (const [id, created] of [
      ["at-start", "001"],
      ["good", "002"],
      ["at-finish", "003"],
    ] as const)
      await writeSession(
        home,
        id,
        [task("0025", "task_started"), commandEvent("child event", id)],
        "root",
        at(created),
      );
    const sessions = await scanRolloutSessions({
      codexHome: home,
      rootThreadId: "root",
      rootPrompt: "scan",
      startedAt: at("001"),
      completedAt: at("004"),
    });
    const calls = [];
    for (const session of sessions)
      for await (const event of session.events()) {
        const id = (event["payload"] as Record<string, unknown>)["call_id"];
        if (id) calls.push(id);
      }
    expect(calls).toEqual(["inside", "good"]);
  });

  test("retains only the exact injected context without turn markers and withholds ambiguous inputs", async () => {
    const home = await temporaryHome();
    await writeSession(
      home,
      "injected",
      [
        injected("private", "001"),
        injected("scan", "002"),
        commandEvent("unmarked", "private", at("003")),
        injected("post", "004"),
      ],
      undefined,
      at("000"),
    );
    await writeSession(
      home,
      "ambiguous",
      [
        task("001", "task_started"),
        user("scan", "001"),
        commandEvent("ambiguous", "private"),
        task("002", "task_started"),
        user("scan", "002"),
        commandEvent("ambiguous", "private2"),
      ],
      undefined,
      at("000"),
    );
    for (const rootThreadId of ["injected", "ambiguous"]) {
      const [session] = await scanRolloutSessions({
        codexHome: home,
        rootThreadId,
        rootPrompt: "scan",
        startedAt: at("001"),
        completedAt: at("004"),
      });
      const output = [];
      for await (const event of session!.events()) output.push(event);
      expect(output).toEqual(
        rootThreadId === "injected" ? [injected("scan", "002")] : [],
      );
    }
  });

  test("retains standalone Deep comparisons only for receipts belonging to this invocation", async () => {
    const home = await temporaryHome();
    const directory = join(home, "worker-usage", "scan");
    await mkdir(directory, { recursive: true });
    for (const [id, scanId, startedAt] of [
      ["comparison", "scan", at("002")],
      ["wrong-scan", "other", at("002")],
      ["previous", "scan", at("000")],
      ["post-scan", "scan", at("009")],
    ] as const) {
      await writeFile(
        join(directory, id + ".json"),
        JSON.stringify({
          schemaVersion: 1,
          source: "codex_sdk",
          usageScope: "thread_cumulative",
          kind: "compare",
          scanId,
          attemptId: id,
          threadId: id,
          startedAt,
        }),
      );
    }
    for (const id of [
      "comparison",
      "wrong-scan",
      "previous",
      "post-scan",
      "unrelated",
    ]) {
      await writeSession(
        home,
        id,
        [
          task("003", "task_started"),
          commandEvent("native result", id, at("004")),
          task("005", "task_complete"),
          task("009", "task_started"),
          commandEvent("later work", "later", at("010")),
        ],
        undefined,
        at("002"),
        join(home, "scan", "artifacts", "deep_discovery"),
      );
    }
    const sessions = await scanRolloutSessions({
      codexHome: home,
      rootThreadId: "coordinator",
      workerReceipts: { directory, scanId: "scan" },
      startedAt: at("001"),
      completedAt: at("009"),
    });
    expect(sessions.map(({ threadId }) => threadId)).toEqual(["comparison"]);
    const calls = [];
    for await (const event of sessions[0]!.events()) {
      if (event["type"] === "response_item") calls.push(event["payload"]);
    }
    expect(calls).toEqual([
      commandEvent("native result", "comparison")["payload"],
    ]);
  });

  test.each([
    ["both", ["failed-attempt", "first-child", "retry", "retry-child"]],
    ["retry only", ["retry", "retry-child"]],
    ["neither", []],
    ["neither with only the manual turn retained", []],
  ] as const)(
    "exports only proven turns in a retried discovery session (receipt IDs for %s)",
    async (receiptIds, expected) => {
      const home = await temporaryHome();
      const directory = join(home, "worker-usage", "scan");
      await mkdir(directory, { recursive: true });
      for (const [turnId, startedAt, scanId] of [
        ["failed-attempt", at("001"), "scan"],
        ["retry", at("005"), "scan"],
        ["manual", at("003"), "other-scan"],
      ] as const) {
        await writeFile(
          join(directory, turnId + ".json"),
          JSON.stringify({
            schemaVersion: 1,
            source: "codex_sdk",
            usageScope: "thread_cumulative",
            kind: "discovery",
            scanId,
            attemptId: turnId,
            threadId: "worker",
            ...((receiptIds === "both" ||
              (receiptIds === "retry only" && turnId === "retry")) && {
              turnId,
            }),
            outcome: turnId === "failed-attempt" ? "failed" : "succeeded",
            startedAt,
          }),
        );
      }
      const events = [];
      for (const [turnId, start, end] of [
        ["failed-attempt", "001", "003"],
        ["manual", "003", "005"],
        ["retry", "005", "009"],
      ] as const) {
        if (
          receiptIds === "neither with only the manual turn retained" &&
          turnId !== "manual"
        )
          continue;
        const started = task(start, "task_started");
        events.push(
          { ...started, payload: { ...started.payload, turn_id: turnId } },
          commandEvent("result", turnId, at(start)),
          task(
            end,
            turnId === "failed-attempt" ? "turn_aborted" : "task_complete",
          ),
        );
      }
      await writeSession(home, "worker", events, undefined, at("001"));
      for (const [id, start] of [
        ["first-child", "002"],
        ["manual-child", "004"],
        ["retry-child", "006"],
      ] as const) {
        await writeSession(
          home,
          id,
          [task(start, "task_started"), commandEvent("result", id, at(start))],
          "worker",
          at(start),
        );
      }
      const sessions = await scanRolloutSessions({
        codexHome: home,
        rootThreadId: "coordinator",
        executionThreadIds: ["worker"],
        workerReceipts: { directory, scanId: "scan" },
        startedAt: at("001"),
        completedAt: at("010"),
      });
      expect(sessions.map(({ threadId }) => threadId)).toContain("worker");
      const ids = [];
      for (const session of sessions) {
        for await (const event of session.events()) {
          if (event["type"] === "response_item")
            ids.push((event["payload"] as Record<string, unknown>)["call_id"]);
        }
      }
      expect(ids.sort()).toEqual([...expected]);
    },
  );

  test("keeps registered worker lineages when the execution root rollout is missing", async () => {
    const home = await temporaryHome();
    const startedAt = "2026-08-11T12:00:00Z",
      completedAt = "2026-08-11T12:03:00Z";
    await writeSession(home, "worker", [], undefined, startedAt);
    await writeSession(home, "child", [], "worker", startedAt);
    await writeSession(home, "other", [], undefined, startedAt);
    const sessions = await scanRolloutSessions({
      rootThreadId: "missing",
      executionThreadIds: ["worker"],
      codexHome: home,
      startedAt,
      completedAt,
    });
    expect(sessions.map((s) => s.threadId)).toEqual(["worker", "child"]);
  });

  test.each([
    ["prefix first", [0], [0, 1, 1, 2], 1, false, false],
    ["complete first", [0, 1, 1, 2], [0], 0, false, false],
    ["identical copies", [0, 1, 1, 2], [0, 1, 1, 2], 0, false, false],
    ["longer divergent copy", [0, 2], [0, 1, 1, 2], 0, false, false],
    ["shorter divergent copy", [0, 1, 1, 2], [0, 2], 0, false, false],
    ["equal-length divergent copy", [0, 1], [0, 2], 0, false, false],
    ["complete archived copy", [0], [0, 1, 1, 2], 1, true, false],
    ["prefix archived copy", [0, 1, 1, 2], [0], 0, true, false],
    ["identical archived copy", [0, 1, 1, 2], [0, 1, 1, 2], 0, true, false],
    ["divergent archived copy", [0, 2], [0, 1, 1, 2], 0, true, false],
    ["complete compressed copy", [0], [0, 1, 1, 2], 1, false, true],
    ["prefix compressed copy", [0, 1, 1, 2], [0], 0, false, true],
    ["identical compressed copy", [0, 1, 1, 2], [0, 1, 1, 2], 0, false, true],
    ["divergent compressed copy", [0, 2], [0, 1, 1, 2], 0, false, true],
    ["complete compressed archived copy", [0], [0, 1, 1, 2], 1, true, true],
  ] as const)(
    "retains complete copied rollout events and precedence: %s",
    async (_label, first, second, selected, archived, compressed) => {
      const homes = [await temporaryHome(), await temporaryHome()];
      const activity = [
        commandEvent("first", "first-call", "2026-08-11T12:00:03Z"),
        commandEvent("repeated", "repeat-call", "2026-08-11T12:00:01Z"),
        commandEvent("last", "last-call", "2026-08-11T12:00:02Z"),
      ];
      const copies = [first, second];
      for (const [index, home] of homes.entries()) {
        await writeSession(home, "parent", []);
        await writeSession(
          home,
          "worker",
          copies[index]!.map((event) => activity[event]!),
          "parent",
        );
      }
      if (compressed) {
        const path = join(
          homes[1]!,
          "sessions",
          "2026",
          "08",
          "11",
          "rollout-worker.jsonl",
        );
        await writeFile(`${path}.zst`, zstdCompressSync(await readFile(path)));
        unlinkSync(path);
      }
      if (archived) {
        await rename(
          join(homes[1]!, "sessions"),
          join(homes[1]!, "archived_sessions"),
        );
      }
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          continuationThreadId: "parent",
          executionThreadIds: ["parent"],
        },
        archived ? [...homes].reverse() : homes,
      );
      expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
        "parent",
        "worker",
      ]);
      expect(result.sessions[1]!.path).toBe(
        join(
          homes[selected]!,
          archived && selected === 1 ? "archived_sessions" : "sessions",
          "2026",
          "08",
          "11",
          `rollout-worker.jsonl${compressed && selected === 1 ? ".zst" : ""}`,
        ),
      );
      expect(
        result.events
          .filter(({ threadId }) => threadId === "worker")
          .slice(1)
          .map(({ event }) => event),
      ).toEqual(copies[selected]!.map((event) => activity[event]!));
    },
  );

  test("keeps first-copy ownership when a longer copy has different session metadata", async () => {
    const first = await temporaryHome();
    const second = await temporaryHome();
    const event = commandEvent("scan work", "scan-call");
    await writeSession(first, "parent", []);
    await writeSession(first, "worker", [event], "unrelated");
    await writeSession(second, "worker", [event, event], "parent");
    const result = await readSavedScanLogs(
      {
        scanId: "scan-1",
        continuationThreadId: "parent",
        executionThreadIds: ["parent"],
      },
      [first, second],
    );
    expect(result.sessions.map(({ threadId }) => threadId)).toEqual(["parent"]);
  });

  test.each([false, true])(
    "collects parentless comparisons inside a shared Desktop scan window (archived: %p)",
    async (archived) => {
      const home = await temporaryHome();
      const scanDir = join(home, "scan");
      const cwd = join(scanDir, "artifacts", "deep_discovery");
      await writeSession(home, "owner", [], undefined, "2026-08-01T00:00:00Z");
      await writeSession(home, "other-task", [], "owner");
      await writeSession(
        home,
        "worker",
        [],
        undefined,
        "2026-08-02T00:30:00Z",
        join(cwd, "workers", "discovery-0001", "output"),
      );
      await writeSession(
        home,
        "replacement-comparison",
        [],
        undefined,
        "2026-08-02T02:00:00Z",
        cwd,
      );
      await writeSession(
        home,
        "older-comparison",
        [],
        undefined,
        "2026-08-01T01:00:00Z",
        cwd,
      );
      await writeSession(
        home,
        "comparison",
        [],
        undefined,
        "2026-08-02T01:00:00Z",
        cwd,
      );
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          scanDir: archived ? scanDir + ".previous-test" : scanDir,
          mode: "deep",
          continuationThreadId: "owner",
          lifecycle: {
            startedAt: "2026-08-02T00:00:00Z",
            finishedAt: "2026-08-02T02:00:00Z",
          },
          progress: { status: "complete", updatedAt: "2026-08-03T00:00:00Z" },
          executionThreadIds: ["worker"],
        },
        home,
      );
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
        "comparison",
        "owner",
        "worker",
      ]);
    },
  );

  test("collects known desktop and CLI threads across active and archived homes without duplicates", async () => {
    const desktop = await temporaryHome();
    const cli = await temporaryHome();
    await writeSession(desktop, "desktop-owner", [
      commandEvent("desktop scan", "owner-call"),
    ]);
    await writeSession(desktop, "worker", [
      commandEvent("stale archived copy", "stale-call"),
    ]);
    await writeSession(
      desktop,
      "worker-child",
      [commandEvent("archived child", "child-call")],
      "worker",
    );
    await writeSession(desktop, "unrelated", [
      commandEvent("unrelated archived scan", "unrelated-call"),
    ]);
    await rename(join(desktop, "sessions"), join(desktop, "archived_sessions"));
    await writeSession(cli, "worker", [
      commandEvent("active worker", "worker-call"),
    ]);
    await writeSession(cli, "owner-child", [], "desktop-owner");
    await writeSession(cli, "other-scan", [
      commandEvent("unrelated CLI scan", "other-call"),
    ]);

    const result = await readSavedScanLogs(
      {
        scanId: "scan-1",
        threadIds: ["desktop-owner", "worker", "worker"],
        executionThreadIds: ["worker"],
      },
      [desktop, cli, desktop],
      { allowMissingRoot: true },
    );

    expect(result.threadId).toBe("desktop-owner");
    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "desktop-owner",
      "worker",
      "worker-child",
    ]);
    expect(
      result.events.filter(({ threadId }) => threadId === "worker"),
    ).toHaveLength(2);
    expect(JSON.stringify(result)).toContain("desktop scan");
    expect(JSON.stringify(result)).toContain("active worker");
    expect(JSON.stringify(result)).toContain("archived child");
    expect(JSON.stringify(result)).not.toContain("stale archived copy");
    expect(JSON.stringify(result)).not.toContain("unrelated");
  });

  test.each([
    ["omitted", undefined],
    ["recorded", "missing-owner"],
  ] as const)(
    "feedback collects known worker descendants without the owner log with %s continuation",
    async (_label, continuationThreadId) => {
      const home = await temporaryHome();
      await writeSession(home, "owner-child", [], "missing-owner");
      await writeSession(home, "worker", [
        commandEvent("independent worker", "worker-call"),
      ]);
      await writeSession(home, "worker-child", [], "worker");
      await writeSession(home, "unrelated-child", [], "another-owner");
      const scan = {
        scanId: "scan-1",
        ...(continuationThreadId === undefined ? {} : { continuationThreadId }),
        threadIds: ["missing-owner", "worker"],
        executionThreadIds: ["worker"],
      };

      const result = await readSavedScanLogs(scan, home, {
        allowMissingRoot: true,
      });
      expect(result.threadId).toBe("missing-owner");
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
        "worker",
        "worker-child",
      ]);
      if (continuationThreadId === undefined) {
        expect(() => readSavedScanLogs(scan, home)).toThrow(
          "No session is associated with scan scan-1.",
        );
      } else {
        await expect(readSavedScanLogs(scan, home)).rejects.toThrow(
          "No saved session logs are available for scan scan-1.",
        );
      }
    },
  );

  test("feedback returns an empty log set when no scan threads are recorded", async () => {
    const home = await temporaryHome();
    await writeSession(home, "unrelated", []);
    expect(
      await readSavedScanLogs({ scanId: "scan-1" }, home, {
        allowMissingRoot: true,
      }),
    ).toEqual({
      scanId: "scan-1",
      threadId: null,
      sessions: [],
      events: [],
    });
  });

  test("keeps worker events when the parent rollout disappears after discovery", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", []);
    await writeSession(
      home,
      "worker",
      [commandEvent("available worker", "worker-call")],
      "parent",
    );
    const parentPath = join(
      home,
      "sessions",
      "2026",
      "08",
      "11",
      "rollout-parent.jsonl",
    );
    const originalParse = JSON.parse;
    let removed = false;
    const parseSpy = spyOn(JSON, "parse").mockImplementation(
      (text, reviver) => {
        const parsed = originalParse(text, reviver);
        if (!removed && parsed?.payload?.id === "parent") {
          unlinkSync(parentPath);
          removed = true;
        }
        return parsed;
      },
    );
    try {
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          continuationThreadId: "parent",
          executionThreadIds: ["parent"],
        },
        home,
        { allowMissingRoot: true },
      );
      expect(removed).toBe(true);
      expect(result.events.map(({ threadId }) => threadId)).toEqual([
        "worker",
        "worker",
      ]);
    } finally {
      parseSpy.mockRestore();
    }
  });

  test("returns complete parent and worker events without unrelated sessions", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      commandEvent(
        "OPENAI_API_KEY=sk-proj-SYNTHETIC_KEY_123 rg authorization /repo/src/auth.ts",
        "call-parent",
        "2026-08-11T12:00:00.000Z",
      ),
    ]);
    await writeSession(
      home,
      "worker",
      [
        commandEvent(
          "python3 -m pytest /repo/tests",
          "call-worker",
          "2026-08-11T12:00:01.000Z",
        ),
        {
          type: "response_item",
          payload: {
            type: "function_call_output",
            call_id: "call-worker",
            status: "failed",
            output: "private command output",
          },
        },
      ],
      "parent",
    );
    await writeSession(home, "unrelated", [
      {
        type: "event_msg",
        payload: { type: "agent_message", message: "private unrelated scan" },
      },
    ]);

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });

    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "parent",
      "worker",
    ]);
    expect(result.events.map(({ threadId }) => threadId)).toEqual([
      "parent",
      "parent",
      "worker",
      "worker",
      "worker",
    ]);
    expect(result.events.at(-1)).toMatchObject({
      threadId: "worker",
      event: {
        type: "response_item",
        payload: { status: "failed", output: "private command output" },
      },
    });
    expect(JSON.stringify(result)).toContain("SYNTHETIC_KEY");
    expect(JSON.stringify(result)).toContain("private command output");
    expect(JSON.stringify(result)).not.toContain("private unrelated scan");
  });

  test("reads sessions that Codex compressed", async () => {
    const home = await temporaryHome();
    await writeSession(
      home,
      "parent",
      [commandEvent("parent work", "parent-call")],
      undefined,
      undefined,
      "/scan",
    );
    await writeSession(
      home,
      "worker",
      [commandEvent("worker work", "worker-call")],
      "parent",
    );
    const directory = join(home, "sessions", "2026", "08", "11");
    for (const threadId of ["parent", "worker"]) {
      const path = join(directory, `rollout-${threadId}.jsonl`);
      await writeFile(`${path}.zst`, zstdCompressSync(await readFile(path)));
      unlinkSync(path);
    }

    expect(await findScanSession(home, "parent")).toMatchObject({
      workingDirectory: "/scan",
      path: join(directory, "rollout-parent.jsonl.zst"),
    });
    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });
    expect(result.events).toEqual([
      expect.objectContaining({ threadId: "parent" }),
      {
        threadId: "parent",
        event: commandEvent("parent work", "parent-call"),
      },
      expect.objectContaining({ threadId: "worker" }),
      {
        threadId: "worker",
        event: commandEvent("worker work", "worker-call"),
      },
    ]);
  });

  test("excludes inherited parent history from worker logs", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", []);
    const startedAt = "2026-08-11T12:02:00.900Z";
    await writeSession(
      home,
      "worker",
      [
        {
          type: "session_meta",
          payload: { id: "parent", timestamp: "2026-08-11T12:00:00.000Z" },
        },
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            started_at: Date.parse("2026-08-11T12:00:00.000Z") / 1_000,
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "PRIVATE PRE-SCAN CONVERSATION",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            started_at: Math.floor(Date.parse(startedAt) / 1_000),
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "Reviewing authorization",
          },
        },
      ],
      "parent",
      startedAt,
    );

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });
    expect(JSON.stringify(result)).toContain("Reviewing authorization");
    expect(JSON.stringify(result)).not.toContain("PRIVATE PRE-SCAN");
  });

  test("includes independent Deep workers without crossing scan boundaries", async () => {
    const home = await temporaryHome();
    const scanDirectory = join(home, "scans", "current");
    const artifacts = join(scanDirectory, "artifacts");
    await writeSession(
      home,
      "parent",
      [],
      undefined,
      "2026-08-11T12:00:00.900Z",
      scanDirectory,
    );
    const workerDirectory = join(
      artifacts,
      "deep_discovery",
      "workers",
      "worker-1",
      "output",
    );
    await writeSession(
      home,
      "worker",
      [commandEvent("review current worker", "worker-call")],
      undefined,
      "2026-08-11T12:00:00.950Z",
      process.platform === "win32"
        ? workerDirectory.toUpperCase()
        : workerDirectory,
    );
    await writeSession(
      home,
      "reducer",
      [commandEvent("reduce current findings", "reducer-call")],
      undefined,
      "2026-08-11T12:02:00.000Z",
      process.platform === "win32" ? artifacts.toUpperCase() : artifacts,
    );
    await writeSession(home, "worker-child", [], "worker");
    for (const [threadId, directory, startedAt] of [
      [
        "stale-worker",
        join(artifacts, "deep_discovery", "workers", "stale", "output"),
        "2026-08-11T11:59:00.000Z",
      ],
      ["same-second-previous-scan", artifacts, "2026-08-11T12:00:00.100Z"],
      ["completion-instant", artifacts, "2026-08-11T12:02:00.001Z"],
      ["after-completion", artifacts, "2026-08-11T12:02:00.002Z"],
      [
        "invalid-start",
        join(artifacts, "deep_discovery", "workers", "invalid", "output"),
        "not-a-timestamp",
      ],
      [
        "sibling-directory",
        join(artifacts, "deep_discovery", "output"),
        "2026-08-11T12:01:00.000Z",
      ],
      [
        "nested-scan",
        join(scanDirectory, "nested", "artifacts"),
        "2026-08-11T12:01:00.000Z",
      ],
    ] as const) {
      await writeSession(
        home,
        threadId,
        [commandEvent(`exclude ${threadId}`, `${threadId}-call`)],
        undefined,
        startedAt,
        directory,
      );
    }
    await writeSession(
      home,
      "unknown-start",
      [commandEvent("exclude unknown-start", "unknown-call")],
      undefined,
      undefined,
      join(artifacts, "deep_discovery", "workers", "unknown", "output"),
    );

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
      scanDirectory,
      completedAt: "2026-08-11T12:02:00.001Z",
    });

    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "parent",
      "reducer",
      "worker",
      "worker-child",
    ]);
    expect(JSON.stringify(result)).toContain("review current worker");
    expect(JSON.stringify(result)).toContain("reduce current findings");
    expect(JSON.stringify(result)).not.toContain("exclude ");
  });

  test("keeps archived Deep workers without exposing later replacement sessions", async () => {
    const home = await temporaryHome();
    const original = join(home, "scans", "results");
    const archived = `${original}.previous-20260811T120300-a1b2c3d4`;
    const completedAt = "2026-08-11T12:02:00.000Z";
    await writeSession(
      home,
      "archived-parent",
      [],
      undefined,
      "2026-08-11T12:00:00.000Z",
      original,
    );
    await writeSession(
      home,
      "archived-worker",
      [commandEvent("review archived scan", "archived-call")],
      undefined,
      "2026-08-11T12:01:00.000Z",
      join(original, "artifacts", "deep_discovery", "workers", "old", "output"),
    );
    await writeSession(
      home,
      "replacement-worker",
      [commandEvent("PRIVATE REPLACEMENT SCAN", "replacement-call")],
      undefined,
      "2026-08-11T12:03:00.000Z",
      join(original, "artifacts"),
    );

    const options = {
      scanId: "archived-scan",
      threadId: "archived-parent",
      codexHome: home,
      scanDirectory: archived,
      completedAt,
    };
    const archivedLogs = await readScanLogs(options);
    expect(archivedLogs.sessions.map(({ threadId }) => threadId)).toEqual([
      "archived-parent",
      "archived-worker",
    ]);
    expect(JSON.stringify(archivedLogs)).toContain("review archived scan");
    expect(JSON.stringify(archivedLogs)).not.toContain("PRIVATE REPLACEMENT");

    const unrelatedRoot = await readScanLogs({
      ...options,
      scanDirectory: join(home, "scans", "unrelated.previous-fixture"),
    });
    expect(unrelatedRoot.sessions.map(({ threadId }) => threadId)).toEqual([
      "archived-parent",
    ]);

    const malformedCompletion = await readScanLogs({
      ...options,
      completedAt: "invalid-timestamp",
    });
    expect(
      malformedCompletion.sessions.map(({ threadId }) => threadId),
    ).toEqual(["archived-parent"]);

    const runningLogs = await readScanLogs({ ...options, completedAt: null });
    expect(runningLogs.sessions.map(({ threadId }) => threadId).sort()).toEqual(
      ["archived-parent", "archived-worker", "replacement-worker"],
    );
  });

  test.each([false, true])(
    "does not parse event bodies from unrelated saved sessions (copied: %p)",
    async (copied) => {
      const home = await temporaryHome();
      await writeSession(home, "parent", [
        commandEvent("included", "parent-call"),
      ]);
      const unrelated = commandEvent(
        "UNRELATED_PRIVATE_EVENT_BODY",
        "unrelated-call",
      );
      await writeSession(home, "unrelated", [unrelated]);
      const homes = [home];
      if (copied) {
        const copyHome = await temporaryHome();
        await writeSession(copyHome, "unrelated", [unrelated, unrelated]);
        await writeSession(copyHome, "parent", [
          commandEvent("included", "parent-call"),
        ]);
        homes.push(copyHome);
      }
      const originalParse = JSON.parse;
      let unrelatedBodies = 0;
      let includedBodies = 0;
      const parseSpy = spyOn(JSON, "parse").mockImplementation(
        (text, reviver) => {
          if (text.includes("UNRELATED_PRIVATE_EVENT_BODY")) unrelatedBodies++;
          if (text.includes("parent-call")) includedBodies++;
          return originalParse(text, reviver);
        },
      );

      try {
        const index = await scanRolloutSessions({
          rootThreadId: "parent",
          codexHome: homes,
          startedAt: "2026-08-11T12:00:00Z",
          completedAt: "2026-08-11T12:03:00Z",
        });
        expect(index.map((session) => session.threadId)).toEqual(["parent"]);
        expect(includedBodies).toBe(0);
        const result = await readScanLogs({
          scanId: "scan-1",
          threadId: "parent",
          codexHome: homes,
        });
        expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
          "parent",
        ]);
        expect(unrelatedBodies).toBe(0);
      } finally {
        parseSpy.mockRestore();
      }
    },
  );

  test("preserves large selected events and skips malformed metadata prefixes", async () => {
    const home = await temporaryHome();
    const output = "x".repeat(2 * 1024 * 1024 + 1);
    await writeSession(home, "parent", [
      { type: "response_item", payload: { output } },
    ]);
    const path = join(
      home,
      "sessions",
      "2026",
      "08",
      "11",
      "rollout-parent.jsonl",
    );
    await writeFile(path, `not json\n42\n${await readFile(path, "utf8")}`);

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });

    expect(result.events.at(-1)?.["event"]).toMatchObject({
      payload: { output },
    });
  });

  test("reports when the saved scan session is missing", async () => {
    const home = await temporaryHome();
    await expect(
      readScanLogs({
        scanId: "scan-1",
        threadId: "missing",
        codexHome: home,
      }),
    ).rejects.toThrow("No saved session logs are available for scan scan-1.");
  });
});
