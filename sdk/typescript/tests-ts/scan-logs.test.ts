import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { readScanLogs } from "../src/scan-logs.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

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
  await writeFile(
    join(directory, `rollout-${threadId}.jsonl`),
    [
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
    ]
      .map((event) => JSON.stringify(event))
      .join("\n"),
  );
}

async function temporaryHome(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scan-logs-")),
  );
  directories.push(directory);
  return directory;
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

describe("saved scan logs", () => {
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

  test("does not parse event bodies from unrelated saved sessions", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      commandEvent("included", "parent-call"),
    ]);
    await writeSession(home, "unrelated", [
      commandEvent("UNRELATED_PRIVATE_EVENT_BODY", "unrelated-call"),
    ]);
    const originalParse = JSON.parse;
    let unrelatedBodies = 0;
    const parseSpy = spyOn(JSON, "parse").mockImplementation(
      (text, reviver) => {
        if (text.includes("UNRELATED_PRIVATE_EVENT_BODY")) unrelatedBodies++;
        return originalParse(text, reviver);
      },
    );

    try {
      const result = await readScanLogs({
        scanId: "scan-1",
        threadId: "parent",
        codexHome: home,
      });
      expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
        "parent",
      ]);
      expect(unrelatedBodies).toBe(0);
    } finally {
      parseSpy.mockRestore();
    }
  });

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
