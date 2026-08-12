import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
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
    const startedAt = "2026-08-11T12:02:00.000Z";
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
            started_at: Date.parse(startedAt) / 1_000,
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
