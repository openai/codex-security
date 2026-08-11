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

describe("saved scan logs", () => {
  test("includes parent and worker activity but excludes unrelated sessions", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      {
        type: "response_item",
        timestamp: "2026-08-11T12:00:00.000Z",
        payload: {
          type: "function_call",
          call_id: "call-parent",
          name: "exec_command",
          arguments: JSON.stringify({
            cmd: "rg authorization /repo/src/auth.ts",
          }),
        },
      },
    ]);
    await writeSession(
      home,
      "worker",
      [
        {
          type: "response_item",
          timestamp: "2026-08-11T12:00:01.000Z",
          payload: {
            type: "function_call",
            call_id: "call-worker",
            name: "exec_command",
            arguments: JSON.stringify({ cmd: "python3 -m pytest /repo/tests" }),
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
      repository: "/repo",
      codexHome: home,
    });

    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "parent",
      "worker",
    ]);
    expect(result.events).toEqual([
      {
        threadId: "parent",
        timestamp: "2026-08-11T12:00:00.000Z",
        kind: "command",
        status: "running",
        description: "rg authorization /repo/src/auth.ts",
        paths: ["src/auth.ts"],
      },
      {
        threadId: "worker",
        timestamp: "2026-08-11T12:00:01.000Z",
        kind: "command",
        status: "running",
        description: "python3 -m pytest /repo/tests",
        paths: ["tests"],
      },
    ]);
    expect(JSON.stringify(result)).not.toContain("private unrelated scan");
  });

  test("redacts credentials unless raw events are explicitly requested", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      {
        type: "response_item",
        payload: {
          type: "function_call",
          call_id: "call-1",
          name: "exec_command",
          arguments: JSON.stringify({
            cmd: "OPENAI_API_KEY=sk-proj-SYNTHETIC_KEY_123 cat /repo/config/AWS_SECRET_ACCESS_KEY=SYNTHETIC_VALUE",
          }),
        },
      },
    ]);

    const options = {
      scanId: "scan-1",
      threadId: "parent",
      repository: "/repo",
      codexHome: home,
    };
    const redacted = await readScanLogs(options);
    expect(redacted.events[0]?.["description"]).toBe(
      "OPENAI_API_KEY=[redacted] cat /repo/config/AWS_SECRET_ACCESS_KEY=[redacted]",
    );
    expect(redacted.events[0]?.["paths"]).toEqual([
      "config/AWS_SECRET_ACCESS_KEY=[redacted]",
    ]);
    expect(JSON.stringify(redacted)).not.toContain("SYNTHETIC_KEY");
    expect(JSON.stringify(redacted)).not.toContain("SYNTHETIC_VALUE");

    const raw = await readScanLogs({ ...options, raw: true });
    expect(JSON.stringify(raw)).toContain("sk-proj-SYNTHETIC_KEY_123");
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

    for (const raw of [false, true]) {
      const result = await readScanLogs({
        scanId: "scan-1",
        threadId: "parent",
        repository: "/repo",
        codexHome: home,
        raw,
      });
      expect(JSON.stringify(result)).toContain("Reviewing authorization");
      expect(JSON.stringify(result)).not.toContain("PRIVATE PRE-SCAN");
    }
  });

  test("records completed and failed tool calls", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      {
        type: "response_item",
        payload: {
          type: "function_call",
          call_id: "call-1",
          name: "exec_command",
          arguments: JSON.stringify({ cmd: "pytest /repo/tests" }),
        },
      },
      {
        type: "response_item",
        payload: {
          type: "function_call_output",
          call_id: "call-1",
          status: "failed",
          output: "private command output",
        },
      },
    ]);

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      repository: "/repo",
      codexHome: home,
    });
    expect(result.events.map((event) => event["status"])).toEqual([
      "running",
      "failed",
    ]);
    expect(JSON.stringify(result)).not.toContain("private command output");
  });

  test("reports when the saved scan session is missing", async () => {
    const home = await temporaryHome();
    await expect(
      readScanLogs({
        scanId: "scan-1",
        threadId: "missing",
        repository: "/repo",
        codexHome: home,
      }),
    ).rejects.toThrow("No saved session logs are available for scan scan-1.");
  });
});
