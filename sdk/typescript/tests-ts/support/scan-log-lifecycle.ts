import { spawn } from "node:child_process";
import { readFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { expect } from "bun:test";
import { readSavedScanLogs, type ScanLogSource } from "../../src/scan-logs.js";
import { sendFeedback } from "../../src/feedback.js";

const childFixture = fileURLToPath(
  new URL("../fixtures/scan-log-turn.mjs", import.meta.url),
);
const feedbackFixture = fileURLToPath(
  new URL("../fixtures/feedback.mjs", import.meta.url),
);

export function savedLogTurn(
  input: {
    environment: NodeJS.ProcessEnv;
    threadId: string;
    turnId: string;
    outcome: "completed" | "failed";
    draft?: boolean;
    delegate?: boolean;
  },
  onThreadStarted?: (threadId: string) => void,
) {
  return {
    events: (async function* () {
      const child = spawn(process.execPath, [childFixture], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      const exited = new Promise<number | null>((resolve) =>
        child.once("close", resolve),
      );
      let stderr = "";
      child.stderr.setEncoding("utf8").on("data", (data) => {
        stderr += data;
      });
      child.stdin.end(JSON.stringify(input));
      for await (const line of createInterface({ input: child.stdout })) {
        const event = JSON.parse(line) as {
          type: string;
          [key: string]: unknown;
        };
        if (event.type === "thread.started")
          onThreadStarted?.(event["thread_id"] as string);
        yield event;
      }
      expect(await exited, stderr).toBe(0);
    })(),
  };
}

export async function checkSavedProjection(
  scan: ScanLogSource,
  environment: NodeJS.ProcessEnv,
  root: string,
  threadId: string,
  turnIds: string[],
  delegated = false,
) {
  const home = environment["CODEX_HOME"]!;
  const cutoff = Date.parse(scan.progress!.updatedAt!);
  const threads = [
    { threadId, turnIds },
    ...(delegated
      ? turnIds.map((turnId) => ({
          threadId: `${threadId}-child-${turnId}`,
          turnIds: [`${turnId}-child`],
        }))
      : []),
  ];
  const expected = [];
  for (const thread of threads) {
    const path = join(home, "sessions", `rollout-${thread.threadId}.jsonl`);
    const raw = (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    for (const turnId of thread.turnIds.filter(
      (id) =>
        id !== "main" &&
        (id !== "main-child" || scan.progress?.status === "complete"),
    )) {
      expect(
        Date.parse(
          raw.find((event) => event.payload.turn_id === turnId).timestamp,
        ),
      ).toBeGreaterThan(cutoff);
    }
    const later = [
      {
        type: "event_msg",
        timestamp: new Date(cutoff + 60_000).toISOString(),
        payload: { type: "task_started", turn_id: "unrelated" },
      },
      {
        type: "response_item",
        timestamp: new Date(cutoff + 60_001).toISOString(),
        payload: {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: "unrelated reply" }],
        },
      },
    ];
    await appendFile(
      path,
      later.map((event) => JSON.stringify(event) + "\n").join(""),
    );
    const before = await readFile(path);
    let selected = false;
    const events = raw.filter((event) => {
      if (event.type === "event_msg" && event.payload.type === "task_started")
        selected = thread.turnIds.includes(event.payload.turn_id);
      return (
        selected ||
        event.timestamp === undefined ||
        Date.parse(event.timestamp) <= cutoff
      );
    });
    expected.push({ ...thread, path, before, events });
  }
  const logs = await readSavedScanLogs(scan, home);
  const requestFile = join(root, "feedback-request.json");
  await sendFeedback(
    {
      reason: "Synthetic lifecycle regression",
      includeLogs: true,
      scan,
      environment: {
        ...environment,
        CODEX_CLI_PATH: process.execPath,
        FEEDBACK_REQUEST_FILE: requestFile,
      },
      workingDirectory: root,
    },
    (_command, _args, options) =>
      spawn(process.execPath, [feedbackFixture], options),
  );
  const { attachments } = JSON.parse(await readFile(requestFile, "utf8"));
  expect(JSON.parse(attachments[0].content)).toEqual(logs);
  for (const thread of expected) {
    expect(await readFile(thread.path)).toEqual(thread.before);
    const events = logs.events
      .filter((row) => row["threadId"] === thread.threadId)
      .map(({ event }) => event);
    expect(events).toEqual(thread.events);
    expect(
      events
        .filter((event: any) => event.payload.type === "task_started")
        .map((event: any) => event.payload.turn_id),
    ).toEqual(thread.turnIds);
  }
}
