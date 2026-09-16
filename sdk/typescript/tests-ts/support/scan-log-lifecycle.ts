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

export function savedLogTurn(input: {
  environment: NodeJS.ProcessEnv;
  threadId: string;
  turnId: string;
  outcome: "completed" | "failed";
  draft?: boolean;
}) {
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
      for await (const line of createInterface({ input: child.stdout }))
        yield JSON.parse(line) as { type: string; [key: string]: unknown };
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
) {
  const home = environment["CODEX_HOME"]!;
  const path = join(home, "sessions", `rollout-${threadId}.jsonl`);
  const original = await readFile(path, "utf8");
  const cutoff = Date.parse(scan.progress!.updatedAt!);
  const raw = original
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const turnId of turnIds.filter((id) => id !== "main")) {
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
  const logs = await readSavedScanLogs(scan, home);
  const events = logs.events.map(({ event }) => event);
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
  expect(await readFile(path)).toEqual(before);
  // Complete raw projection, including failure output, with no later conversation.
  let selected = true;
  const expected = raw.filter((event) => {
    if (event.type === "event_msg" && event.payload.type === "task_started") {
      selected = turnIds.includes(event.payload.turn_id);
    }
    return selected;
  });
  expect(events).toEqual(expected);
  expect(
    events
      .filter((event: any) => event.payload.type === "task_started")
      .map((event: any) => event.payload.turn_id),
  ).toEqual(turnIds);
}
