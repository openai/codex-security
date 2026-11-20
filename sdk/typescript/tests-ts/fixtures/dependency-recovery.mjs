import {
  appendFileSync,
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";

const [dir, scenario] = process.argv.slice(2);
const log = (event) =>
  appendFileSync(join(dir, "commands"), JSON.stringify(event) + "\n");
const checkpoint = join(dir, "native-thread");
const restarted = existsSync(checkpoint);
const send = (v) => process.stdout.write(JSON.stringify(v) + "\n");
const profile = {
  filesystem: { ":root": "read" },
  network: { enabled: false },
};
const config = {
  default_permissions: "dependency_investigation",
  permissions: { dependency_investigation: profile },
};
const result = (id, value) => send({ id, result: value });
let activeTurn = "original-turn";
let turnCount = 0;
const reply = (params) =>
  send({
    method: "item/completed",
    params: {
      threadId: "original-thread",
      turnId: activeTurn,
      item: params,
    },
  });
const answer = {
  type: "agentMessage",
  text: '{"restored":true}',
  phase: "final_answer",
};
const endTurn = (status) =>
  send({
    method: "turn/completed",
    params: {
      threadId: "original-thread",
      turn: {
        id: activeTurn,
        status,
        ...(status === "failed" && {
          error: { message: "Provider refused the investigation." },
        }),
      },
    },
  });
const tool = {
  type: "mcpToolCall",
  id: "write-1",
  server: "fixture",
  tool: "record",
  readOnlyHint: false,
};
log({ launch: restarted ? "replacement" : "initial" });
for await (const raw of createInterface({ input: process.stdin })) {
  const { id, method, params } = JSON.parse(raw);
  if (id === undefined) continue;
  if (method === "initialize") result(id, {});
  if (method === "config/read")
    result(id, {
      config,
      layers: [{ name: { type: "sessionFlags" }, config }],
    });
  if (method === "thread/start" || method === "thread/resume") {
    log({
      method,
      threadId: params.threadId,
      permissions: params.permissions,
      ephemeral: params.ephemeral,
    });
    const completed = scenario === "already-complete";
    const turns = restarted
      ? [
          {
            id: "original-turn",
            status: completed ? "completed" : "interrupted",
            items: completed ? [answer] : [{ ...tool, status: "completed" }],
          },
        ]
      : [];
    writeFileSync(checkpoint, "same thread");
    result(id, {
      thread: {
        id:
          scenario === "wrong-thread" && restarted
            ? "other-thread"
            : "original-thread",
        ephemeral: false,
        turns,
        status: { type: "idle" },
      },
      activePermissionProfile: { id: "dependency_investigation" },
      model: "fixture",
      modelProvider: "fixture",
    });
  }
  if (method === "turn/start") {
    const prompt = params.input[0].text;
    log({ method, prompt });
    turnCount++;
    if (scenario.startsWith("feedback")) {
      activeTurn = "turn-" + turnCount;
      result(id, { turn: { id: activeTurn } });
      send({
        method: "thread/tokenUsage/updated",
        params: {
          threadId: "original-thread",
          tokenUsage: {
            total: { inputTokens: turnCount * 4, outputTokens: turnCount },
          },
        },
      });
      reply({ ...answer, text: "Submission " + turnCount });
      endTurn("completed");
      continue;
    }
    result(id, { turn: { id: "original-turn" } });
    if (!restarted) {
      send({
        method: "item/started",
        params: {
          threadId: "original-thread",
          turnId: "original-turn",
          item: { ...tool, status: "inProgress" },
        },
      });
      if (scenario === "pending-write") {
        process.exitCode = 9;
        break;
      }
      log({ mutation: "committed" });
      reply({
        ...tool,
        status: "completed",
        arguments: { id: "proof" },
        result: {
          content: [{ type: "text", text: "Verified source receipt" }],
        },
      });
      if (scenario === "denial") {
        endTurn("failed");
        break;
      }
      if (scenario === "stderr-denial") {
        process.stderr.write("Provider permission denied");
        process.exitCode = 9;
        break;
      }
      if (scenario === "invalid-answer") {
        reply({ ...answer, text: "invalid output" });
        endTurn("completed");
        break;
      }
      if (scenario === "provider-error")
        send({
          method: "error",
          params: {
            threadId: "original-thread",
            turnId: "original-turn",
            willRetry: false,
            error: { message: "Model refused this request." },
          },
        });
      process.exitCode = 9;
      break;
    }
    if (scenario === "second-exit") {
      process.exitCode = 9;
      break;
    }
    if (!readFileSync(join(dir, "commands"), "utf8").includes("committed"))
      throw new Error("missing recorded work");
    reply(answer);
    endTurn("completed");
    break;
  }
}
await new Promise((resolve) => process.stdout.write("", resolve));
process.exit(process.exitCode ?? 0);
