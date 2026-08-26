import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const [scenario, transcript] = process.argv.slice(2);
const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const submit = (id, arguments_, overrides = {}) =>
  send({
    id,
    method: "item/tool/call",
    params: {
      threadId: "review-thread",
      turnId: "review-turn",
      tool: "submit_decisions",
      namespace: null,
      arguments: arguments_,
      ...overrides,
    },
  });
const complete = (status = "completed") =>
  send({
    method: "turn/completed",
    params: {
      threadId: "review-thread",
      turn: { id: "review-turn", status },
    },
  });

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  appendFileSync(transcript, `${line}\n`);
  if (message.method === "initialize") {
    assert.equal(message.params.capabilities.experimentalApi, true);
    send({ id: message.id, result: {} });
  } else if (message.method === "account/login/start") {
    assert.equal(message.params.type, "apiKey");
    assert.equal(message.params.apiKey, "synthetic-review-key");
    send({ id: message.id, result: { type: "apiKey" } });
  } else if (message.method === "thread/start") {
    assert.equal(message.params.ephemeral, true);
    assert.equal(message.params.sandbox, "read-only");
    assert.equal(message.params.config.mcp_servers.synthetic.enabled, false);
    assert.deepEqual(message.params.environments, []);
    assert.equal(message.params.dynamicTools[0].name, "submit_decisions");
    send({
      id: message.id,
      result: {
        thread: { id: "review-thread", ephemeral: true, path: null },
      },
    });
  } else if (message.method === "turn/start") {
    send({
      method: "turn/started",
      params: { threadId: "review-thread", turn: { id: "review-turn" } },
    });
    send({ id: message.id, result: { turn: { id: "review-turn" } } });
    if (scenario === "exit") process.exit(1);
    if (scenario === "text-only") {
      send({
        method: "item/completed",
        params: {
          threadId: "review-thread",
          turnId: "review-turn",
          item: { type: "agentMessage", text: '{"decision":"SAME"}' },
        },
      });
      complete();
    } else if (scenario === "correction") {
      submit("wrong-thread", { decision: "SAME" }, { threadId: "other" });
      submit("wrong-tool", { decision: "SAME" }, { tool: "other" });
      submit("invalid", { decision: "UNKNOWN" });
    } else {
      submit("valid", { decision: "SAME" });
    }
  } else if (["wrong-thread", "wrong-tool"].includes(message.id)) {
    assert.equal(message.error.code, -32601);
  } else if (message.id === "invalid") {
    assert.equal(message.result.success, false);
    assert.match(message.result.contentItems[0].text, /Resubmit/);
    submit("valid", { decision: "SAME" });
  } else if (message.id === "valid") {
    assert.equal(message.result.success, true);
    if (scenario === "failed-turn") {
      process.stderr.write("Synthetic provider failure with private details\n");
      complete("failed");
    } else complete();
  }
}
