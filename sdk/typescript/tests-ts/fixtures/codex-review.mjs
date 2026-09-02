import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const [scenario, transcript, checkout] = process.argv.slice(2);
let turns = 0;
let turnId;
const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const submit = (id, arguments_, overrides = {}) =>
  send({
    id,
    method: "item/tool/call",
    params: {
      threadId: "review-thread",
      turnId,
      tool: "submit_decisions",
      namespace: "review_validator",
      arguments: arguments_,
      ...overrides,
    },
  });
const complete = (status = "completed", error = null) =>
  send({
    method: "turn/completed",
    params: {
      threadId: "review-thread",
      turn: { id: turnId, status, error },
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
    if (["request-error", "credential-error"].includes(scenario)) {
      send({
        id: message.id,
        error: {
          code: -32000,
          message:
            scenario === "credential-error"
              ? "Authentication failed: Bearer synthetic-review-key"
              : "Authentication required",
          data: "Synthetic private response data",
        },
      });
      continue;
    }
    assert.equal(message.params.ephemeral, true);
    assert.equal(message.params.permissions, "codex_security_review");
    assert.equal(message.params.approvalPolicy, "on-request");
    assert.equal(message.params.approvalsReviewer, "auto_review");
    assert.equal(message.params.config.mcp_servers.synthetic.enabled, false);
    assert.deepEqual(
      message.params.config.features.code_mode.direct_only_tool_namespaces,
      ["review_validator"],
    );
    assert.equal(message.params.cwd, checkout);
    assert.notEqual(message.params.cwd, process.cwd());
    assert.equal(message.params.dynamicTools[0].name, "review_validator");
    assert.equal(
      message.params.dynamicTools[0].tools[0].name,
      "submit_decisions",
    );
    const errorTool = message.params.dynamicTools[0].tools.find(
      (tool) => tool.name === "submit_error",
    );
    assert.deepEqual(errorTool.inputSchema.required, ["reason"]);
    assert.equal(errorTool.inputSchema.additionalProperties, false);
    send({
      id: message.id,
      result: {
        thread: { id: "review-thread", ephemeral: true, path: null },
      },
    });
  } else if (message.method === "turn/start") {
    turns++;
    turnId = `review-turn-${turns}`;
    assert.equal(message.params.threadId, "review-thread");
    if (turns > 1) {
      assert.equal(turns, 2);
      assert.match(message.params.input[0].text, /original assigned review/);
      assert.match(
        message.params.input[0].text,
        /review_validator.submit_decisions/,
      );
      if (["retry-correction", "invalid-submission"].includes(scenario))
        assert.match(message.params.input[0].text, /Invalid decision/);
    }
    send({
      method: "turn/started",
      params: { threadId: "review-thread", turn: { id: turnId } },
    });
    send({ id: message.id, result: { turn: { id: turnId } } });
    if (turns > 1) {
      submit("wrong-turn", { decision: "SAME" }, { turnId: "review-turn-1" });
      send({
        method: "turn/completed",
        params: {
          threadId: "review-thread",
          turn: { id: "review-turn-1", status: "completed" },
        },
      });
    }
    if (scenario === "exit") process.exit(1);
    if (scenario === "invalid-json") {
      process.stdout.write("Synthetic private response data\n");
    } else if (
      scenario === "invalid-submission" ||
      (scenario === "retry-correction" && turns === 1)
    ) {
      submit("invalid", { decision: "UNKNOWN" });
    } else if (
      scenario === "text-only" ||
      ([
        "text-only-correction",
        "cancel-continuation",
        "required-source-error-after-text",
      ].includes(scenario) &&
        turns === 1)
    ) {
      send({
        method: "item/completed",
        params: {
          threadId: "review-thread",
          turnId,
          item: { type: "agentMessage", text: '{"decision":"SAME"}' },
        },
      });
      complete();
    } else if (scenario === "cancel-continuation") {
      process.stderr.write("Ready to cancel continuation\n");
    } else if (scenario === "correction") {
      submit("wrong-thread", { decision: "SAME" }, { threadId: "other" });
      submit("wrong-tool", { decision: "SAME" }, { tool: "other" });
      submit("wrong-namespace", { decision: "SAME" }, { namespace: null });
      submit(
        "wrong-error-thread",
        { reason: "Unrelated failure" },
        { tool: "submit_error", threadId: "other" },
      );
      submit("invalid", { decision: "UNKNOWN" });
    } else if (scenario === "invalid-review-error") {
      submit("invalid-error", { reason: " " }, { tool: "submit_error" });
    } else if (scenario.startsWith("required-source-error")) {
      if (scenario === "required-source-error-after-verdict")
        submit("pending-verdict", { decision: "SAME" });
      submit(
        "blocked",
        { reason: "Required source revision could not be read." },
        { tool: "submit_error" },
      );
    } else if (scenario === "incomplete-content") {
      submit("valid", { decision: "DISTINCT" });
    } else {
      if (scenario === "optional-lookup-failure")
        send({
          method: "item/completed",
          params: {
            threadId: "review-thread",
            turnId,
            item: { type: "commandExecution", status: "failed", exitCode: 1 },
          },
        });
      submit("valid", { decision: "SAME" });
    }
  } else if (
    [
      "wrong-thread",
      "wrong-tool",
      "wrong-namespace",
      "wrong-error-thread",
      "wrong-turn",
    ].includes(message.id)
  ) {
    assert.equal(message.error.code, -32601);
  } else if (message.id === "invalid-error") {
    assert.equal(message.result.success, false);
    assert.match(message.result.contentItems[0].text, /Resubmit/);
    submit(
      "blocked",
      { reason: "Required source revision could not be read." },
      { tool: "submit_error" },
    );
  } else if (message.id === "invalid") {
    assert.equal(message.result.success, false);
    assert.match(message.result.contentItems[0].text, /Resubmit/);
    if (["invalid-submission", "retry-correction"].includes(scenario))
      complete();
    else submit("valid", { decision: "SAME" });
  } else if (message.id === "valid") {
    assert.equal(message.result.success, true);
    if (scenario === "accepted-no-replay") {
      submit("late-submission", { decision: "UNKNOWN" });
    } else if (scenario === "failed-turn") {
      process.stderr.write("Synthetic provider failure with private details\n");
      complete("failed", {
        message: "Rate limit exceeded",
        codexErrorInfo: "usageLimitExceeded",
        additionalDetails: "Synthetic private response data",
      });
    } else complete();
  } else if (message.id === "late-submission") {
    assert.equal(message.result.success, true);
    complete();
  }
}
