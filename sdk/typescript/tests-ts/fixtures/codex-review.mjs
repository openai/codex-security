import refusalMessages from "./codex-refusal-messages.json" with { type: "json" };
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const [scenario, transcript, checkout, stage = "pair-review"] =
  process.argv.slice(2);

const failure = (message, codexErrorInfo) => ({ message, codexErrorInfo });
const httpFailure = (message, httpStatusCode = 503) =>
  failure(message, { httpConnectionFailed: { httpStatusCode } });
const transportStatus = /^transport-(?:request|turn)-(\d+)$/.exec(
  scenario,
)?.[1];
const transportFailure = transportStatus
  ? httpFailure(
      `Safety policy: request refused by upstream with ${transportStatus}`,
      Number(transportStatus),
    )
  : scenario === "transport-wording-request"
    ? httpFailure("Request flagged for possible cybersecurity risk.")
    : undefined;
const turnFailures = {
  ...(scenario.startsWith("transport-turn-")
    ? { [scenario]: transportFailure }
    : {}),
  "transport-null-turn": failure(
    "Request flagged for possible cybersecurity risk.",
    { responseStreamDisconnected: { httpStatusCode: null } },
  ),
  "transport-timeout-turn": httpFailure(
    "Safety policy: request refused because the service timed out",
    504,
  ),

  "determiner-service-error": httpFailure(
    "Safety policy: this request is refused because the upstream service is unavailable.",
  ),
  "sentence-service-error": httpFailure(
    "Safety policy: request refused. Service unavailable.",
  ),
  "policy-turn-code": failure("Request blocked.", "cyberPolicy"),
  "policy-turn": failure(
    "Request flagged for possible cybersecurity risk.",
    "other",
  ),
  "policy-accordance-turn": failure(
    "This request was refused in accordance with the safety policy.",
    "other",
  ),
  "policy-terse-turn": failure("Refused due to the safety policy", "other"),
  "failed-turn": failure("Rate limit exceeded", "usageLimitExceeded"),
  "rate-limit-turn": failure("Rate limit reached", "rateLimitExceeded"),
  "server-error": httpFailure("Provider temporarily unavailable"),
  "service-unavailable": httpFailure(
    "Connection refused: safety policy service unavailable",
  ),
  "network-request-error": httpFailure(
    "Network request refused: safety policy service unavailable",
  ),
  "http-request-error": httpFailure(
    "HTTP request blocked: safety policy service unavailable",
  ),
  "prefix-network-error": httpFailure(
    "Failed to contact safety policy: request refused by upstream with 503",
  ),
  "prefix-because-error": httpFailure(
    "Safety policy: request refused because the upstream service is unavailable.",
  ),
  "prefix-as-error": httpFailure(
    "Safety policy: request refused as the upstream service is unavailable.",
  ),
  "prefix-service-error": httpFailure(
    "Safety policy: request refused: service unavailable",
  ),
  "prefix-upstream-error": httpFailure(
    "Safety policy: request refused by upstream with 503",
  ),
  "connection-error": failure("Provider stream disconnected", {
    responseStreamDisconnected: { httpStatusCode: null },
  }),
  "overloaded-turn": failure(
    "Selected model is at capacity.",
    "serverOverloaded",
  ),
  "internal-error-turn": failure(
    "Internal server error",
    "internalServerError",
  ),
  "unauthorized-turn": httpFailure("Authentication required", 401),
  "bad-request-turn": failure("Invalid model configuration", "badRequest"),
  "unknown-turn": failure("Unknown model failure", "other"),
};
const requestFailures = {
  "request-error": { message: "Authentication required" },
  "sentence-service-request-error": httpFailure(
    "Safety policy: request refused. Service unavailable.",
  ),
  "credential-error": {
    message: "Authentication failed: Bearer synthetic-review-key",
  },
  "policy-request": { message: "Request rejected: cyber_policy." },
  "policy-request-code": failure("Request blocked.", "cyberPolicy"),
};
const blockers = {
  "policy-reported-error": "Request refusal due to the safety policy.",
  "required-source-error-policy-file":
    "Connection refused while fetching content-policy.ts",
  "required-source-error-upload-policy":
    "Artifact upload was blocked by the content policy.",
  "required-source-error-publication-policy":
    "Artifact publication was refused due to the content policy.",
  "required-source-error-publication-refusal":
    "Artifact publication refusal due to the content policy.",
  "required-source-error-policy-requires-refusal":
    "Artifact upload failed because the content policy requires refusal of unsupported media",
  "required-source-error-upload-content-policy-violation":
    "Artifact upload failed due to content policy violation",
  "required-source-error-upload-safety-policy-violation":
    "Artifact upload failed due to safety policy violation",
};
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
    const requestFailure = scenario.startsWith("transport-turn-")
      ? undefined
      : (transportFailure ?? requestFailures[scenario]);
    if (requestFailure) {
      const { codexErrorInfo } = requestFailure;
      send({
        id: message.id,
        error: {
          code: -32000,
          message: requestFailure.message,
          data: codexErrorInfo
            ? { codexErrorInfo }
            : "Synthetic private response data",
        },
      });
      continue;
    }
    assert.equal(message.params.ephemeral, true);
    assert.equal(message.params.permissions, "codex_security_review");
    assert.equal(
      message.params.approvalPolicy,
      stage === "screening" ? "never" : "on-request",
    );
    if (stage === "screening") {
      assert.equal(message.params.config.features.multi_agent, false);
      assert.equal(message.params.config.features.multi_agent_v2, false);
    }
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
    if (scenario === "exit-diagnostic") {
      process.stdout.end();
      process.stderr.write(
        "Permission profile synthetic_profile was rejected: café 🔒\n",
        () => process.exit(7),
      );
      continue;
    }
    if (scenario === "diagnostics") {
      process.stderr.write("Native diagnostic: Bearer synthetic-review-key\n");
      send({
        method: "configWarning",
        params: { message: "Configured model fallback: synthetic-review-key" },
      });
      send({
        method: "warning",
        params: { message: "Source lookup warning", threadId: "review-thread" },
      });
      send({
        method: "item/completed",
        params: {
          threadId: "review-thread",
          turnId,
          item: {
            id: "command-1",
            type: "commandExecution",
            status: "completed",
            exitCode: 7,
            aggregatedOutput: "Source lookup failed: synthetic-review-key",
          },
        },
      });
      for (const threadId of ["nested-review", "review-thread"])
        send({
          method: "thread/tokenUsage/updated",
          params: {
            threadId,
            turnId,
            tokenUsage: {
              total: { inputTokens: 12, outputTokens: 3, totalTokens: 15 },
            },
          },
        });
      submit("valid", { decision: "SAME" });
    } else if (scenario === "configured-model") {
      const decision = { decision: "DISTINCT", rationale: "Independent fixes" };
      submit(
        "valid",
        stage === "screening"
          ? { decisions: { "pair-1": decision } }
          : decision,
      );
    } else if (scenario === "invalid-json") {
      process.stdout.write("Synthetic private response data\n");
    } else if (
      scenario === "invalid-submission" ||
      (scenario === "retry-correction" && turns === 1)
    ) {
      submit("invalid", { decision: "UNKNOWN" });
    } else if (
      scenario === "text-only" ||
      scenario === "service-timeout-text" ||
      Object.hasOwn(refusalMessages, scenario) ||
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
          item: {
            type: "agentMessage",
            text:
              scenario === "service-timeout-text"
                ? "Safety policy: request refused because the service timed out"
                : (refusalMessages[scenario] ?? '{"decision":"SAME"}'),
          },
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
    } else if (
      scenario.startsWith("required-source-error") ||
      scenario === "policy-reported-error"
    ) {
      if (scenario === "required-source-error-after-verdict")
        submit("pending-verdict", { decision: "SAME" });
      submit(
        "blocked",
        {
          reason:
            blockers[scenario] ?? "Required source revision could not be read.",
        },
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
    } else if (turnFailures[scenario]) {
      process.stderr.write("Synthetic provider failure with private details\n");
      complete("failed", {
        ...turnFailures[scenario],
        additionalDetails: "Synthetic private response data",
      });
    } else complete();
  } else if (message.id === "late-submission") {
    assert.equal(message.result.success, true);
    complete();
  }
}
