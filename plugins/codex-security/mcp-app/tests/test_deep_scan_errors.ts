import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

const {
  classifyCodexWorkerError,
  codexWorkerTurnError,
  DeepScanNonRetryableError,
  exceedsContext,
} = await importModule({
  entryPoints: [
    fileURLToPath(new URL("../src/deep-scan/errors.ts", import.meta.url)),
  ],
});

test(function testOsErrorCodesRemainRetryable() {
  for (const code of ["ENOENT", "EACCES", "ENOEXEC", "EPERM"]) {
    const original = Object.assign(new Error(`spawn codex ${code}`), { code });
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
  }
});

test(function testTextualMissingPathErrorsRemainRetryable() {
  for (const diagnostic of [
    "Error: No such file or directory (os error 2)",
    "Error: The system cannot find the file specified. (os error 2)",
  ]) {
    const original = new Error(
      ["Codex Exec exited with code 1:", diagnostic].join("\n"),
    );
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
  }
});

test(function testWorkerErrorClassificationPreservesExplicitFailures() {
  const explicit = new DeepScanNonRetryableError(
    "Explicitly rejected worker permission profile.",
  );
  assert.equal(classifyCodexWorkerError(explicit), explicit);

  for (const message of [
    "Request blocked by cyberPolicy.",
    "config parser handles unknown keys",
    "failed to load configuration: invalid value",
    "agents.max_threads cannot be set when features.multi_agent_v2 is enabled",
    "authentication required",
    "not logged in",
    "missing API key",
    "Codex Exec exited with code 2: failed to load configuration: invalid value",
    "chatgpt authentication required for remote plugin catalog; api key auth is not supported",
    "chatgpt authentication required to sync remote plugins; api key auth is not supported",
    "required MCP servers failed to initialize: codex_security_artifacts: timed out handshaking with MCP server after 30s",
    "required MCP servers failed to initialize: other_server: request timed out",
  ]) {
    const original = new Error(message);
    assert.equal(classifyCodexWorkerError(original), original);
  }
  for (const code of ["ECONNRESET", "EPIPE", "ETIMEDOUT", "cyber_policy"]) {
    const original = Object.assign(new Error("Unrecognized worker failure"), {
      code,
    });
    assert.equal(classifyCodexWorkerError(original), original);
  }
});

test(function testNativeTurnFailureClassification() {
  for (const message of [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
    "Quota exceeded. Check your plan and billing details.",
    "To use Codex with your ChatGPT plan, upgrade to Plus: https://chatgpt.com/explore/plus.",
    "Your workspace is out of credits. Add credits to continue.",
    "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
    "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
    "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
    "You’ve hit your usage limit. Try again later.",
    "You’ve hit your usage limit for the selected model. Switch to another model to continue.",
    "Error running remote compact task: You’ve hit your usage limit. Try again later.",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.ok(error instanceof DeepScanNonRetryableError);
    assert.equal(error.message, message);
  }
  for (const message of [
    "Command failed: Request blocked by cyberPolicy.",
    "Error running remote compact task: Request blocked by cyberPolicy.",
    "Request blocked by cyberPolicy. See the fixture.",
    " Request blocked by cyberPolicy.",
    "429 Too Many Requests",
    "Command failed: Quota exceeded. Check your plan and billing details.",
    "Error running remote compact task: stream disconnected before completion: synthetic reset",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.equal(error.name, "Error");
    assert.equal(error.message, message);
  }
});

test(function testContextLimitClassification() {
  for (const error of [
    { code: "context_length_exceeded" },
    new Error("context_length_exceeded"),
    "Codex ran out of room in the model's context window.",
    "Your input exceeds the context window of this model.",
    "This model's maximum context length is 128000 tokens.",
    "compaction service context window exceeded",
    "The request exceeded the model's context window.",
    "Context length exceeded",
  ]) {
    assert.equal(exceedsContext(error), true, String(error));
  }
  for (const error of [
    { code: "rate_limit_exceeded" },
    new Error("Rate limit reached. Please try again in 1.2s."),
    new Error("Codex worker stream ended before turn.completed"),
    new Error("Keep the context window small when writing prompts."),
    new Error("unknown_context_length_exceeded_status"),
    undefined,
  ]) {
    assert.equal(exceedsContext(error), false, String(error));
  }
});
