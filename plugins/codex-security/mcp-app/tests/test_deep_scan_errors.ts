import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

const {
  classifyCodexWorkerError,
  codexWorkerTurnError,
  DeepScanNonRetryableError,
  isCodexCybersecurityPolicyRefusal,
} = await importModule({
  entryPoints: [
    fileURLToPath(new URL("../src/deep-scan/errors.ts", import.meta.url)),
  ],
});

testOsErrorCodesRemainRetryable();
testTextualMissingPathErrorsRemainRetryable();
testWorkerErrorClassificationPreservesExplicitFailures();
testUsageLimitClassification();

function testOsErrorCodesRemainRetryable() {
  for (const code of ["ENOENT", "EACCES", "ENOEXEC", "EPERM"]) {
    const original = Object.assign(new Error(`spawn codex ${code}`), { code });
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
  }
}

function testTextualMissingPathErrorsRemainRetryable() {
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
}

function testWorkerErrorClassificationPreservesExplicitFailures() {
  const explicit = new DeepScanNonRetryableError(
    "Explicitly rejected worker permission profile.",
  );
  assert.equal(classifyCodexWorkerError(explicit), explicit);

  const refusalMessages = [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
  ];
  for (const message of refusalMessages) {
    const original = new Error(message);
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
    assert.equal(isCodexCybersecurityPolicyRefusal(classified), true);

    const explicitRefusal = new DeepScanNonRetryableError(message);
    assert.equal(classifyCodexWorkerError(explicitRefusal), explicitRefusal);

    for (const unrecognized of [
      `Source fixture: ${message}`,
      `${message} Source fixture.`,
      JSON.stringify({ message }),
      `Codex Exec exited with code 1: ${message}`,
      `429 Too Many Requests: ${message}`,
      ` ${message}`,
      `${message}\n`,
      message.toLowerCase(),
    ]) {
      const unrelated = new Error(unrecognized);
      assert.equal(classifyCodexWorkerError(unrelated), unrelated);
      assert.equal(isCodexCybersecurityPolicyRefusal(unrelated), false);
    }
  }

  for (const message of [
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
}

function testUsageLimitClassification() {
  for (const message of [
    "Quota exceeded. Check your plan and billing details.",
    "Your workspace is out of credits. Add credits to continue.",
    "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
    "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
    "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
    "You’ve hit your usage limit. Try again later.",
    "You’ve hit your usage limit for the selected model. Switch to another model to continue.",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.ok(error instanceof DeepScanNonRetryableError);
    assert.equal(error.message, message);
  }
  for (const message of [
    "429 Too Many Requests",
    "Command failed: Quota exceeded. Check your plan and billing details.",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.equal(error.name, "Error");
    assert.equal(error.message, message);
  }
}
