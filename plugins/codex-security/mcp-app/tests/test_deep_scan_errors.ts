import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

const { codexWorkerTurnError, DeepScanNonRetryableError } = await importModule({
  entryPoints: [
    fileURLToPath(new URL("../src/deep-scan/errors.ts", import.meta.url)),
  ],
});

test(function testUsageLimitClassification() {
  for (const message of [
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
    "429 Too Many Requests",
    "Command failed: Quota exceeded. Check your plan and billing details.",
    "Error running remote compact task: stream disconnected before completion: synthetic reset",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.equal(error.name, "Error");
    assert.equal(error.message, message);
  }
});
