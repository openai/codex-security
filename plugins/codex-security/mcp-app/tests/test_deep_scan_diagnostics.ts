import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { writeJson } from "./support/json.ts";
import {
  coordinatorFixture,
  startCoordinator,
  standardScanDraft,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";

test("Standard scan retries preserve the full validation error", async () => {
  try {
    const { fixture, store } = await coordinatorFixture();
    const id = "source location ".repeat(300).trimEnd();
    const message = `Standard scan worker repeats resolved deferred id: ${id}`;
    let basePrompt: string | undefined;
    const requests: CodexWorkerRequest[] = [];
    const coordinator = startCoordinator(
      fixture,
      store,
      {
        run: async (request: CodexWorkerRequest) => {
          requests.push(request);
          const draft = standardScanDraft(
            fixture.run.scanId,
            undefined,
            "diagnostic-worker",
          );
          if (requests.length === 1) {
            basePrompt = await readFile(request.promptPath, "utf8");
            const closure = { id, reason: "Review completed." };
            draft.reviewState.resolvedDeferred = [closure, closure];
          }
          await writeJson(
            path.join(request.workingDirectory, "result.json"),
            draft,
          );
          return {};
        },
      },
      { retryDelaysMs: [0] },
    );
    const outcome = await coordinator.wait(undefined);
    assert.equal(outcome.status, "succeeded", outcome.error);
    assert.equal(requests.length, 2);
    const retry = await readFile(requests[1].promptPath, "utf8");
    const data = JSON.parse(
      retry
        .split("\n")
        .find((line) => line.startsWith('{"validation_error":'))!,
    );
    assert.equal(data.validation_error.message, message);
    assert.ok(retry.includes(message));
    assert.equal(
      store.workerUpdates.find((update) => update.error)?.error,
      message,
    );
    assert.equal(await readFile(requests[0].promptPath, "utf8"), basePrompt);
  } finally {
    await temporaryDirectories.cleanup();
  }
});
