import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importModule } from "./import-module.ts";
import {
  coordinatorFixture,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";

const { DeepScanWorkerRunner, createDeepScanArtifacts } = await importModule({
  stdin: {
    contents: [
      'export { DeepScanWorkerRunner } from "./worker-runner.ts";',
      'export { createDeepScanArtifacts } from "./artifacts.ts";',
    ].join("\n"),
    resolveDir: path.join(import.meta.dirname, "../src/deep-scan"),
  },
  loader: { ".md": "text" },
});

test("Standard scan retries preserve the full validation error", async () => {
  try {
    const { fixture, store } = await coordinatorFixture();
    const validationError = new Error(
      "Invalid Standard scan field: " +
        "source location ".repeat(300).trimEnd(),
    );
    const workerRoot = path.join(
      fixture.run.scanDir,
      "artifacts",
      "diagnostic-worker",
    );
    const artifactDir = path.join(workerRoot, "output");
    const promptPath = path.join(workerRoot, "prompt.md");
    await mkdir(artifactDir, { recursive: true });
    await writeFile(promptPath, "Complete the assigned security review.\n");
    const requests: CodexWorkerRequest[] = [];
    const runner = new DeepScanWorkerRunner({
      run: fixture.run,
      store,
      executor: {
        run: async (request: CodexWorkerRequest) => {
          requests.push(request);
          return {};
        },
      },
      artifacts: createDeepScanArtifacts(fixture.run.scanDir),
      pluginRoot: fixture.pluginRoot,
      clock: { now: Date.now, sleep: async () => {} },
      random: () => 0,
      log: () => {},
      retryDelaysMs: [0],
      signal: new AbortController().signal,
    });
    let validations = 0;
    const outcome = await runner.runWorkerWithRetries({
      workerId: randomUUID(),
      promptPath,
      promptRoot: path.join(workerRoot, "prompts"),
      artifactDir,
      validate: async () => {
        if (validations++ === 0) throw validationError;
      },
    });
    assert.equal(outcome.status, "succeeded");
    assert.equal(requests.length, 2);
    const retry = await readFile(requests[1].promptPath, "utf8");
    const data = JSON.parse(
      retry
        .split("\n")
        .find((line) => line.startsWith('{"validation_error":'))!,
    );
    assert.equal(data.validation_error.message, validationError.message);
    assert.ok(retry.includes(validationError.message));
    assert.equal(
      store.workerUpdates.find((update) => update.error)?.error,
      validationError.message,
    );
    assert.equal(
      await readFile(promptPath, "utf8"),
      "Complete the assigned security review.\n",
    );
  } finally {
    await temporaryDirectories.cleanup();
  }
});
