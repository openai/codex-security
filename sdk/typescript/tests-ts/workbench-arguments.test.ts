import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { workbenchArgs } from "../src/workbench-arguments.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import {
  scanRegistrationArguments,
  workbenchCommand,
} from "./support/workbench-command.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "workbench-arguments-",
);
afterEach(cleanup);

test("workbench arguments preserve field order, values, and repeated flags", () => {
  expect(
    workbenchArgs("fixture-command", {
      scanId: "scan-example",
      registrationJsonStdin: true,
      archiveExisting: false,
      parentScanId: undefined,
      offset: 0,
      negative: -1e30,
      name: "",
      query: "--query\nUTF-8 λ\0",
      inputWorkerId: ["worker-2", "worker-1", "worker-2"],
      omittedWorkerId: [],
    }),
  ).toEqual([
    "fixture-command",
    "--scan-id",
    "scan-example",
    "--registration-json-stdin",
    "--offset",
    "0",
    "--negative=-1e+30",
    "--name",
    "",
    "--query=--query\nUTF-8 λ\0",
    "--input-worker-id",
    "worker-2",
    "--input-worker-id",
    "worker-1",
    "--input-worker-id",
    "worker-2",
  ]);
});

test.each(["fail-scan", "cancel-scan"])(
  "persists large worker coverage through %s at the process boundary",
  async (command) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDirectory = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDirectory, { mode: 0o700 });
    const workbench = workbenchCommand(await resolvePluginPython(), () => ({
      PATH: process.env["PATH"],
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      CODEX_HOME: join(root, "codex-home"),
      CODEX_SQLITE_HOME: join(root, "codex-sqlite"),
      CODEX_STATE_DB: "",
    }));
    const registration = await workbench(
      scanRegistrationArguments(repository, scanDirectory),
    );
    const coverageScope = Array.from({ length: 1600 }, (_, index) => {
      const suffix = String(index).padStart(12, "0");
      return [
        `thread:00000000-0000-4000-8000-${suffix}`,
        `worker-attempt:10000000-0000-4000-8000-${suffix}`,
      ];
    }).flat();
    const usage = {
      source: "codex_runtime",
      coverage: "partial",
      coverageScope,
      threadCount: 1600,
      missingThreadCount: 1,
      cacheWriteInputTokensReported: false,
      inputTokens: 40,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 5,
      reasoningOutputTokens: 0,
      totalTokens: 45,
    };
    const payload = JSON.stringify({ usage });
    // A realistic Deep Scan scope can exceed Linux's per-argument byte limit.
    expect(Buffer.byteLength(payload)).toBeGreaterThan(128 * 1024);
    const scanId = String(registration["scanId"]);
    await workbench([
      command,
      "--scan-id",
      scanId,
      ...(command === "fail-scan" ? ["--message=Synthetic failure."] : []),
      "--cost-json",
      payload,
    ]);
    const stored = await workbench(["get-scan", "--scan-id", scanId]);
    expect(stored["scan"]).toMatchObject({
      progress: { status: command === "fail-scan" ? "failed" : "canceled" },
      usage,
    });
  },
);
