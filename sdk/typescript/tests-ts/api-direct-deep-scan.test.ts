import { mkdir, readFile, writeFile } from "node:fs/promises";
import { hash } from "node:crypto";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { copyCompletedScan } from "./plugin-root.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("Deep Scan uses the engine and retains SDK registration and finalization", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const commands: string[] = [];
  const parentTurn = mock(async () => {
    throw new Error("A parent model turn must not execute the Deep Scan.");
  });
  const started = mock();
  const client = TestClient.withDependencies({
    ...scanRuntimeDependencies(codexHome, scanDir),
    environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
    createCodex: () => ({
      startThread: () => ({ id: null, runStreamed: parentTurn }),
    }),
    runDeepScan: async function* (options) {
      expect(options.scanId).toBe("scan_example_001");
      expect(options.codexOptions.env).toMatchObject({
        CODEX_SECURITY_SCAN_ID: options.scanId,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        CODEX_SECURITY_REPOSITORY: repository,
      });
      await copyCompletedScan(root);
      const coveragePath = join(scanDir, "coverage.json");
      const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
      coverage.mode = "deep_repository";
      const coverageBytes = JSON.stringify(coverage);
      await writeFile(coveragePath, coverageBytes);
      const manifestPath = join(scanDir, "scan-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      const artifact = manifest.scan.artifacts.find(
        (entry: { path: string }) => entry.path === "coverage.json",
      );
      artifact.sha256 = hash("sha256", coverageBytes);
      await writeFile(manifestPath, JSON.stringify(manifest));
      yield* completedEvents("engine-session");
    },
    runWorkbench: async (_options, args, input) => {
      commands.push(args[0]!);
      return mockWorkbench(args, input);
    },
  });
  try {
    const result = await client.run(repository, {
      mode: "deep",
      onScanStarted: started,
    });
    expect(result.threadId).toBe("engine-session");
    expect(result.reportPath).toBe(join(scanDir, "report.md"));
    expect(parentTurn).not.toHaveBeenCalled();
    expect(started).toHaveBeenCalledTimes(1);
    expect(
      commands.filter((command) =>
        [
          "register-cli-scan",
          "set-scan-thread",
          "prepare-scan-completion",
          "complete-scan",
        ].includes(command),
      ),
    ).toEqual([
      "register-cli-scan",
      "set-scan-thread",
      "prepare-scan-completion",
      "complete-scan",
    ]);
  } finally {
    await client.close();
  }
});
