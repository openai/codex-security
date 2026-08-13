import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  completedEvents,
  createApiTestFixtures,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();

afterEach(cleanup);

const TestClient = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => CodexSecurity;

function preparedRuntime(codexHome: string): Record<string, unknown> {
  return {
    codexHome,
    plugin: {
      pluginRoot: PLUGIN_ROOT,
      marketplaceRoot: PLUGIN_ROOT,
      installedRoot: PLUGIN_ROOT,
      marketplaceName: "codex-security-sdk",
      name: "codex-security",
      version: "0.1.0",
    },
    environment: {},
    credentialsAvailable: true,
  };
}

function runWorkbench(_options: unknown, args: readonly string[]) {
  if (args[0] === "register-cli-scan") {
    return Promise.resolve({
      scanId: "scan_example_001",
      targetId: "target_sha256_example",
      targetRevision: "deadbeef",
      scanDir: args[args.indexOf("--scan-dir") + 1],
      contract: { target: { allowedKinds: ["git_revision"] } },
    });
  }
  if (args[0] === "get-scan-feedback") {
    return Promise.resolve({
      scanId: "scan_example_001",
      targetId: "target_sha256_example",
      falsePositives: [],
    });
  }
  return Promise.resolve({});
}

describe("completed scan follow-up instructions", () => {
  test.each([
    ["missing report", "report.md", undefined],
    ["partial report", "report.md", "# Incomplete draft\n"],
    ["invalid findings", "findings.json", "{invalid"],
    ["sealed nested artifact", "artifacts/worker.json", '{"partial":true}'],
  ] as const)(
    "restores completed scan artifacts damaged by post-scan instructions: %s",
    async (_scenario, artifact, replacement) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const codexHome = join(root, "codex-home");
      const scanDir = join(root, "scan");
      await mkdir(repository);
      await mkdir(codexHome);
      await mkdir(scanDir, { mode: 0o700 });
      let turns = 0;
      let original = Buffer.alloc(0);
      const client = new TestClient(
        {},
        {
          environment: {},
          prepareRuntime: async () => preparedRuntime(codexHome),
          resolvePluginPython: async () => "/managed/python",
          prepareOutputDir: async () => scanDir,
          repositoryRevision: async () => "deadbeef",
          runWorkbench,
          createCodex: () => ({
            startThread: () => ({
              id: "thread-1",
              async runStreamed() {
                turns += 1;
                if (turns === 1) {
                  await copyCompletedScan(root);
                  if (artifact.startsWith("artifacts/")) {
                    const artifactPath = join(scanDir, artifact);
                    await mkdir(dirname(artifactPath), { recursive: true });
                    await writeFile(artifactPath, '{"complete":true}\n');
                    const manifestPath = join(scanDir, "scan-manifest.json");
                    const manifest = JSON.parse(
                      await readFile(manifestPath, "utf8"),
                    );
                    manifest.scan.artifacts.push({
                      path: artifact,
                      sha256: createHash("sha256")
                        .update(await readFile(artifactPath))
                        .digest("hex"),
                      mediaType: "application/json",
                    });
                    await writeFile(manifestPath, JSON.stringify(manifest));
                  }
                  original = await readFile(join(scanDir, artifact));
                  return { events: completedEvents() };
                }
                const artifactPath = join(scanDir, artifact);
                if (replacement === undefined) await rm(artifactPath);
                else await writeFile(artifactPath, replacement);
                async function* failedEvents(): AsyncGenerator<ThreadEvent> {
                  yield {
                    type: "turn.failed",
                    error: { message: "Could not draft fixes." },
                  };
                }
                return { events: failedEvents() };
              },
            }),
          }),
        },
      );

      await expect(
        client.run(repository, { postScanPrompt: "Draft confirmed fixes." }),
      ).resolves.toMatchObject({ scanDir });
      expect(await readFile(join(scanDir, artifact))).toEqual(original);
      await client.close();
    },
  );
});
