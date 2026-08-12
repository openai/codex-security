import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  completedEvents,
  createApiTestFixtures,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
const InternalCodexSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;

afterEach(async () => {
  await fixtures.cleanup();
});

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

function mockWorkbench(args: readonly string[]) {
  if (args[0] === "register-cli-scan") {
    return {
      scanId: "scan_example_001",
      targetId: "target_sha256_example",
      targetRevision: "deadbeef",
      scanDir: args[args.indexOf("--scan-dir") + 1],
      contract: { target: { allowedKinds: ["git_revision"] } },
    };
  }
  if (args[0] === "get-scan-feedback") {
    return {
      scanId: "scan_example_001",
      targetId: "target_sha256_example",
      falsePositives: [],
    };
  }
  return {};
}

async function scanResponseSurface(runtimeOptions?: {
  surface: "cli" | "sdk";
}): Promise<string | undefined> {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  let codexOptions: CodexOptions | null = null;

  const client = new InternalCodexSecurity(
    {},
    {
      environment: {},
      prepareRuntime: async () => preparedRuntime(codexHome),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options: unknown, args: readonly string[]) =>
        mockWorkbench(args),
      createCodex: (options: CodexOptions) => {
        codexOptions = options;
        return {
          startThread: () => ({
            id: null,
            async runStreamed() {
              await fixtures.copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        };
      },
    },
    runtimeOptions,
  );

  await client.run(repository);
  await client.close();
  return (
    (codexOptions as CodexOptions | null)?.config?.[
      "responses_api_metadata"
    ] as Record<string, string> | undefined
  )?.["codex_security_surface"];
}

describe("CodexSecurity Responses metadata", () => {
  test("SDK runtime scans use sdk metadata", async () => {
    expect(await scanResponseSurface()).toBe("sdk");
  });

  test("CLI runtime scans use cli metadata instead of sdk metadata", async () => {
    const surface = await scanResponseSurface({ surface: "cli" });
    expect(surface).toBe("cli");
    expect(surface).not.toBe("sdk");
  });
});
