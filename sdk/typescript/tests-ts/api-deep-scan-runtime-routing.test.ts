import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import type { CodexOptions } from "@openai/codex-sdk";
import type { DirectDeepScanOptions } from "../src/deep-scan.js";
import { TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  {
    name: "inherited Node override",
    dependencyNode: "configured runtime",
    runtimeNode: "configured runtime",
    route: "parent",
  },
  {
    name: "Node override supplied by the prepared runtime",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "prepared Node override replacing the dependency value",
    dependencyNode: "ambient runtime",
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "dependency Node override absent from the prepared runtime",
    dependencyNode: "unused runtime",
    runtimeNode: null,
    route: "direct",
  },
  {
    name: "no Node override",
    dependencyNode: null,
    runtimeNode: null,
    route: "direct",
  },
])("Deep Scan respects $name", async (scenario) => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const selectedNode =
    scenario.runtimeNode === null
      ? undefined
      : join(root, scenario.runtimeNode, "node");
  const runtimeEnvironment: Record<string, string> =
    selectedNode === undefined ? {} : { CODEX_MCP_NODE_PATH: selectedNode };
  const originalRuntimeEnvironment = { ...runtimeEnvironment };
  const parentTurn = mock(async () => {
    throw new Error("parent route reached");
  });
  const directRun = mock(async function* (options: DirectDeepScanOptions) {
    expect(options.codexOptions.env?.["CODEX_MCP_NODE_PATH"]).toBe(
      selectedNode,
    );
    throw new Error("direct route reached");
  });
  const createCodex = mock((options: CodexOptions) => {
    expect(options.apiKey).toBe("synthetic-routing-key");
    expect(options.env?.["CODEX_MCP_NODE_PATH"]).toBe(selectedNode);
    expect(options.env?.["CODEX_SECURITY_SCAN_DIR"]).toBe(scanDir);
    expect(options.config).toMatchObject({
      model: "gpt-6.1-sol",
      model_reasoning_effort: "high",
      features: { shell_tool: false },
    });
    return {
      startThread: () => ({ id: null, runStreamed: parentTurn }),
    };
  });
  const client = new TestClient(
    {
      codexOverrides: {
        model: "gpt-6.1-sol",
        model_reasoning_effort: "high",
        features: { shell_tool: false },
      },
    },
    {
      ...scanRuntimeDependencies(codexHome, scanDir),
      environment: {
        CODEX_API_KEY: "synthetic-routing-key",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        ...(scenario.dependencyNode === null
          ? {}
          : {
              CODEX_MCP_NODE_PATH: join(root, scenario.dependencyNode, "node"),
            }),
      },
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        environment: runtimeEnvironment,
      }),
      // Keep the host's Bun fallback and account advisory out of this check.
      supportsDirectDeepScan: async () => true,
      createCodex,
      runDeepScan: directRun,
    },
  );
  try {
    await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
      `${scenario.route} route reached`,
    );
    expect(createCodex).toHaveBeenCalledTimes(1);
    expect(parentTurn).toHaveBeenCalledTimes(
      scenario.route === "parent" ? 1 : 0,
    );
    expect(directRun).toHaveBeenCalledTimes(
      scenario.route === "direct" ? 1 : 0,
    );
    expect(runtimeEnvironment).toEqual(originalRuntimeEnvironment);
  } finally {
    await client.close();
  }
});
