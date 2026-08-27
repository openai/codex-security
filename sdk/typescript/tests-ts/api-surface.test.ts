import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/index.js";
import { mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
const InternalCodexSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;

afterEach(fixtures.cleanup);

async function scanResponseSurface(runtimeOptions?: {
  surface: "cli" | "sdk";
}): Promise<{
  surface: string | undefined;
  threadSource: string | undefined;
}> {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  let codexOptions: CodexOptions | null = null;
  let threadOptions: ThreadOptions | null = null;

  const client = new InternalCodexSecurity(
    {},
    {
      environment: {},
      prepareRuntime: async () => preparedRuntime(codexHome),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (
        _options: unknown,
        args: readonly string[],
        input?: string,
      ) => mockWorkbench(args, input),
      createCodex: (options: CodexOptions) => {
        codexOptions = options;
        return {
          startThread: (options: ThreadOptions) => {
            threadOptions = options;
            return {
              id: null,
              async runStreamed() {
                await fixtures.copyCompletedScan(root);
                return { events: completedEvents() };
              },
            };
          },
        };
      },
    },
    runtimeOptions,
  );

  await client.run(repository);
  await client.close();
  return {
    surface: (
      (codexOptions as CodexOptions | null)?.config?.[
        "responses_api_metadata"
      ] as Record<string, string> | undefined
    )?.["codex_security_surface"],
    threadSource: (threadOptions as ThreadOptions | null)?.threadSource,
  };
}

describe("CodexSecurity Responses metadata", () => {
  test("SDK runtime scans use sdk metadata", async () => {
    expect(await scanResponseSurface()).toEqual({
      surface: "sdk",
      threadSource: "security_scan",
    });
  });

  test("CLI runtime scans use cli metadata instead of sdk metadata", async () => {
    expect(await scanResponseSurface({ surface: "cli" })).toEqual({
      surface: "cli",
      threadSource: "security_scan",
    });
  });
});
