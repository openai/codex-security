import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);

test.each(["runtime", "sqlite override", "database override"] as const)(
  "workbench usage discovery uses the %s database with a separate caller home",
  async (source) => {
    const root = await fixtures.temporaryDirectory();
    const repository = join(root, "repository");
    const callerHome = join(root, "caller-home");
    const runtimeHome = join(root, "runtime-home");
    const overrideHome = join(root, "usage-state");
    const scanDir = join(root, "scan");
    await Promise.all(
      [repository, callerHome, runtimeHome, overrideHome, scanDir].map((path) =>
        mkdir(path, { mode: 0o700 }),
      ),
    );
    const expectedDatabase = join(
      source === "runtime" ? runtimeHome : overrideHome,
      "state_5.sqlite",
    );
    await writeFile(expectedDatabase, "synthetic state database location");
    const python = Bun.which(
      process.platform === "win32" ? "python" : "python3",
    )!;
    expect(python).not.toBeNull();
    let helperCalls = 0;
    let observedEnvironment:
      Parameters<typeof runWorkbench>[0]["environment"] | undefined;
    const client = new TestClient(
      { codexOverrides: { model: "unpriced-model" } },
      {
        environment: {
          CODEX_HOME: callerHome,
          CODEX_SQLITE_HOME: source === "sqlite override" ? overrideHome : "",
          CODEX_STATE_DB:
            source === "database override" ? expectedDatabase : "",
        },
        prepareRuntime: async () => preparedRuntime(runtimeHome),
        resolvePluginPython: async () => python,
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (
          options: Parameters<typeof runWorkbench>[0],
          args: readonly string[],
          input?: string,
        ) => {
          helperCalls += 1;
          expect(options.environment["CODEX_HOME"]).toBe(runtimeHome);
          expect(options.environment["CODEX_SQLITE_HOME"]).toBe(
            source === "sqlite override" ? overrideHome : "",
          );
          expect(options.environment["CODEX_STATE_DB"]).toBe(
            source === "database override" ? expectedDatabase : "",
          );
          observedEnvironment = options.environment;
          return mockWorkbench(args, input);
        },
        createCodex: () => {
          throw new Error("environment observed");
        },
      },
    );
    try {
      await expect(client.run(repository)).rejects.toThrow(
        "environment observed",
      );
      expect(helperCalls).toBeGreaterThan(0);
      const database = execFileSync(
        python,
        [
          "-c",
          "import sys; sys.path.insert(0, sys.argv[1]); from workbench_scan_usage import _codex_state_database; print(_codex_state_database())",
          join(PLUGIN_ROOT, "scripts"),
        ],
        {
          env: { ...process.env, ...observedEnvironment },
          encoding: "utf8",
        },
      ).trim();
      expect(database).toBe(expectedDatabase);
    } finally {
      await client.close();
    }
  },
);
