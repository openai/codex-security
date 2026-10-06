import { createCliTest } from "./support/cli-run.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { runWorkbench } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(["standard", "deep"])(
  "%s scans save large post-scan prompts before starting Codex",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "state", "codex-home");
    await mkdir(repository);
    await mkdir(codexHome, { recursive: true });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const promptFile = join(root, "post-scan.md");
    const postScanPrompt =
      "Review the completed scan and its evidence.\n".repeat(10_000);
    expect(Buffer.byteLength(postScanPrompt)).toBeGreaterThan(256 * 1024);
    await writeFile(promptFile, postScanPrompt);
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      [
        "scan",
        repository,
        "--mode",
        mode,
        "--output-dir",
        join(root, "scan"),
        "--post-scan-prompt-file",
        promptFile,
        "--json",
      ],
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: throwing("Synthetic stop after registration"),
          }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic stop after registration");
    await rm(promptFile);
    const scans = (await command(["list-scans", "--repository", repository]))[
      "scans"
    ] as Array<{ scanId: string }>;
    expect(scans).toHaveLength(1);
    const saved = await command([
      "get-scan-recipe",
      "--scan-id",
      scans[0]!.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({ mode, postScanPrompt });
    expect(JSON.stringify(saved)).not.toContain(promptFile);
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
  },
);
