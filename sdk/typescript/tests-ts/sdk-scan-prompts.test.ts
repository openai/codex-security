import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();
afterEach(cleanup);

test.each([
  ["omitted", undefined],
  ["empty inline", ""],
  ["blank inline", " \n\t"],
  ["instructions", "Review the synthetic authorization boundary."],
  ["empty file", undefined],
] as const)(
  "SDK %s prompts require rerun instructions only when used",
  async (scenario, scanPrompt) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    const file = join(root, "empty.md");
    if (scenario === "empty file") await writeFile(file, " \n");
    let recipe: JsonObject | undefined;
    await using client = new TestClient(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "register-cli-scan")
            recipe = JSON.parse(input!).recipe;
          return mockWorkbench(args, input);
        },
        createCodex: () => ({
          startThread: () => ({
            id: "thread-1",
            async runStreamed() {
              await copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );
    await client.run(
      repository,
      scenario === "empty file" ? { scanPromptFile: file } : { scanPrompt },
    );
    expect(recipe).toBeDefined();
    const requiresInstructions = scenario === "instructions";
    let reran = false;
    const stderr = capture();
    const exit = await main(
      ["scans", "rerun", "saved", "--json"],
      capture().stream,
      stderr.stream,
      dependencies({
        currentDirectory: repository,
        onWorkbench: async () => ({ recipe: recipe! }),
        onRun: () => {
          reran = true;
        },
      }),
    );
    expect(exit).toBe(requiresInstructions ? 2 : 0);
    expect(reran).toBe(!requiresInstructions);
    expect(recipe?.["requiresScanPrompt"]).toBe(
      requiresInstructions ? true : undefined,
    );
    if (requiresInstructions)
      expect(stderr.text()).toContain("additional instructions");
  },
);

test.each([
  ["scanPromptFile", "scanPrompt"],
  ["validationPromptFile", "validationPrompt"],
  ["postScanPromptFile", "postScanPrompt"],
] as const)(
  "SDK %s uses the existing file protections and permits explicit external files",
  async (fileOption, inlineOption) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const external = join(root, "external");
    const linked = join(repository, "linked");
    await mkdir(repository);
    await mkdir(external);
    const file = join(external, "prompt.md");
    await writeFile(file, "Synthetic private instructions.");
    await symlink(
      external,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );
    await using client = new TestClient(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
        prepareRuntime: async () => {
          throw new Error("Runtime must not start");
        },
      },
    );
    for (const operation of ["preflight", "run"] as const) {
      await expect(
        client[operation](repository, { [fileOption]: external }),
      ).rejects.toThrow("Input files must be regular files");
      await expect(
        client[operation](repository, {
          [fileOption]: join(linked, "prompt.md"),
        }),
      ).rejects.toThrow(
        "Input files must not follow repository directory links",
      );
    }
    const preflight = await client.preflight(repository, {
      [fileOption]: file,
    });
    expect(preflight.mode).toBe("standard");
    expect(JSON.stringify(preflight)).not.toContain(
      "Synthetic private instructions",
    );
    await expect(
      client.preflight(repository, {
        [fileOption]: join(root, "missing.md"),
        [inlineOption]: "Explicit inline instructions.",
      }),
    ).resolves.toMatchObject({ mode: "standard" });
  },
);

test("SDK prompt files retain empty-file and deep-validation behavior", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const empty = join(root, "empty.md");
  const validation = join(root, "validation.md");
  await writeFile(empty, " \n");
  await writeFile(validation, "Validate the synthetic fixture.");
  await using client = new TestClient(
    {},
    {
      environment: {
        CODEX_HOME: join(root, "ambient"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
    },
  );
  await expect(
    client.preflight(repository, {
      scanPromptFile: empty,
      postScanPromptFile: empty,
    }),
  ).resolves.toMatchObject({ mode: "standard" });
  await expect(
    client.preflight(repository, { validationPromptFile: empty }),
  ).rejects.toThrow("The validation prompt must not be empty");
  await expect(
    client.preflight(repository, {
      mode: "deep",
      validationPromptFile: validation,
    }),
  ).rejects.toThrow("Custom validation is not supported for Deep scans");
});
