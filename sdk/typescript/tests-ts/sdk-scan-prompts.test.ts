import { captureCli } from "./support/cli-run.js";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test, mock } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import { completedCodex, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting } from "./support/errors.js";
import {
  prepareKnowledgeBase,
  readKnowledgeBaseSnapshot,
} from "../src/knowledge-base.js";
import {
  restoreScanKnowledge,
  saveScanKnowledge,
  scanInputIdentity,
} from "../src/scan-inputs.js";
import { workbenchCommand } from "./support/workbench-command.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test("rerun recognizes unchanged context after the workbench serializes its recipe", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(scanDir, { mode: 0o700 });
  await writeFile(join(repository, "source.ts"), "// synthetic source\n");
  const document = join(root, "architecture.md");
  await writeFile(document, "Original architecture.");
  const scanInputs = scanInputIdentity(
    undefined,
    await readKnowledgeBaseSnapshot([document]),
  );
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const command = workbenchCommand(python!, join(root, "state"));
  const saved = await command(
    [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    JSON.stringify({
      recipe: {
        repository,
        target: { kind: "repository", paths: [] },
        mode: "standard",
        config: {},
        knowledgeBasePaths: [document],
        scanInputs,
      },
    }),
  );
  const stderr = captureCli(main, "stderr");
  const onTurn = mock();
  const code = await stderr.run(
    ["scans", "rerun", saved["scanId"] as string, "--json"],
    dependencies({
      currentDirectory: repository,
      onWorkbench: command,
      onTurn,
    }),
  );
  expect(code, stderr.text()).toBe(0);
  expect(onTurn).toHaveBeenCalledTimes(1);
  expect(stderr.text()).toContain("Starting a new scan");
  expect(stderr.text()).not.toContain("Changed inputs:");
});

test("a throwing rerun notice does not prevent the requested scan", async () => {
  const repository = await temporaryDirectory();
  const stdout = capture();
  const stderr = capture();
  const onTurn = mock();
  let attemptedNotice = false;
  const code = await main(
    ["scans", "rerun", "saved", "--json"],
    stdout.stream,
    {
      write(value) {
        if (String(value).includes("Starting a new scan")) {
          attemptedNotice = true;
          throw new Error("Synthetic diagnostic sink failure");
        }
        return stderr.stream.write(value);
      },
    },
    dependencies({
      currentDirectory: repository,
      onTurn,
      onWorkbench: async () => ({
        scanId: "saved",
        recipe: {
          repository,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          config: {},
        },
      }),
    }),
  );
  expect(attemptedNotice).toBe(true);
  expect(code, stderr.text()).toBe(0);
  expect(onTurn).toHaveBeenCalledTimes(1);
  expect(JSON.parse(stdout.text())).toHaveProperty("manifest");
});

test.skipIf(process.platform === "win32")(
  "saved knowledge preserves a POSIX backslash filename through capture and restoration",
  async () => {
    const root = await temporaryDirectory();
    const directory = join(root, "documents");
    const scanDir = join(root, "scan");
    await mkdir(directory);
    await mkdir(scanDir);
    await writeFile(
      join(directory, "architecture\\v1.md"),
      "Original architecture.",
    );
    const captured = await readKnowledgeBaseSnapshot([directory]);
    await saveScanKnowledge(scanDir, captured);
    const restored = await restoreScanKnowledge(
      scanDir,
      root,
      scanInputIdentity(undefined, captured),
    );
    const staged = await prepareKnowledgeBase(restored, undefined, root);
    try {
      expect(
        await readFile(join(staged.path, "0-architecture\\v1.md.txt"), "utf8"),
      ).toBe("Original architecture.");
    } finally {
      await staged.cleanup();
    }
  },
);

test("saved knowledge cannot stage documents outside its input directory", async () => {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  await mkdir(scanDir);
  const captured = {
    sources: [],
    protectedRoots: [],
    documents: { "../outside.txt": "Synthetic document." },
  };
  await saveScanKnowledge(scanDir, captured);
  await expect(
    restoreScanKnowledge(scanDir, root, scanInputIdentity(undefined, captured)),
  ).rejects.toThrow("plain filenames");
});

test("rerun identifies changed instructions and captures current knowledge for the new scan", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const document = join(root, "architecture.md");
  const prompt = join(root, "instructions.md");
  await writeFile(document, "Original architecture.");
  const scanInputs = scanInputIdentity(
    "Original instructions.",
    await readKnowledgeBaseSnapshot([document]),
  );
  await writeFile(document, "Current architecture.");
  await writeFile(prompt, "Current instructions.");
  let selected: unknown;
  const stderr = captureCli(main, "stderr");
  const code = await stderr.run(
    ["scans", "rerun", "saved", "--scan-prompt-file", prompt, "--json"],
    dependencies({
      currentDirectory: repository,
      onWorkbench: async () => ({
        scanId: "saved",
        recipe: {
          repository,
          target: { kind: "repository", paths: [] },
          mode: "deep",
          config: {},
          knowledgeBasePaths: [document],
          requiresScanPrompt: true,
          scanInputs,
        },
      }),
      onTurn: (_repository, options) => {
        selected = options;
      },
    }),
  );
  expect(code, stderr.text()).toBe(0);
  expect(selected).toMatchObject({
    parentScanId: "saved",
    scanPrompt: "Current instructions.",
    knowledgeBaseSnapshot: {
      documents: { "0-architecture.md.txt": "Current architecture." },
    },
  });
  expect(stderr.text()).toContain("Starting a new scan");
  expect(stderr.text()).toContain(
    "Changed inputs: scan instructions, knowledge base",
  );
});

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
    await using client = TestClient.withDependencies({
      environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
      prepareRuntime: async () => preparedRuntime(codexHome),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args, input) => {
        if (args[0] === "register-cli-scan") recipe = JSON.parse(input!).recipe;
        return mockWorkbench(args, input);
      },
      createCodex: completedCodex(root, "thread-1"),
    });
    await client.run(
      repository,
      scenario === "empty file" ? { scanPromptFile: file } : { scanPrompt },
    );
    expect(recipe).toBeDefined();
    const requiresInstructions = scenario === "instructions";
    const onRun = mock();
    const stderr = captureCli(main, "stderr");
    const exit = await stderr.run(
      ["scans", "rerun", "saved", "--json"],
      dependencies({
        currentDirectory: repository,
        onWorkbench: async () => ({ recipe: recipe! }),
        onRun,
      }),
    );
    expect(exit).toBe(requiresInstructions ? 2 : 0);
    expect(onRun.mock.calls.length > 0).toBe(!requiresInstructions);
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
    await using client = TestClient.withDependencies({
      environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
      prepareRuntime: rejecting("Runtime must not start"),
    });
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
  await using client = TestClient.withDependencies({
    environment: {
      CODEX_HOME: join(root, "ambient"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
  });
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
