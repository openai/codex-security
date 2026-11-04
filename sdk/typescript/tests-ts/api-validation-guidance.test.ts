import {
  chmod,
  cp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { describe, expect, spyOn, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";

import { PLUGIN_ROOT } from "./plugin-root.js";
import { shellEnvironmentReference } from "./support/api-client.js";
import { readKnowledgeBaseSnapshot } from "../src/knowledge-base.js";
import { createValidationFixtures } from "./support/validation.js";

describe("CodexSecurity finding validation", () => {
  const {
    actualLstat,
    assessment,
    validationEvents,
    validationClient,
    persistedValidationClient,
    temporaryDirectory,
  } = createValidationFixtures();

  test("invalidates cached validation when inline instructions change", async () => {
    let modelCalls = 0;
    let instructions = "Original standalone validation instructions.";
    const instructionPath = join(
      PLUGIN_ROOT,
      "references",
      "standalone-validation.md",
    );
    const actualReadFile = fsPromises.readFile;
    const readInstructions = spyOn(fsPromises, "readFile").mockImplementation(
      (async (...args: Parameters<typeof actualReadFile>) =>
        args[0] === instructionPath
          ? instructions
          : await actualReadFile(...args)) as typeof actualReadFile,
    );
    try {
      async function* events() {
        modelCalls += 1;
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const workflowId = await fixture.bindWorkflow("validation-instructions");
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect(await client.validate(request)).toEqual(first);
      expect(modelCalls).toBe(1);
      instructions = "Updated standalone validation instructions.";
      await client.validate(request);
      expect(modelCalls).toBe(2);
      expect(fixture.captured.prompt).toContain(instructions);
    } finally {
      readInstructions.mockRestore();
    }
  });

  test.each([true, false])(
    "reuses a validation only when bundled references are used (custom: %j)",
    async (custom) => {
      const pluginRoot = custom
        ? join(await temporaryDirectory(), "selected-plugin")
        : PLUGIN_ROOT;
      const reference = join(
        await temporaryDirectory(),
        "additional-guidance.md",
      );
      await writeFile(reference, "Original synthetic guidance.");
      if (custom) {
        await cp(PLUGIN_ROOT, pluginRoot, { recursive: true });
        await writeFile(
          join(pluginRoot, "references", "standalone-validation.md"),
          `Read the validation guidance at ${JSON.stringify(reference)}.\n`,
        );
      }
      let modelCalls = 0;
      async function* events() {
        modelCalls += 1;
        yield* validationEvents(
          JSON.stringify({
            ...assessment,
            report: await readFile(reference, "utf8"),
          }),
        );
      }
      const fixture = await persistedValidationClient(events, pluginRoot);
      await using client = fixture.client;
      const workflowId = await fixture.bindWorkflow(
        "additional-validation-reference",
      );
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect((await client.validate(request)).report).toBe(first.report);
      expect(modelCalls).toBe(custom ? 2 : 1);
      if (custom) {
        await writeFile(reference, "Updated synthetic guidance.");
        expect((await client.validate(request)).report).toBe(
          "Updated synthetic guidance.",
        );
        expect(modelCalls).toBe(3);
      }
      expect(fixture.captured.prompt).toContain(
        await readFile(
          join(pluginRoot, "references", "standalone-validation.md"),
          "utf8",
        ),
      );
    },
  );

  test("reads unchanged and updated system-configured validation instructions", async () => {
    const root = await temporaryDirectory("native-system-validation-");
    const instructions = join(root, "instructions.md");
    const nativeConfig = join(root, "config.toml");
    await writeFile(instructions, "Original synthetic system guidance.");
    await writeFile(
      nativeConfig,
      `model_instructions_file = ${JSON.stringify(instructions)}\n`,
    );
    let modelCalls = 0;
    async function* events() {
      modelCalls += 1;
      const configuration = parseToml(await readFile(nativeConfig, "utf8"));
      yield* validationEvents(
        JSON.stringify({
          ...assessment,
          report: await readFile(
            configuration["model_instructions_file"] as string,
            "utf8",
          ),
        }),
      );
    }
    const fixture = await persistedValidationClient(
      events,
      PLUGIN_ROOT,
      undefined,
      { ProgramData: root },
    );
    await using client = fixture.client;
    const workflowId = await fixture.bindWorkflow(
      "system-validation-instructions",
    );
    const nativePath =
      process.platform === "win32"
        ? join(root, "OpenAI", "Codex", "config.toml")
        : "/etc/codex/config.toml";
    const originalLstat = actualLstat;
    const nativeLookup = spyOn(fsPromises, "lstat").mockImplementation(((
      ...args: Parameters<typeof originalLstat>
    ) =>
      originalLstat(
        args[0] === nativePath ? nativeConfig : args[0],
        args[1],
      )) as typeof originalLstat);
    try {
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect((await client.validate(request)).report).toBe(first.report);
      expect(modelCalls).toBe(2);
      await writeFile(instructions, "Updated synthetic system guidance.");
      expect((await client.validate(request)).report).toBe(
        "Updated synthetic system guidance.",
      );
      expect(modelCalls).toBe(3);
    } finally {
      nativeLookup.mockRestore();
    }
  });

  test.each([
    { setting: "top-level", changed: true },
    { setting: "top-level", changed: false },
    { setting: "selected profile", changed: true },
    { setting: "selected profile", changed: false },
    { setting: "none", changed: false },
  ] as const)(
    "runs file-backed validation instructions through Codex, %p",
    async ({ setting, changed }) => {
      const instructions = join(await temporaryDirectory(), "instructions.md");
      await writeFile(instructions, "Original synthetic instructions.");
      let modelCalls = 0;
      async function* events() {
        modelCalls += 1;
        yield* validationEvents(
          JSON.stringify({
            ...assessment,
            report: await readFile(instructions, "utf8"),
          }),
        );
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      if (setting === "top-level") {
        client.config.codexOverrides!["model_instructions_file"] = instructions;
      } else if (setting === "selected profile") {
        client.config.codexOverrides!["profile"] = "selected";
        client.config.codexOverrides!["profiles"] = {
          selected: { model_instructions_file: instructions },
        };
      }
      const workflowId = await fixture.bindWorkflow("file-backed-validation");
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect(modelCalls).toBe(1);
      if (changed)
        await writeFile(instructions, "Updated synthetic instructions.");
      const second = await client.validate(request);
      expect(modelCalls).toBe(setting === "none" ? 1 : 2);
      expect(second.report).toBe(
        changed ? "Updated synthetic instructions." : first.report,
      );
      expect(
        resolveCodexProfile(fixture.captured.codex!.config as JsonObject)[
          "model_instructions_file"
        ],
      ).toBe(setting === "none" ? undefined : instructions);
    },
  );

  test.each([
    { modelFails: false, cleanupFails: true },
    { modelFails: true, cleanupFails: true },
    { modelFails: false, cleanupFails: false },
    { modelFails: true, cleanupFails: false },
  ])(
    "preserves the validation outcome when temporary knowledge cleanup fails: %p",
    async ({ modelFails, cleanupFails }) => {
      const modelError = new Error("Synthetic validation failure.");
      const cleanupError = new Error(
        "Synthetic temporary knowledge cleanup failure.",
      );
      async function* events() {
        if (modelFails) throw modelError;
        yield* validationEvents();
      }
      const fixture = await validationClient(events);
      await using client = fixture.client;
      const document = join(fixture.root, "knowledge.md");
      await writeFile(document, "Synthetic primary project guidance.");
      const actualRm = fsPromises.rm;
      let cleanupPath: string | undefined;
      const cleanupSpy = spyOn(fsPromises, "rm").mockImplementation(
        async (path, options) => {
          if (
            path ===
            fixture.captured.codex?.env?.["CODEX_SECURITY_KNOWLEDGE_BASE"]
          ) {
            cleanupPath = String(path);
            if (cleanupFails) throw cleanupError;
          }
          return await actualRm(path, options);
        },
      );
      try {
        const result = client.validate({
          ...fixture.options,
          knowledgeBasePaths: [document],
        });
        if (modelFails) await expect(result).rejects.toBe(modelError);
        else await expect(result).resolves.toMatchObject(assessment);
        expect(cleanupPath).toBeDefined();
        expect(await readFile(document, "utf8")).toBe(
          "Synthetic primary project guidance.",
        );
      } finally {
        cleanupSpy.mockRestore();
        if (cleanupPath !== undefined)
          await actualRm(cleanupPath, { recursive: true, force: true });
      }
    },
  );

  test.each([
    ["unchanged", false],
    ["modified", false],
    ["modified", true],
    ["renamed", true],
    ["deleted", true],
  ] as const)(
    "retains supplied knowledge context for workflow validation; change=%s, snapshot=%p",
    async (change, snapshot) => {
      let modelCalls = 0;
      const normalizedPaths: string[] = [];
      let fixture: Awaited<ReturnType<typeof persistedValidationClient>>;
      async function* events() {
        modelCalls += 1;
        const path =
          fixture.captured.codex?.env?.["CODEX_SECURITY_KNOWLEDGE_BASE"];
        expect(path).toBeDefined();
        normalizedPaths.push(path!);
        const files = await readdir(path!);
        const context = await readFile(join(path!, files[0]!), "utf8");
        yield* validationEvents(
          JSON.stringify({ ...assessment, report: context }),
        );
      }
      fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const document = join(fixture.root, "policy.md");
      await writeFile(document, "Original synthetic policy.");
      const workflowId = await fixture.bindWorkflow("knowledge-validation");
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
        knowledgeBasePaths: [document],
        ...(snapshot
          ? {
              knowledgeBaseSnapshot: await readKnowledgeBaseSnapshot([
                document,
              ]),
            }
          : {}),
      };
      const first = await client.validate(request);
      expect(first.report).toBe("Original synthetic policy.");
      expect(fixture.captured.prompt).toContain(
        shellEnvironmentReference("CODEX_SECURITY_KNOWLEDGE_BASE"),
      );
      expect(fixture.captured.prompt).not.toContain(
        "Original synthetic policy.",
      );
      const movedDocument = join(fixture.root, "moved-policy.md");
      if (change === "modified")
        await writeFile(document, "Updated synthetic policy.");
      else if (change === "renamed") await rename(document, movedDocument);
      else if (change === "deleted") await rm(document);
      const second = await client.validate(request);
      expect(modelCalls).toBe(change === "modified" && !snapshot ? 2 : 1);
      expect(second.report).toBe(
        change === "modified" && !snapshot
          ? "Updated synthetic policy."
          : first.report,
      );
      if (change === "renamed" || change === "deleted") {
        const fresh = await client.validate({
          ...request,
          finding: "Another synthetic candidate.",
        });
        expect(fresh.report).toBe(first.report);
        expect(modelCalls).toBe(2);
      }
      expect(normalizedPaths.every((path) => !existsSync(path))).toBe(true);
      if (change === "deleted") expect(existsSync(document)).toBe(false);
      else
        expect(
          await readFile(
            change === "renamed" ? movedDocument : document,
            "utf8",
          ),
        ).toBe(
          change === "modified" ? "Updated synthetic policy." : first.report,
        );
    },
  );

  test
    .skipIf(process.platform === "win32")
    .each(["workflow", "file-backed workflow", "no workflow"] as const)(
    "validates an ignored FIFO without requiring a cache snapshot: %s",
    async (mode) => {
      let modelCalls = 0;
      async function* events() {
        modelCalls += 1;
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const repository = fixture.options.repositoryPath;
      execFileSync("git", ["init", "-q", repository]);
      await writeFile(join(repository, ".gitignore"), "ignored-pipe\n");
      execFileSync(fixture.python, [
        "-c",
        "import os,sys; os.mkfifo(sys.argv[1])",
        join(repository, "ignored-pipe"),
      ]);
      const workflowId = await fixture.bindWorkflow(
        "unsupported-validation-snapshot",
      );
      if (mode === "file-backed workflow") {
        const instructions = join(fixture.root, "instructions.md");
        await writeFile(instructions, "Synthetic validation instructions.");
        client.config.codexOverrides!["model_instructions_file"] = instructions;
      }
      const request = {
        ...fixture.options,
        outputDir: undefined,
        ...(mode === "no workflow" ? {} : { workflowId }),
      };
      await client.validate(request);
      await client.validate(request);
      expect(modelCalls).toBe(2);
      expect(fixture.captured.prompt).toContain("Candidate finding");
    },
  );

  test
    .skipIf(process.platform === "win32" || process.geteuid?.() === 0)
    .each(["file", "directory"] as const)(
    "validates unreadable ignored cache entries: %s",
    async (kind) => {
      let modelCalls = 0;
      async function* events() {
        modelCalls += 1;
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const repository = fixture.options.repositoryPath;
      execFileSync("git", ["init", "-q", repository]);
      await writeFile(join(repository, ".gitignore"), "ignored-cache\n");
      const entry = join(repository, "ignored-cache");
      if (kind === "directory") {
        await mkdir(entry);
        await writeFile(join(entry, "cache.txt"), "Synthetic cache data.");
      } else await writeFile(entry, "Synthetic cache data.");
      const mode = (await stat(entry)).mode;
      const workflowId = await fixture.bindWorkflow(
        "unreadable-validation-cache",
      );
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      await chmod(entry, 0);
      try {
        expect(await client.validate(request)).toMatchObject(assessment);
        expect(await client.validate(request)).toMatchObject(assessment);
        expect(modelCalls).toBe(2);
      } finally {
        await chmod(entry, mode);
      }
      expect(await client.validate(request)).toMatchObject(assessment);
      expect(await client.validate(request)).toMatchObject(assessment);
      expect(modelCalls).toBe(3);
    },
  );

  test.each([
    "home",
    "output worktree",
    "output project configuration",
    "none",
  ] as const)("uses current native validation guidance: %s", async (scope) => {
    const stateRoot = await temporaryDirectory("native-validation-guidance-");
    if (scope === "output worktree" || scope === "output project configuration")
      execFileSync("git", ["init", "-q", stateRoot]);
    let fixture: Awaited<ReturnType<typeof persistedValidationClient>>;
    let guide: string | undefined;
    let modelCalls = 0;
    async function* events() {
      modelCalls += 1;
      expect(fixture.captured.codex?.env?.["CODEX_HOME"]).toBe(
        fixture.codexHome,
      );
      if (
        scope === "output worktree" ||
        scope === "output project configuration"
      )
        expect(
          relative(
            stateRoot,
            fixture.captured.thread!.workingDirectory!,
          ).startsWith(".."),
        ).toBe(false);
      yield* validationEvents(
        JSON.stringify({
          ...assessment,
          report:
            guide === undefined
              ? "Synthetic assessment."
              : scope === "output project configuration"
                ? parseToml(await readFile(guide, "utf8"))[
                    "developer_instructions"
                  ]
                : await readFile(guide, "utf8"),
        }),
      );
    }
    fixture = await persistedValidationClient(events, PLUGIN_ROOT, undefined, {
      CODEX_SECURITY_STATE_DIR: join(stateRoot, "state"),
    });
    await using client = fixture.client;
    guide =
      scope === "home"
        ? join(fixture.codexHome, "AGENTS.md")
        : scope === "output worktree"
          ? join(stateRoot, "AGENTS.md")
          : scope === "output project configuration"
            ? join(stateRoot, ".codex", "config.toml")
            : undefined;
    if (guide !== undefined) {
      await mkdir(dirname(guide), { recursive: true });
      await writeFile(
        guide,
        scope === "output project configuration"
          ? 'developer_instructions = "Original synthetic guidance."\n'
          : "Original synthetic guidance.",
      );
    }
    const workflowId = await fixture.bindWorkflow("native-validation-guidance");
    const request = {
      ...fixture.options,
      outputDir: undefined,
      workflowId,
    };
    const first = await client.validate(request);
    expect((await client.validate(request)).report).toBe(first.report);
    expect(modelCalls).toBe(guide === undefined ? 1 : 2);
    if (guide !== undefined) {
      await writeFile(
        guide,
        scope === "output project configuration"
          ? 'developer_instructions = "Updated synthetic guidance."\n'
          : "Updated synthetic guidance.",
      );
      expect((await client.validate(request)).report).toBe(
        "Updated synthetic guidance.",
      );
      expect(modelCalls).toBe(3);
    }
  });
});
