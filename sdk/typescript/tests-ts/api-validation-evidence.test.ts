import {
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";

import { PLUGIN_ROOT } from "./plugin-root.js";
import { gitText } from "./support/shell.js";
import { createValidationFixtures } from "./support/validation.js";

describe("CodexSecurity finding validation", () => {
  const {
    assessment,
    validationEvents,
    persistedValidationClient,
    temporaryDirectory,
  } = createValidationFixtures();

  async function registerValidationScan(
    fixture: Awaited<ReturnType<typeof persistedValidationClient>>,
    repository: string,
    environment: NodeJS.ProcessEnv,
  ): Promise<string> {
    const scanDir = join(fixture.root, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    const registration = await runWorkbench(
      { python: fixture.python, pluginRoot: PLUGIN_ROOT, environment },
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          repository,
          mode: "standard",
          target: { kind: "repository", paths: [] },
          config: {},
        }),
      ],
    );
    return registration["scanId"] as string;
  }

  test.each([
    "AGENTS.md",
    "REVIEW.md",
    ".codex/config.toml",
    "unrelated.txt",
    "unchanged",
  ] as const)(
    "rechecks native guidance created while cached evidence is fingerprinted: %s",
    async (scope) => {
      const stateRoot = await temporaryDirectory("validation-guidance-race-");
      execFileSync("git", ["init", "-q", stateRoot]);
      const guide = join(stateRoot, scope);
      let fixture: Awaited<ReturnType<typeof persistedValidationClient>>;
      let modelCalls = 0;
      async function* events() {
        modelCalls++;
        await writeFile(
          join(fixture.captured.thread!.workingDirectory!, "proof.bin"),
          Buffer.alloc(256 * 1024, 7),
        );
        yield* validationEvents(
          JSON.stringify({
            ...assessment,
            report: existsSync(guide)
              ? await readFile(guide, "utf8")
              : "Original assessment.",
          }),
        );
      }
      fixture = await persistedValidationClient(
        events,
        PLUGIN_ROOT,
        undefined,
        {
          CODEX_SECURITY_STATE_DIR: join(stateRoot, "state"),
        },
      );
      await using client = fixture.client;
      client.config.codexOverrides!["project_doc_fallback_filenames"] = [
        "REVIEW.md",
      ];
      let changeDuringEvidence = false;
      let changed = false;
      fixture.workbench.mockImplementation(async (options, args, input) => {
        const payload =
          args[0] === "finding-workflow" ? JSON.parse(input!) : undefined;
        const pending = runWorkbench(options, args, input);
        if (
          changeDuringEvidence &&
          !changed &&
          payload?.action === "source" &&
          payload.evidence === true
        ) {
          changed = true;
          if (scope !== "unchanged") {
            await mkdir(dirname(guide), { recursive: true });
            await writeFile(
              guide,
              scope === ".codex/config.toml"
                ? 'developer_instructions = "New native guidance."\n'
                : "New native guidance.\n",
            );
          }
        }
        return await pending;
      });
      const workflowId = await fixture.bindWorkflow(
        "native-guidance-during-evidence",
      );
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect(await client.validate(request)).toEqual(first);
      expect(modelCalls).toBe(1);
      changeDuringEvidence = true;
      const second = await client.validate(request);
      const nativeGuidance = !["unrelated.txt", "unchanged"].includes(scope);
      expect(changed).toBe(true);
      expect(modelCalls).toBe(nativeGuidance ? 2 : 1);
      expect(second.report).toBe(
        nativeGuidance ? (await readFile(guide, "utf8")).trim() : first.report,
      );
      const sameGuidance = await client.validate(request);
      expect(sameGuidance.report).toBe(second.report);
      expect(modelCalls).toBe(nativeGuidance ? 3 : 1);
    },
  );

  test.each([
    "unchanged",
    "source contents",
    "recorded contents",
    "recorded checkout",
  ] as const)(
    "rechecks %s after reading a saved validation assessment",
    async (change) => {
      let modelCalls = 0;
      async function* events() {
        modelCalls += 1;
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const repository = fixture.options.repositoryPath;
      const source = join(repository, "source.ts");
      await writeFile(source, "export const value = 'original';\n");
      const environment = {
        CODEX_SECURITY_STATE_DIR: fixture.stateDirectory,
      };
      const scanId =
        change === "source contents"
          ? undefined
          : await registerValidationScan(fixture, repository, environment);
      const workflowId = "cached-validation-recheck";
      await fixture.bindWorkflow(workflowId, environment);
      let readSavedAssessment = false;
      fixture.workbench.mockImplementation(async (options, args, input) => {
        const response = await runWorkbench(options, args, input);
        if (
          args[0] === "finding-workflow" &&
          JSON.parse(input!)["action"] === "get-review" &&
          response["review"] !== null
        ) {
          readSavedAssessment = true;
          if (change === "recorded checkout") {
            await rename(repository, join(fixture.root, "original-repository"));
            await mkdir(repository);
            await writeFile(source, "export const value = 'original';\n");
          } else if (change !== "unchanged") {
            await writeFile(source, "export const value = 'changed';\n");
          }
        }
        return response;
      });
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
        ...(scanId === undefined ? {} : { scanId }),
      };
      const first = await client.validate(request);
      if (change === "unchanged") {
        expect(await client.validate(request)).toEqual(first);
      } else {
        await expect(client.validate(request)).rejects.toThrow(
          change === "source contents"
            ? "Repository changed during validation"
            : change === "recorded contents"
              ? "Scan target contents changed"
              : "checkout path was replaced",
        );
      }
      expect(readSavedAssessment).toBe(true);
      expect(modelCalls).toBe(1);
    },
  );

  test.each([
    ["cached", "source contents", "unchanged"],
    ["cached", "recorded contents", "unchanged"],
    ["cached", "source contents", "changed"],
    ["cached", "recorded contents", "missing"],
    ["fresh", "source contents", "unchanged"],
    ["fresh", "recorded contents", "missing"],
  ] as const)(
    "rechecks %s validation %s after reading %s evidence",
    async (phase, change, evidence) => {
      let modelCalls = 0;
      async function* events() {
        modelCalls++;
        await writeFile(
          join(fixture.captured.thread!.workingDirectory!, "proof.txt"),
          "Synthetic evidence.\n",
        );
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const repository = fixture.options.repositoryPath;
      const source = join(repository, "source.ts");
      await writeFile(source, "export const value = 'original';\n");
      const environment = {
        CODEX_SECURITY_STATE_DIR: fixture.stateDirectory,
      };
      const scanId =
        change === "source contents"
          ? undefined
          : await registerValidationScan(fixture, repository, environment);
      const workflowId = "evidence-validation-recheck";
      await fixture.bindWorkflow(workflowId, environment);
      let changeDuringEvidence = false;
      let changed = false;
      let savedReviews = 0;
      fixture.workbench.mockImplementation(async (options, args, input) => {
        const payload =
          args[0] === "finding-workflow" ? JSON.parse(input!) : undefined;
        const changeNow =
          changeDuringEvidence &&
          !changed &&
          payload?.action === "source" &&
          payload.evidence === true;
        if (changeNow && evidence === "changed")
          await writeFile(
            join(payload.repository, "proof.txt"),
            "Changed evidence.\n",
          );
        if (changeNow && evidence === "missing")
          await rm(payload.repository, { recursive: true });
        const response = await runWorkbench(options, args, input);
        if (changeNow) {
          await writeFile(source, "export const value = 'changed';\n");
          changed = true;
        }
        if (payload?.action === "save-review") savedReviews++;
        return response;
      });
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
        ...(scanId === undefined ? {} : { scanId }),
      };
      const first = await client.validate(request);
      expect(await client.validate(request)).toEqual(first);
      expect(modelCalls).toBe(1);
      changeDuringEvidence = true;
      await expect(
        client.validate({
          ...request,
          ...(phase === "fresh" ? { finding: "Another candidate" } : {}),
        }),
      ).rejects.toThrow(
        change === "source contents"
          ? "Repository changed during validation"
          : "Scan target contents changed",
      );
      expect(changed).toBe(true);
      expect(modelCalls).toBe(phase === "fresh" ? 2 : 1);
      expect(savedReviews).toBe(1);
    },
  );

  test.each(["canonical", "repository alias"])(
    "validates an unchanged recorded Git target with %s tool paths",
    async (kind) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      const hostGit = Bun.which("git");
      expect(hostGit).not.toBeNull();
      const tools = join(root, "external-tools");
      await mkdir(tools);
      const selectedGit = join(
        tools,
        process.platform === "win32" ? "git.exe" : "git",
      );
      await symlink(await realpath(hostGit!), selectedGit);
      const alias = join(repository, "tools");
      await symlink(
        tools,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(join(repository, ".gitignore"), "tools\n");
      await writeFile(
        join(repository, "source.ts"),
        "export const value = 'original';\n",
      );
      gitText(["init", "--initial-branch=main"], { cwd: repository });
      gitText(
        [
          "-c",
          "user.name=Synthetic User",
          "-c",
          "user.email=synthetic@example.test",
          "add",
          ".",
        ],
        { cwd: repository },
      );
      gitText(
        [
          "-c",
          "user.name=Synthetic User",
          "-c",
          "user.email=synthetic@example.test",
          "commit",
          "-m",
          "Synthetic validation baseline",
        ],
        { cwd: repository },
      );
      const fixture = await persistedValidationClient(
        undefined,
        PLUGIN_ROOT,
        root,
        {
          PATH: kind === "canonical" ? tools : alias,
        },
      );
      await using client = fixture.client;
      const environment = {
        PATH: tools,
        CODEX_SECURITY_GIT: selectedGit,
        CODEX_SECURITY_STATE_DIR: fixture.stateDirectory,
      };
      const scanDir = join(root, "scan");
      await mkdir(scanDir, { mode: 0o700 });
      const registration = await runWorkbench(
        { python: fixture.python, pluginRoot: PLUGIN_ROOT, environment },
        [
          "register-cli-scan",
          "--repository",
          repository,
          "--scan-dir",
          scanDir,
          "--recipe-json",
          JSON.stringify({
            repository,
            mode: "standard",
            target: { kind: "repository", paths: [] },
            config: {},
          }),
        ],
      );
      const workflowId = "git-tool-validation";
      await fixture.bindWorkflow(workflowId, environment);
      const request = {
        ...fixture.options,
        outputDir: undefined,
        scanId: registration["scanId"] as string,
        workflowId,
      };
      const first = await client.validate(request);
      expect(await client.validate(request)).toEqual(first);
      expect(first.disposition).toBe(assessment.disposition);
      for (const [options] of fixture.workbench.mock.calls) {
        expect(options.environment?.["CODEX_SECURITY_GIT"]).toBe(selectedGit);
        expect(options.environment?.["PATH"]).toBe(tools);
      }
      expect(fixture.captured.codex?.env?.["CODEX_SECURITY_GIT"]).toBe(
        selectedGit,
      );
      expect(fixture.captured.codex?.env?.["PATH"]).toContain(tools);
    },
  );
});
