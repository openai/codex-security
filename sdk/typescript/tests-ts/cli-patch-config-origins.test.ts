import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const included of [false, true]) {
  for (const mode of [
    "outside unchanged",
    "outside replaced",
    "inside shadow",
  ] as const) {
    test(`binds relative config origins to Git's setup directory (${mode}, included: ${included})`, async () => {
      const root = await fixtures.create("patch-config-origin-selected-");
      const support = await fixtures.create("patch-config-origin-support-");
      const outside = mode !== "inside shadow";
      const caller = outside
        ? await fixtures.create("patch-config-origin-caller-")
        : join(root, "runner");
      await mkdir(caller, { recursive: true });
      const setup = outside ? caller : root;
      const shadowDirectory = outside ? root : caller;
      const globalConfig = join(setup, "settings");
      const activeConfig = join(
        setup,
        included ? "included-settings" : "settings",
      );
      const shadowConfig = join(
        shadowDirectory,
        included ? "included-settings" : "settings",
      );
      const operatorHooks = join(support, "operator-hooks");
      const replacementHooks = join(caller, "replacement-hooks");
      const operatorEffect = join(support, "operator-effect");
      const replacementEffect = join(support, "replacement-effect");
      const scripts = [];
      for (const [directory, effect] of [
        [operatorHooks, operatorEffect],
        [replacementHooks, replacementEffect],
      ]) {
        await mkdir(directory!, { recursive: true });
        const path = join(directory!, "post-index-change");
        const shellPath = `'${effect!.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
        const contents = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
        await writeFile(path, contents, { mode: 0o755 });
        scripts.push({ path, contents });
      }
      const config = (hooks: string) =>
        `[core]\n hooksPath = ${JSON.stringify(hooks.replaceAll("\\", "/"))}\n`;
      const originalConfig = config(operatorHooks);
      if (included)
        await writeFile(globalConfig, "[include]\n path = included-settings\n");
      await writeFile(activeConfig, originalConfig);
      await writeFile(
        join(shadowDirectory, "settings"),
        "[synthetic]\n value = shadow\n",
      );
      if (included)
        await writeFile(shadowConfig, "[synthetic]\n value = shadow\n");
      await writeFile(join(root, "app.ts"), "selected source\n");
      await writeFile(join(caller, "note.txt"), "caller source\n");
      const initialize = (directory: string) => {
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("add", ".");
        git("commit", "-m", "Synthetic config-origin baseline");
        return git;
      };
      const git = initialize(root);
      const callerGit = outside ? initialize(caller) : undefined;
      const environment = {
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "settings",
        GIT_DIR: join(root, ".git"),
        GIT_WORK_TREE: root,
      };
      const selectedGit = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: caller,
          env: { ...process.env, ...environment },
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      expect(
        selectedGit("config", "--show-origin", "--get", "core.hooksPath"),
      ).toBe(
        `file:${included ? "included-settings" : "settings"}\t${operatorHooks.replaceAll("\\", "/")}`,
      );
      for (const hooks of [operatorHooks, replacementHooks]) {
        selectedGit(
          "-c",
          `core.hooksPath=${hooks}`,
          "update-index",
          "--assume-unchanged",
          join(root, "app.ts"),
        );
        selectedGit(
          "-c",
          `core.hooksPath=${hooks}`,
          "update-index",
          "--no-assume-unchanged",
          join(root, "app.ts"),
        );
      }
      expect(await readFile(operatorEffect, "utf8")).toContain("effect");
      expect(await readFile(replacementEffect, "utf8")).toContain("effect");
      await unlink(operatorEffect);
      await unlink(replacementEffect);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const callerHead = callerGit?.("rev-parse", "HEAD");
      const callerIndex = outside
        ? await readFile(join(caller, ".git", "index"))
        : undefined;
      let launches = 0;
      let controls: readonly string[] = [];
      let modelDirectory: string | undefined;
      let operatorBefore = "";
      const bookkeeping: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: caller,
          environment,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              launches > 0 &&
              args.some((arg) =>
                ["add", "read-tree", "update-index", "write-tree"].includes(
                  arg,
                ),
              )
            )
              bookkeeping.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
          onCodex: async (_args, output) => {
            launches++;
            controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
            modelDirectory = output?.appServer?.directory;
            operatorBefore = await readFile(operatorEffect, "utf8").catch(
              () => "",
            );
            if (mode !== "outside unchanged") {
              const target =
                mode === "outside replaced" ? activeConfig : shadowConfig;
              await writeFile(
                `${target}.replacement`,
                config(replacementHooks),
              );
              await rename(`${target}.replacement`, target);
            }
            if (!outside)
              await writeFile(
                join(caller, "note.txt"),
                "updated caller source\n",
              );
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(launches).toBe(1);
      expect(modelDirectory).toBe(caller);
      expect(controls).toContain(globalConfig);
      expect(controls).toContain(activeConfig);
      expect(controls).not.toContain(shadowConfig);
      const operatorAfter = await readFile(operatorEffect, "utf8").catch(
        () => "",
      );
      if (mode === "outside replaced") {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(outcome.stderr.replaceAll("\\", "/")).toContain(
          activeConfig.replaceAll("\\", "/"),
        );
        expect(bookkeeping).toEqual([]);
        expect(operatorAfter).toBe(operatorBefore);
        expect(await readFile(activeConfig, "utf8")).toBe(
          config(replacementHooks),
        );
      } else {
        if (outside) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "No patch was applied; 0 files changed",
          );
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files.sort()).toEqual(
            [
              relative(root, shadowConfig).replaceAll("\\", "/"),
              "runner/note.txt",
            ].sort(),
          );
        }
        expect(bookkeeping.length).toBeGreaterThan(0);
        expect(operatorAfter.length).toBeGreaterThan(operatorBefore.length);
        expect(await readFile(activeConfig, "utf8")).toBe(originalConfig);
      }
      expect(await readFile(replacementEffect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe(
        "selected source\n",
      );
      for (const { path, contents } of scripts)
        expect(await readFile(path, "utf8")).toBe(contents);
      if (outside) {
        expect(callerGit!("rev-parse", "HEAD")).toBe(callerHead!);
        expect(callerIndex!).toEqual(
          await readFile(join(caller, ".git", "index")),
        );
        expect(await readFile(join(caller, "note.txt"), "utf8")).toBe(
          "caller source\n",
        );
      }
    });
  }
}
