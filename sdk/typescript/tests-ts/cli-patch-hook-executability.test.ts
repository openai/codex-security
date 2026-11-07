import { afterEach, expect, test } from "bun:test";
import {
  chmod,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const mode of [
  "edit inactive file",
  "replace inactive file",
  "activate permissions",
  "replace with executable",
  "overlapping configuration",
] as const) {
  test.skipIf(process.platform === "win32")(
    `patch preserves Unix hook executability: ${mode}`,
    async () => {
      const root = await fixtures.create("patch-hook-executability-");
      const support = await fixtures.create(
        "patch-hook-executability-support-",
      );
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const source = join(root, "app.ts");
      const hook = join(root, "post-index-change");
      const effect = join(support, "effect");
      const shellPath = `'${effect.replaceAll("'", "'\\''")}'`;
      const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
      const configuration = "[synthetic]\n value = original\n";
      const original =
        mode === "overlapping configuration" ? configuration : script;
      await writeFile(source, "before\n");
      await writeFile(hook, original, { mode: 0o644 });
      git("add", ".");
      git("commit", "-m", "Synthetic inactive hook baseline");
      const operator = join(support, "post-index-change");
      await writeFile(operator, script, { mode: 0o755 });
      git(
        "-c",
        `core.hooksPath=${support}`,
        "update-index",
        "--assume-unchanged",
        "app.ts",
      );
      git(
        "-c",
        `core.hooksPath=${support}`,
        "update-index",
        "--no-assume-unchanged",
        "app.ts",
      );
      expect(await readFile(effect, "utf8")).toContain("effect");
      await unlink(effect);
      git("config", "core.hooksPath", ".");
      if (mode === "overlapping configuration")
        git("config", "include.path", "../post-index-change");
      expect((await stat(hook)).mode & 0o111).toBe(0);
      git("update-index", "--assume-unchanged", "app.ts");
      git("update-index", "--no-assume-unchanged", "app.ts");
      expect(await readFile(effect).catch(() => null)).toBeNull();
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const config = await readFile(join(root, ".git", "config"));
      let launches = 0;
      let protectedPaths: readonly string[] = [];
      const afterTurn: string[][] = [];
      const changed =
        mode === "overlapping configuration"
          ? "[synthetic]\n value = changed\n"
          : `${script}# Synthetic source edit\n`;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (launches > 0) afterTurn.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            launches++;
            protectedPaths =
              output?.appServer?.permissions?.readOnlyPaths ?? [];
            await writeFile(source, "after\n");
            if (mode === "activate permissions") {
              await chmod(hook, 0o755);
            } else if (mode === "edit inactive file") {
              await writeFile(hook, changed);
            } else {
              await writeFile(`${hook}.replacement`, changed, {
                mode: mode === "replace with executable" ? 0o755 : 0o644,
              });
              await rename(`${hook}.replacement`, hook);
            }
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(launches).toBe(1);
      expect(protectedPaths).toContain(join(root, ".git"));
      if (mode === "overlapping configuration") {
        expect(protectedPaths).toContain(hook);
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location",
        );
        expect(afterTurn).toEqual([]);
      } else {
        expect(protectedPaths).not.toContain(hook);
        if (
          mode === "activate permissions" ||
          mode === "replace with executable"
        ) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain("Git hook became accessible");
          expect(afterTurn).toEqual([]);
          expect((await stat(hook)).mode & 0o111).not.toBe(0);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files).toEqual([
            "app.ts",
            "post-index-change",
          ]);
          expect(afterTurn.some((args) => args.includes("write-tree"))).toBe(
            true,
          );
          expect((await stat(hook)).mode & 0o111).toBe(0);
        }
      }
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(await readFile(hook, "utf8")).toBe(
        mode === "activate permissions" ? original : changed,
      );
      expect(await readFile(source, "utf8")).toBe("after\n");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, ".git", "config"))).toEqual(config);
      expect(await readFile(operator, "utf8")).toBe(script);
    },
  );
}
