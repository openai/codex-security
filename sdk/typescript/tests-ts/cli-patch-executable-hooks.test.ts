import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  readFile,
  rename,
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

for (const mode of ["existing native", "new native", "ordinary exe"] as const) {
  test.skipIf(mode === "ordinary exe" && process.platform === "win32")(
    `patch binds native executable hook selection: ${mode}`,
    async () => {
      const root = await fixtures.create("patch-executable-hook-");
      const support = await fixtures.create("patch-executable-hook-support-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(root, "app.ts"), "before\n");
      await writeFile(join(root, ".gitignore"), "synthetic-hooks\n0\n1\n");
      git("add", ".");
      git("commit", "-m", "Synthetic executable hook baseline");
      const hooks = join(root, "synthetic-hooks");
      await mkdir(hooks);
      git("config", "core.hooksPath", hooks);
      const suffix =
        process.platform === "win32" || mode === "ordinary exe" ? ".exe" : "";
      const hook = join(hooks, `post-index-change${suffix}`);
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const effect = join(support, "hook-effect");
      const program = `require("node:fs").writeFileSync(${JSON.stringify(effect)}, "effect");\n`;
      await writeFile(join(root, "0"), program);
      await writeFile(join(root, "1"), program);
      await copyFile(node, hook);
      if (mode === "ordinary exe") {
        execFileSync(hook, ["1", "0"], { cwd: root });
        expect(await readFile(effect, "utf8")).toBe("effect");
        await unlink(effect);
      }
      git("update-index", "--assume-unchanged", "app.ts");
      git("update-index", "--no-assume-unchanged", "app.ts");
      if (mode === "ordinary exe")
        expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      else {
        expect(await readFile(effect, "utf8")).toBe("effect");
        await unlink(effect);
      }
      if (mode === "new native") await unlink(hook);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      let launches = 0;
      let protectedPaths: readonly string[] = [];
      const postTurnWrites: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              launches > 0 &&
              args.some((value) =>
                ["add", "read-tree", "update-index", "write-tree"].includes(
                  value,
                ),
              )
            )
              postTurnWrites.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            launches++;
            protectedPaths =
              output?.appServer?.permissions?.readOnlyPaths ?? [];
            await unlink(effect).catch(() => {});
            if (mode !== "new native")
              await rename(hook, join(hooks, "retired-binary"));
            await copyFile(node, hook);
            await writeFile(join(root, "app.ts"), "after\n");
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(launches).toBe(1);
      if (mode === "ordinary exe") {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(protectedPaths).not.toContain(hook);
        expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      } else {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          mode === "new native"
            ? "Git hook became accessible during the patch"
            : "Git configuration or hooks changed location during the patch",
        );
        if (mode === "existing native") expect(protectedPaths).toContain(hook);
        expect(postTurnWrites).toEqual([]);
      }
      expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}
