import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const role of ["hook", "conditional include"] as const) {
  // These fixtures use the Unix symlink-loop behavior of executable entries.
  test
    .skipIf(process.platform === "win32")
    .each(["directory", "missing"] as const)(
    `unavailable ${role} can become an ordinary %s entry`,
    async (transition) => {
      const root = await fixtures.create("patch-unavailable-transition-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const source = join(root, "app.ts");
      await writeFile(source, "before\n");
      await writeFile(
        join(root, ".gitignore"),
        "operator-hooks\nconditional-config\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic unavailable control baseline");
      let unavailable: string;
      if (role === "hook") {
        const hooks = join(root, "operator-hooks");
        await mkdir(hooks);
        unavailable = join(hooks, "pre-commit");
        git("config", "core.hooksPath", hooks);
      } else {
        unavailable = join(root, "conditional-config");
        git(
          "config",
          "includeIf.onbranch:future-branch.path",
          "../conditional-config",
        );
      }
      await symlink(unavailable, unavailable);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const config = await readFile(join(root, ".git", "config"));
      let launches = 0;
      let controls: readonly string[] = [];
      const afterTurn: string[][] = [];
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
            controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
            await unlink(unavailable);
            if (transition === "directory") {
              await mkdir(unavailable);
              await writeFile(
                join(unavailable, "ordinary.txt"),
                "ordinary data\n",
              );
            }
            await writeFile(source, "after\n");
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(controls).toContain(join(root, ".git"));
      expect(controls).not.toContain(unavailable);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(afterTurn.some((args) => args.includes("write-tree"))).toBe(true);
      expect(await readFile(source, "utf8")).toBe("after\n");
      if (transition === "directory")
        expect(await readFile(join(unavailable, "ordinary.txt"), "utf8")).toBe(
          "ordinary data\n",
        );
      else
        await expect(readFile(unavailable)).rejects.toHaveProperty(
          "code",
          "ENOENT",
        );
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, ".git", "config"))).toEqual(config);
    },
  );
}
