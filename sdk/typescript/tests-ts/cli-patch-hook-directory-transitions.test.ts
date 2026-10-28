import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each(["add", "rename", "remove", "replace directory"] as const)(
  "ordinary hook-name directories support source changes: %s",
  async (operation) => {
    const root = await fixtures.create("patch-hook-directory-transition-");
    const retained = await fixtures.create("patch-retained-hook-directory-");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(root, "app.ts"), "before\n");
    const directory = join(root, "update");
    if (operation !== "add") {
      await mkdir(directory);
      await writeFile(join(directory, "module.ts"), "original source\n");
    }
    git("add", ".");
    git("commit", "-m", "Synthetic ordinary source baseline");
    git("config", "core.hooksPath", ".");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const config = await readFile(join(root, ".git", "config"));
    let launches = 0;
    let controls: readonly string[] = [];
    const afterTurn: string[][] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (launches > 0) afterTurn.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
        await writeFile(join(root, "app.ts"), "after\n");
        if (operation === "rename") {
          await rename(directory, join(root, "renamed-update"));
        } else if (operation === "remove") {
          await rm(directory, { recursive: true });
        } else {
          if (operation === "replace directory")
            await rename(directory, join(retained, "original-update"));
          await mkdir(directory);
          await writeFile(join(directory, "module.ts"), "new source\n");
        }
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches).toBe(1);
    expect(controls).toContain(join(root, ".git"));
    expect(controls).not.toContain(directory);
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout).files).toContain("app.ts");
    expect(afterTurn.some((args) => args.includes("write-tree"))).toBe(true);
    expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    if (operation === "rename") {
      expect(
        await readFile(join(root, "renamed-update", "module.ts"), "utf8"),
      ).toBe("original source\n");
    } else if (operation !== "remove") {
      expect(await readFile(join(directory, "module.ts"), "utf8")).toBe(
        "new source\n",
      );
    }
    if (operation === "replace directory")
      expect(
        await readFile(join(retained, "original-update", "module.ts"), "utf8"),
      ).toBe("original source\n");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(config);
  },
);
