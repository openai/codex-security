import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function initialize(directory: string) {
  const git = repositoryGit(directory);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  git("add", ".");
  git("commit", "-m", "Synthetic worktree baseline");
  return git;
}

test.each(
  [
    { foreign: false, configuration: "absolute" },
    { foreign: true, configuration: "absolute" },
    { foreign: false, configuration: "unset" },
    { foreign: false, configuration: "relative" },
  ].flatMap((configuration) =>
    [false, true].map((gitlink) => ({ ...configuration, gitlink })),
  ),
)(
  "patch discovery binds selected nested administration: %p",
  async ({ foreign, configuration, gitlink }) => {
    const root = await fixtures.create("patch-worktree-selected-");
    const nested = join(root, "source");
    await mkdir(nested);
    await writeFile(join(root, "outer.txt"), "before\n");
    await writeFile(join(nested, "app.ts"), "selected source\n");
    await initialize(root);

    const worktree = foreign
      ? await fixtures.create("patch-worktree-unselected-")
      : nested;
    if (foreign) await writeFile(join(worktree, "app.ts"), "foreign source\n");
    const git = await initialize(worktree);
    if (configuration !== "unset")
      git(
        "config",
        "core.worktree",
        configuration === "relative" ? ".." : worktree,
      );
    if (foreign) {
      await writeFile(join(worktree, "app.ts"), "foreign local edit\n");
      await writeFile(
        join(nested, ".git"),
        `gitdir: ${join(worktree, ".git")}\n`,
      );
    }
    const effect = join(worktree, "hook-effect");
    if (!gitlink && process.platform !== "win32") {
      const hook = join(worktree, ".git", "hooks", "synthetic-fsmonitor");
      await writeFile(
        hook,
        `#!/bin/sh\nprintf effect > ${JSON.stringify(effect)}\nprintf '\\0'\n`,
        {
          mode: 0o755,
        },
      );
      git("config", "core.fsmonitor", hook);
    }
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(worktree, ".git", "index"));
    const source = await readFile(join(worktree, "app.ts"));
    if (gitlink) {
      const parent = repositoryGit(root);
      parent("rm", "--cached", "source/app.ts");
      parent("update-index", "--add", "--cacheinfo", `160000,${head},source`);
      parent("commit", "-m", "Synthetic selected gitlink");
    }
    const selectedIndex = await readFile(join(root, ".git", "index"));
    await rm(effect, { force: true });
    const nestedInventory: string[][] = [];
    let launches = 0;
    let beforeTurnEffect: string | undefined;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: (command, args, cwd, options) => {
        const gitDirectory = args.indexOf("--git-dir");
        if (
          args.includes("ls-files") &&
          gitDirectory >= 0 &&
          resolve(args[gitDirectory + 1]!) === join(nested, ".git")
        )
          nestedInventory.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        beforeTurnEffect = await readFile(effect, "utf8").catch(
          () => undefined,
        );
        await writeFile(join(root, "outer.txt"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });

    expect(outcome.exitCode, outcome.stderr).toBe(foreign && gitlink ? 2 : 0);
    expect(launches).toBe(foreign && gitlink ? 0 : 1);
    if (foreign || !gitlink) expect(nestedInventory).toEqual([]);
    else expect(nestedInventory.length).toBeGreaterThan(0);
    expect(beforeTurnEffect).toBeUndefined();
    expect(
      await readFile(effect, "utf8").catch(() => undefined),
    ).toBeUndefined();
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(worktree, ".git", "index"))).toEqual(index);
    expect(await readFile(join(worktree, "app.ts"))).toEqual(source);
    expect(await readFile(join(root, ".git", "index"))).toEqual(selectedIndex);
    expect(await readFile(join(root, "outer.txt"), "utf8")).toBe(
      foreign && gitlink ? "before\n" : "after\n",
    );
    if (!foreign && !gitlink && process.platform !== "win32") {
      git("ls-files", "--cached");
      expect(await readFile(effect, "utf8")).toBe("effect");
    }
  },
);
