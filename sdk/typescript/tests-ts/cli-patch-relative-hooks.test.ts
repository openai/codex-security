import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  { mode: "default", outside: false, replace: false, rootHook: false },
  { mode: "relative", outside: false, replace: false, rootHook: false },
  { mode: "absolute", outside: false, replace: false, rootHook: false },
  { mode: "relative", outside: true, replace: false, rootHook: false },
  { mode: "relative", outside: false, replace: true, rootHook: false },
  { mode: "relative", outside: true, replace: false, rootHook: true },
  { mode: "relative", outside: true, replace: true, rootHook: true },
])(
  "binds $mode hooks to their execution worktree (root hook: $rootHook, outside cwd: $outside, replaced: $replace)",
  async ({ mode, outside, replace, rootHook }) => {
    const root = await fixtures.create("patch-hook-selected-");
    const foreign = await fixtures.create("patch-hook-unselected-");
    const support = await fixtures.create("patch-hook-support-");
    const nested = join(root, "nested");
    await mkdir(nested);
    const initialize = async (directory: string) => {
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic hook baseline");
      return git;
    };
    const nestedGit = await initialize(nested);
    const git = await initialize(root);
    const foreignGit = await initialize(foreign);
    const hookWorktree = rootHook ? root : nested;
    const hookGit = rootHook ? git : nestedGit;
    const hookDirectory =
      mode === "default"
        ? join(hookWorktree, ".git", "hooks")
        : mode === "relative"
          ? join(hookWorktree, "hooks")
          : join(support, "hooks");
    await mkdir(hookDirectory, { recursive: true });
    const hook = join(hookDirectory, "post-index-change");
    const effect = join(support, "hook-effect");
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const hookScript = (value: string) =>
      `#!/bin/sh\nprintf '${value}\\n' >> ${shellPath}\n`;
    await writeFile(hook, hookScript("operator"), { mode: 0o755 });
    if (mode !== "default")
      hookGit(
        "config",
        "core.hooksPath",
        mode === "relative" ? "hooks" : hookDirectory,
      );
    // All three paths identify a functional trusted hook before the patch runs.
    hookGit("update-index", "--assume-unchanged", "app.txt");
    hookGit("update-index", "--no-assume-unchanged", "app.txt");
    expect(await readFile(effect, "utf8")).toContain("operator");
    const rootHead = git("rev-parse", "HEAD");
    const nestedHead = nestedGit("rev-parse", "HEAD");
    const foreignHead = foreignGit("rev-parse", "HEAD");
    const rootIndex = await readFile(join(root, ".git", "index"));
    const nestedIndex = await readFile(join(nested, ".git", "index"));
    const foreignIndex = await readFile(join(foreign, ".git", "index"));
    const environment = outside
      ? { ...process.env, GIT_DIR: join(root, ".git"), GIT_WORK_TREE: root }
      : process.env;
    let launches = 0;
    let permissions:
      { name: string; readOnlyPaths: readonly string[] } | undefined;
    let beforeTurnEffects = "";
    const bookkeeping: string[][] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: outside ? foreign : root,
      environment,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (
          launches > 0 &&
          args.some((arg) =>
            ["add", "read-tree", "update-index", "write-tree"].includes(arg),
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
        permissions = output?.appServer?.permissions;
        beforeTurnEffects = await readFile(effect, "utf8");
        if (replace) {
          await rename(hook, join(support, "original-hook"));
          await writeFile(hook, hookScript("rewritten"), { mode: 0o755 });
        }
        await writeFile(join(nested, "app.txt"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches).toBe(1);
    expect(outcome.exitCode, outcome.stderr).toBe(replace ? 2 : 0);
    expect(permissions).toBeDefined();
    expect(permissions!.name).toBe("codex_security_patch");
    expect(
      permissions!.readOnlyPaths.some((path) => {
        const from = relative(path, hook);
        return (
          from !== ".." && !from.startsWith(`..${sep}`) && !isAbsolute(from)
        );
      }),
    ).toBe(true);
    const afterEffects = await readFile(effect, "utf8");
    if (replace) {
      expect(outcome.stderr).toContain(
        "Git configuration or hooks changed location during the patch",
      );
      expect(bookkeeping).toEqual([]);
      expect(afterEffects).toBe(beforeTurnEffects);
      expect(await readFile(hook, "utf8")).toBe(hookScript("rewritten"));
    } else {
      expect(afterEffects.length).toBeGreaterThan(beforeTurnEffects.length);
      expect(bookkeeping.length).toBeGreaterThan(0);
      expect(
        afterEffects
          .split("\n")
          .filter(Boolean)
          .every((line) => line === "operator"),
      ).toBe(true);
    }
    expect(git("rev-parse", "HEAD")).toBe(rootHead);
    expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
    expect(foreignGit("rev-parse", "HEAD")).toBe(foreignHead);
    expect(await readFile(join(root, ".git", "index"))).toEqual(rootIndex);
    expect(await readFile(join(nested, ".git", "index"))).toEqual(nestedIndex);
    expect(await readFile(join(foreign, ".git", "index"))).toEqual(
      foreignIndex,
    );
    expect(await readFile(join(root, "app.txt"), "utf8")).toBe("before\n");
    expect(await readFile(join(foreign, "app.txt"), "utf8")).toBe("before\n");
    expect(await readFile(join(nested, "app.txt"), "utf8")).toBe("after\n");
  },
);
