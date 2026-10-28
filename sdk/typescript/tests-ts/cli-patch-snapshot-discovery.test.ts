import { afterEach, expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  realpath,
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

async function initialize(root: string, file: string) {
  await mkdir(root, { recursive: true });
  const git = repositoryGit(root);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  await writeFile(join(root, file), "before\n");
  git("add", ".");
  return git;
}

async function operatorHook(root: string, file: string) {
  const git = repositoryGit(root);
  const effects = await fixtures.create("patch-snapshot-hook-");
  const effect = join(effects, "effect");
  const hook = join(root, ".git", "hooks", "post-index-change");
  const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
  const contents = `#!/bin/sh\nprintf effect > ${shellPath}\n`;
  await writeFile(hook, contents, { mode: 0o755 });
  git("update-index", "--assume-unchanged", file);
  git("update-index", "--no-assume-unchanged", file);
  expect(await readFile(effect, "utf8")).toBe("effect");
  await unlink(effect);
  return { hook, contents, effect };
}

for (const transition of [
  "HEAD gitlink staged for deletion",
  "HEAD gitlink replaced by ordinary files with a new embedded descendant",
  "HEAD ordinary files replaced by an index gitlink",
  "unborn HEAD with staged ordinary files",
] as const) {
  test(`patch discovery matches its snapshot for ${transition}`, async () => {
    const root = await fixtures.create("patch-snapshot-discovery-");
    const git = await initialize(root, "app.ts");
    const source = join(root, "source");
    const unborn = transition === "unborn HEAD with staged ordinary files";
    const ordinary =
      unborn ||
      transition === "HEAD ordinary files replaced by an index gitlink";
    if (ordinary) {
      await mkdir(source);
      await writeFile(join(source, "input.ts"), "before\n");
      git("add", "source/input.ts");
      if (!unborn) git("commit", "-m", "Synthetic ordinary source baseline");
    }
    const inner = await initialize(source, "input.ts");
    inner("commit", "-m", "Synthetic nested baseline");
    const nested = [source];
    let selected: string | undefined;
    let expectedGitlinks: string[];
    if (transition === "HEAD gitlink staged for deletion") {
      git("add", "source");
      git("commit", "-m", "Synthetic gitlink baseline");
      git("rm", "--cached", "source");
      selected = source;
      expectedGitlinks = ["source"];
    } else if (
      transition ===
      "HEAD gitlink replaced by ordinary files with a new embedded descendant"
    ) {
      git("add", "source");
      git("commit", "-m", "Synthetic gitlink baseline");
      const support = await fixtures.create("patch-snapshot-administration-");
      await rename(join(source, ".git"), join(support, "administration"));
      git("rm", "--cached", "source");
      git("add", "source");
      await rename(join(support, "administration"), join(source, ".git"));
      selected = join(source, "newrepo");
      const descendant = await initialize(selected, "nested.ts");
      descendant("commit", "-m", "Synthetic embedded descendant baseline");
      nested.push(selected);
      expectedGitlinks = ["source/newrepo"];
    } else if (!unborn) {
      git("rm", "--cached", "source/input.ts");
      git("add", "source");
      selected = source;
      expectedGitlinks = ["source"];
    } else expectedGitlinks = [];

    const operator = await operatorHook(root, "app.ts");
    const head = git("rev-parse", "--revs-only", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const nestedStates = await Promise.all(
      nested.map(async (directory) => ({
        directory,
        head: repositoryGit(directory)("rev-parse", "HEAD"),
        index: await readFile(join(directory, ".git", "index")),
      })),
    );
    const sourceAdministration = await realpath(join(source, ".git"));
    const selectedAdministration =
      selected === undefined
        ? undefined
        : await realpath(join(selected, ".git"));
    const snapshots: string[] = [];
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: async (command, args, cwd, options) => {
        const output = await runGitRepositoryCommand(
          command,
          args,
          cwd,
          options,
        );
        if (cwd === root && args.length === 1 && args[0] === "write-tree")
          snapshots.push(output.trim());
        return output;
      },
      onCodex: async (_args, output) => {
        launches++;
        const protectedPaths = output?.appServer?.permissions?.readOnlyPaths;
        expect(protectedPaths).toBeDefined();
        if (selectedAdministration !== undefined)
          expect(protectedPaths).toContain(selectedAdministration);
        if (selected !== source)
          expect(protectedPaths).not.toContain(sourceAdministration);
        expect(await readFile(join(root, ".git", "index"))).toEqual(index);
        await writeFile(join(root, "app.ts"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(snapshots.length).toBeGreaterThanOrEqual(2);
    for (const tree of snapshots) {
      const gitlinks = git("ls-tree", "-r", "-z", tree)
        .split("\0")
        .filter((entry) => entry.startsWith("160000 "))
        .map((entry) => entry.slice(entry.indexOf("\t") + 1));
      expect(gitlinks).toEqual(expectedGitlinks);
    }
    expect(git("rev-parse", "--revs-only", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    expect(await readFile(join(source, "input.ts"), "utf8")).toBe("before\n");
    expect(await readFile(operator.hook, "utf8")).toBe(operator.contents);
    expect(await readFile(operator.effect, "utf8")).toBe("effect");
    for (const state of nestedStates) {
      expect(repositoryGit(state.directory)("rev-parse", "HEAD")).toBe(
        state.head,
      );
      expect(await readFile(join(state.directory, ".git", "index"))).toEqual(
        state.index,
      );
    }
  });
}

test("patch discovery refuses new reachable administration before snapshot bookkeeping", async () => {
  const root = await fixtures.create("patch-snapshot-new-administration-");
  const git = await initialize(root, "app.ts");
  await mkdir(join(root, "source"));
  await writeFile(join(root, "source", "input.ts"), "ordinary source\n");
  git("add", ".");
  git("commit", "-m", "Synthetic ordinary source baseline");
  const head = git("rev-parse", "HEAD");
  const index = await readFile(join(root, ".git", "index"));
  const nested = join(root, "source", "newrepo");
  let nestedHead: string | undefined;
  let nestedIndex: Buffer | undefined;
  let operator: Awaited<ReturnType<typeof operatorHook>> | undefined;
  const afterTurn: string[][] = [];
  let launches = 0;
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: root,
    onRepositoryCommand: (command, args, cwd, options) => {
      if (launches > 0) afterTurn.push([...args]);
      return runGitRepositoryCommand(command, args, cwd, options);
    },
    onCodex: async (_args, output) => {
      launches++;
      const inner = await initialize(nested, "input.ts");
      inner("commit", "-m", "Synthetic new administration");
      operator = await operatorHook(nested, "input.ts");
      nestedHead = inner("rev-parse", "HEAD");
      nestedIndex = await readFile(join(nested, ".git", "index"));
      await writeFile(join(root, "app.ts"), "after\n");
      output?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(2);
  expect(launches).toBe(1);
  expect(outcome.stderr).toContain(
    "Git metadata outside the pre-patch administration directories",
  );
  expect(
    afterTurn.filter(
      (args) => args.includes("add") || args.includes("write-tree"),
    ),
  ).toEqual([]);
  expect(afterTurn.filter((args) => args.includes(nested))).toEqual([]);
  expect(git("rev-parse", "HEAD")).toBe(head);
  expect(await readFile(join(root, ".git", "index"))).toEqual(index);
  expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
  expect(await readFile(join(root, "source", "input.ts"), "utf8")).toBe(
    "ordinary source\n",
  );
  expect(nestedHead).toBeDefined();
  expect(nestedIndex).toBeDefined();
  expect(repositoryGit(nested)("rev-parse", "HEAD")).toBe(nestedHead!);
  expect(nestedIndex!).toEqual(await readFile(join(nested, ".git", "index")));
  expect(operator).toBeDefined();
  expect(await readFile(operator!.hook, "utf8")).toBe(operator!.contents);
  expect(await readFile(operator!.effect).catch(() => null)).toBeNull();
});
