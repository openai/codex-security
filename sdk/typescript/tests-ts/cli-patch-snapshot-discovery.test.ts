import { expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  realpath,
  rename,
  unlink,
  writeFile,
  rm,
} from "node:fs/promises";
import { join } from "node:path";
import {
  repositoryGit,
  runGitRepositoryCommand,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
  completePatches,
  publicationRepository,
  resultWithFindings,
  runWorkflow,
  observeIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

async function initialize(root: string, file: string) {
  await mkdir(root, { recursive: true });
  const git = initializePatchGit(root);
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
    const outcome = await runIssuePatch(root, {
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
  const { outcome, launches, afterTurn } = await observeIssuePatch(
    root,
    async () => {
      const inner = await initialize(nested, "input.ts");
      inner("commit", "-m", "Synthetic new administration");
      operator = await operatorHook(nested, "input.ts");
      nestedHead = inner("rev-parse", "HEAD");
      nestedIndex = await readFile(join(nested, ".git", "index"));
      await writeFile(join(root, "app.ts"), "after\n");
    },
  );
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

function commitBaseline(directory: string) {
  const git = initializePatchGit(directory);
  git("add", ".");
  git("commit", "-m", "Synthetic baseline");
  return git;
}

test.each([
  { foreign: false, gitlink: false },
  { foreign: true, gitlink: false },
  { foreign: false, gitlink: true },
  { foreign: true, gitlink: true },
])(
  "patch discovery binds selected nested administration: %p",
  async ({ foreign, gitlink }) => {
    const root = await fixtures.create("patch-worktree-selected-");
    const nested = join(root, "source");
    await mkdir(nested);
    await writeFile(join(root, "outer.txt"), "before\n");
    await writeFile(join(nested, "app.ts"), "selected source\n");
    commitBaseline(root);

    const worktree = foreign
      ? await fixtures.create("patch-worktree-unselected-")
      : nested;
    if (foreign) await writeFile(join(worktree, "app.ts"), "foreign source\n");
    const git = commitBaseline(worktree);
    git("config", "core.worktree", worktree);
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
        "#!/bin/sh\nprintf effect > hook-effect\nprintf '\\0'\n",
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
    const outcome = await runIssuePatch(root, {
      onRepositoryCommand: (command, args, cwd, options) => {
        if (args[0] === "-C" && args[1] === nested && args.includes("ls-files"))
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

test("patch discovery does not execute a workspace fsmonitor rewritten by the model", async () => {
  const root = await fixtures.create("patch-fsmonitor-selected-");
  const output = await fixtures.create("patch-fsmonitor-output-");
  const nested = join(root, "source");
  const hook = join(nested, "monitor.cjs");
  const effect = join(output, "hook-effect");
  const script = (value: string) =>
    `require("node:fs").writeFileSync(${JSON.stringify(effect)}, ${JSON.stringify(value)});\nprocess.stdout.write("\\0");\n`;
  await mkdir(nested);
  await writeFile(join(root, "outer.txt"), "before\n");
  await writeFile(join(nested, "app.ts"), "selected source\n");
  await writeFile(hook, script("operator"));
  commitBaseline(root);
  const git = commitBaseline(nested);
  const commandPath = (path: string) =>
    JSON.stringify(path.replaceAll("\\", "/"));
  git(
    "config",
    "core.fsmonitor",
    `${commandPath(process.execPath)} ${commandPath(hook)}`,
  );

  git("ls-files", "--cached");
  expect(await readFile(effect, "utf8")).toBe("operator");
  await rm(effect);
  const head = git("rev-parse", "HEAD");
  const index = await readFile(join(nested, ".git", "index"));
  const nestedInventory: string[][] = [];
  let launches = 0;
  let beforeTurnEffect: string | undefined;
  const outcome = await runIssuePatch(root, {
    onRepositoryCommand: (command, args, cwd, options) => {
      if (args.includes(nested) && args.includes("ls-files"))
        nestedInventory.push([...args]);
      return runGitRepositoryCommand(command, args, cwd, options);
    },
    onCodex: async (args, streams) => {
      launches++;
      expect(
        args.some((arg) => arg.startsWith("permissions.codex_security_patch=")),
      ).toBe(false);
      expect(streams?.appServer?.permissions?.name).toBe(
        "codex_security_patch",
      );
      expect(streams?.appServer?.permissions?.readOnlyPaths).not.toContain(
        hook,
      );
      beforeTurnEffect = await readFile(effect, "utf8").catch(() => undefined);
      await rm(effect, { force: true });
      await writeFile(hook, script("model-rewritten"));
      await writeFile(join(root, "outer.txt"), "after\n");
      streams?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });

  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(launches).toBe(1);
  expect(nestedInventory).toEqual([]);
  expect(await readFile(effect, "utf8").catch(() => undefined)).toBeUndefined();
  expect(beforeTurnEffect).toBeUndefined();
  expect(await readFile(hook, "utf8")).toBe(script("model-rewritten"));
  expect(await readFile(join(root, "outer.txt"), "utf8")).toBe("after\n");
  expect(git("rev-parse", "HEAD")).toBe(head);
  expect(await readFile(join(nested, ".git", "index"))).toEqual(index);

  git("ls-files", "--cached");
  expect(await readFile(effect, "utf8")).toBe("model-rewritten");
});

test.each([
  ["scan", "checkout"],
  ["patch", "checkout"],
  ["patch", "inherited"],
])(
  "%s publication skips the %s fsmonitor during preflight and commit",
  async (command, source) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-publication-fsmonitor-");
    const effect = join(support, "callback");
    const hook = join(directory, "monitor.cjs");
    const script = (phase: string) =>
      `require("node:fs").writeFileSync(${JSON.stringify(effect)}, ${JSON.stringify(phase)}); process.stdout.write("\\0");`;
    await writeFile(hook, script("preflight"));
    git("add", "monitor.cjs");
    git("commit", "-m", "Synthetic filesystem monitor");
    const quoted = (path: string) => JSON.stringify(path.replaceAll("\\", "/"));
    const monitor = `${quoted(process.execPath)} ${quoted(hook)}`;
    git("config", "core.fsmonitor", monitor);
    const environment =
      source === "inherited"
        ? {
            GIT_CONFIG_PARAMETERS: `'core.fsmonitor'='${monitor.replaceAll("'", "'\\''")}'`,
            GIT_ALLOW_PROTOCOL: "file",
          }
        : {};
    git("status", "--porcelain");
    expect(await readFile(effect, "utf8")).toBe("preflight");
    await rm(effect);
    let beforeTurn: string | undefined;
    const result = await runWorkflow(
      command === "patch"
        ? ["patch", "Synthetic issue", "--create-pr", "--json"]
        : ["scan", directory, "--patch", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        result: resultWithFindings(["high"]),
        onCodex: async (args, output) => {
          beforeTurn = await readFile(effect, "utf8").catch(() => undefined);
          await rm(effect, { force: true });
          await writeFile(hook, script("publication"));
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          if (command === "scan") completePatches(args, output);
          else output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
        onRepositoryCommand: (tool, args, cwd, options) =>
          tool === "git"
            ? runGitRepositoryCommand(tool, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              })
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect([
      beforeTurn,
      await readFile(effect, "utf8").catch(() => undefined),
    ]).toEqual([undefined, undefined]);
    expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
  },
);
