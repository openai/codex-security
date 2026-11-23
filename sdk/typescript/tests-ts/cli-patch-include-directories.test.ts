import { expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
  chmod,
  readlink,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import { capturePatchGitControls } from "../src/patch-git-controls.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  fixSavedFinding,
  publicationRepository,
  patchDirectories,
  directoryLinkType,
  initializePatchGit,
  runSavedPublication,
  observeIssuePatch,
} from "./cli-patch-fixtures.js";
import { execFileSync, spawnSync } from "node:child_process";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";

const fixtures = patchDirectories();

function readGitState(root: string) {
  return Promise.all(
    ["HEAD", "refs/heads/main", "index", "config"].map((file) =>
      readFile(join(root, ".git", file)),
    ),
  );
}

function configFailure(root: string, ...args: string[]) {
  const result = spawnSync("git", ["config", "--includes", ...args], {
    cwd: root,
    encoding: "utf8",
  });
  expect(result.status).toBe(128);
  return result.stderr.trim();
}

for (const mutation of [
  "directory",
  "file",
  "retarget",
  "fixed-directory",
] as const) {
  test(`retains include roles when optional storage is prepared: ${mutation}`, async () => {
    const repository = await fixtures.create("patch-include-storage-");
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    const target = join(repository, "cache-data");
    const alias = join(repository, "cache");
    await mkdir(target);
    await symlink(target, alias, directoryLinkType);
    git(
      "config",
      mutation === "fixed-directory"
        ? "include.path"
        : "includeIf.onbranch:future-branch.path",
      "../cache/objects",
    );
    git("config", "lfs.storage", "../cache");
    const controls = await capturePatchGitControls(
      repository,
      async (_root, checkout, args, options) =>
        runGitRepositoryCommand("git", args, checkout, options),
    );
    expect(controls!.snapshotStoragePaths).toEqual([]);
    expect(controls!.modelOnlyReadOnlyPaths).toContain(join(target, "objects"));
    const objects = join(target, "objects");
    if (mutation === "file")
      await writeFile(objects, "[core]\n filemode = false\n");
    else if (mutation === "retarget") {
      const replacement = await fixtures.create(
        "patch-include-storage-replacement-",
      );
      await rm(alias, { recursive: true });
      await symlink(replacement, alias, directoryLinkType);
    } else await mkdir(objects);
    if (mutation === "directory") await controls!.validate();
    else
      await expect(controls!.validate()).rejects.toThrow(
        "changed location during the patch",
      );
  });
}

for (const mode of [
  "ordinary edit",
  "rename directory",
  "remove directory",
  "replace directory",
  "becomes config file",
  "active directory",
] as const) {
  test(`preserves Git's directory include behavior: ${mode}`, async () => {
    const root = await fixtures.create("patch-include-directory-");
    const git = initializePatchGit(root);
    const directory = join(root, "src");
    const source = join(directory, "app.ts");
    await mkdir(directory);
    await writeFile(source, "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic conditional directory include");
    git(
      "config",
      `includeIf.onbranch:${mode === "active directory" ? "main" : "future-branch"}.path`,
      "../src",
    );
    const state = await readGitState(root);
    let nativeFailure = "";
    if (mode === "active directory") {
      nativeFailure = configFailure(root, "--get-regexp", "^includeif");
      expect(nativeFailure).not.toBe("");
    } else {
      expect(git("config", "--includes", "--get-regexp", "^includeif")).toBe(
        "includeif.onbranch:future-branch.path ../src",
      );
    }
    const replacement = "[synthetic]\n value = now-a-config-file\n";
    const { outcome, launches, afterTurn, controls } = await observeIssuePatch(
      root,
      async () => {
        await writeFile(source, "after\n");
        if (
          mode === "becomes config file" ||
          mode === "rename directory" ||
          mode === "replace directory"
        ) {
          await rename(directory, join(root, "retained-src"));
          if (mode === "becomes config file")
            await writeFile(directory, replacement);
          if (mode === "replace directory") {
            await mkdir(directory);
            await writeFile(source, "replacement source\n");
          }
        }
        if (mode === "remove directory")
          await rm(directory, { recursive: true });
      },
    );
    if (mode === "active directory") {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(launches).toBe(0);
      for (const line of nativeFailure.split(/\r?\n/u))
        expect(outcome.stderr).toContain(line);
      expect(afterTurn).toEqual([]);
      expect(await readFile(source, "utf8")).toBe("before\n");
    } else {
      expect(launches).toBe(1);
      expect(controls).toContain(join(root, ".git"));
      expect(controls).not.toContain(directory);
      expect(controls).not.toContain(source);
      if (mode !== "becomes config file") {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout).files).toEqual([
          ...(mode === "rename directory" || mode === "replace directory"
            ? ["retained-src/app.ts"]
            : []),
          "src/app.ts",
        ]);
        expect(afterTurn.length).toBeGreaterThan(0);
        if (mode === "rename directory" || mode === "replace directory")
          expect(
            await readFile(join(root, "retained-src", "app.ts"), "utf8"),
          ).toBe("after\n");
        if (mode === "remove directory" || mode === "rename directory")
          await expect(readFile(source)).rejects.toHaveProperty(
            "code",
            "ENOENT",
          );
        else
          expect(await readFile(source, "utf8")).toBe(
            mode === "replace directory" ? "replacement source\n" : "after\n",
          );
      } else {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(afterTurn).toEqual([]);
        expect(
          await readFile(join(root, "retained-src", "app.ts"), "utf8"),
        ).toBe("after\n");
        expect(await readFile(directory, "utf8")).toBe(replacement);
        expect(
          git(
            "-c",
            `includeIf.onbranch:main.path=${directory}`,
            "config",
            "--get",
            "synthetic.value",
          ),
        ).toBe("now-a-config-file");
      }
    }
    expect(await readGitState(root)).toEqual(state);
  });
}

test.each([
  ["local", false],
  ["conditional local", false],
  ["global through a checkout config", false],
  ["global through a checkout link", false],
  ["inside checkout", true],
  ["global", true],
] as const)("patch checks active Git includes: %s", async (source, allowed) => {
  const repository = await fixtures.create("patch-include-repository-");
  const operator = await fixtures.create("patch-include-operator-");
  const global = join(operator, "global.gitconfig");
  const target = join(
    source === "inside checkout" ? repository : operator,
    "included.config",
  );
  const git = initializePatchGit(repository);
  await writeFile(join(repository, "app.txt"), "before\n");
  git("add", "app.txt");
  git("commit", "-m", "Synthetic include baseline");
  git("config", "--file", target, "synthetic.probe", "fixture-value");

  if (source === "global through a checkout config") {
    const intermediate = join(repository, "project.gitconfig");
    git("config", "--file", intermediate, "include.path", target);
    git("config", "--file", global, "include.path", intermediate);
  } else if (source === "global through a checkout link") {
    const alias = join(repository, "settings");
    await symlink(operator, alias, directoryLinkType);
    git(
      "config",
      "--file",
      global,
      "include.path",
      join(alias, "included.config"),
    );
  } else if (source === "global") {
    git("config", "--file", global, "include.path", target);
  } else {
    git(
      "config",
      source === "conditional local"
        ? "includeIf.onbranch:main.path"
        : "include.path",
      target,
    );
  }

  const environment = { GIT_CONFIG_GLOBAL: global, GIT_CONFIG_NOSYSTEM: "1" };
  expect(
    await runGitRepositoryCommand(
      "git",
      ["config", "--includes", "--get", "synthetic.probe"],
      repository,
      { environment },
    ),
  ).toBe("fixture-value");
  const { outcome, launches } = await observeIssuePatch(
    repository,
    () => writeFile(join(repository, "app.txt"), "after\n"),
    environment,
  );
  expect(outcome.exitCode, outcome.stderr).toBe(allowed ? 0 : 2);
  expect(launches).toBe(allowed ? 1 : 0);
  if (!allowed)
    expect(outcome.stderr).toContain("outside the selected Git roots");
});

test.skipIf(process.platform === "win32")(
  "rejects an inaccessible conditional include made writable before publication activates its branch",
  async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const blocked = join(directory, "control");
    const include = join(blocked, "config");
    const effect = join(directory, "hook-effect");
    await writeFile(join(directory, ".gitignore"), "control/\nhook-effect\n");
    git("add", ".");
    git("commit", "-m", "Synthetic ignored controls");
    await mkdir(blocked);
    await writeFile(include, "# Synthetic inactive configuration.\n");
    git(
      "config",
      "includeIf.onbranch:codex-security/patch-scan-1.path",
      "../control/config",
    );
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    const remoteRefs = git("ls-remote", remote);
    await chmod(blocked, 0o000);
    try {
      // The native read succeeds because the publication branch is not active yet.
      expect(git("config", "--includes", "--list")).toContain(
        "includeif.onbranch:codex-security/patch-scan-1.path",
      );
      let launches = 0;
      const bookkeeping: string[][] = [];
      const publication: string[][] = [];
      const outcome = await runSavedPublication(directory, {
        onCodex: fixSavedFinding(directory, async () => {
          launches++;
          await chmod(blocked, 0o700);
          const hooks = join(blocked, "hooks");
          await mkdir(hooks);
          await writeFile(include, `[core]\n hooksPath = ${hooks}\n`);
          const hook = join(hooks, "pre-commit");
          await writeFile(
            hook,
            "#!/bin/sh\nprintf 'activated\\n' >> hook-effect\n",
          );
          await chmod(hook, 0o755);
        }),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") {
            if (launches > 0) publication.push([...args]);
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          }
          if (
            launches > 0 &&
            args.some((value) =>
              [
                "add",
                "read-tree",
                "write-tree",
                "update-index",
                "switch",
                "commit",
                "push",
              ].includes(value),
            )
          )
            bookkeeping.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Git conditional include became accessible during the patch",
      );
      expect(launches).toBe(1);
      expect(bookkeeping).toEqual([]);
      expect(publication).toEqual([]);
      expect(
        await readFile(effect, "utf8").catch(() => undefined),
      ).toBeUndefined();
      expect(git("branch", "--show-current")).toBe("main");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
      expect(git("ls-remote", remote)).toBe(remoteRefs);
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(await readFile(include, "utf8")).toContain("hooksPath");
    } finally {
      await chmod(blocked, 0o700);
    }
  },
);

for (const blocker of ["missing", "ordinary file"] as const) {
  test.skipIf(process.platform === "win32").each([false, true])(
    `preserves unresolved include traversal through ${blocker} (activated: %p)`,
    async (activate) => {
      const root = await fixtures.create("patch-unresolved-include-");
      const support = await fixtures.create(
        "patch-unresolved-include-support-",
      );
      const git = initializePatchGit(root);
      const source = join(root, "app.ts");
      const unavailable = join(root, "unavailable");
      await writeFile(source, "[synthetic]\n value = before\n");
      if (blocker === "ordinary file")
        await writeFile(unavailable, "ordinary source\n");
      git("add", ".");
      git("commit", "-m", "Synthetic unresolved include baseline");
      git("config", "include.path", "../unavailable/../app.ts");
      expect(git("config", "--includes", "--list")).not.toContain(
        "synthetic.value",
      );
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const config = await readFile(join(root, ".git", "config"));
      // Exercise the supported Node CLI runtime with native Git path lookups.
      const program = `
import { execFileSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(support))};
const root = ${JSON.stringify(root)};
const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], {cwd: repository, input: options?.input, env: {...process.env, ...(options?.indexFile === undefined ? {} : {GIT_INDEX_FILE: options.indexFile}), ...options?.environment}}).toString(options?.encoding ?? "utf8"));
if (!controls) throw new Error("Synthetic repository was not discovered.");
if (${activate}) {
  if (${blocker === "ordinary file"}) await rm(${JSON.stringify(unavailable)});
  await mkdir(${JSON.stringify(unavailable)});
}
await writeFile(${JSON.stringify(source)}, "[synthetic]\\n value = after\\n");
const bookkeeping = [];
let error;
let files = [];
try {
  await controls.validate();
  const stage = (args) => {
    bookkeeping.push(args);
    return execFileSync("git", args, {cwd: root, env: {...process.env, GIT_INDEX_FILE: ${JSON.stringify(join(support, "snapshot-index"))}}}).toString().trim();
  };
  stage(["read-tree", "HEAD"]);
  stage(["--literal-pathspecs", "add", "--all"]);
  const tree = stage(["write-tree"]);
  files = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", "HEAD", tree], {cwd: root}).toString().split("\\0").filter(Boolean);
} catch (failure) { error = failure.message; }
process.stdout.write(JSON.stringify({paths: controls.readOnlyPaths, error, bookkeeping, files}));
`;
      const result = JSON.parse(
        execFileSync("node", ["--input-type=module", "-e", program], {
          encoding: "utf8",
        }),
      ) as {
        paths: string[];
        error?: string;
        bookkeeping: string[][];
        files: string[];
      };
      expect(result.paths).not.toContain(source);
      if (activate) {
        expect(result.error).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(result.bookkeeping).toEqual([]);
      } else {
        expect(result.error).toBeUndefined();
        expect(result.bookkeeping.length).toBeGreaterThan(0);
        expect(result.files).toEqual(["app.ts"]);
        if (blocker === "ordinary file")
          expect(await readFile(unavailable, "utf8")).toBe("ordinary source\n");
      }
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, ".git", "config"))).toEqual(config);
      expect(await readFile(source, "utf8")).toBe(
        "[synthetic]\n value = after\n",
      );
    },
  );
}

for (const mode of [
  "unchanged inactive",
  "inactive becomes accessible",
  "active",
] as const) {
  test(`preserves native conditional include behavior for a symlink loop: ${mode}`, async () => {
    const root = await fixtures.create("patch-include-loop-");
    const support = await fixtures.create("patch-include-loop-support-");
    const git = initializePatchGit(root);
    await writeFile(join(root, "app.ts"), "before\n");
    await writeFile(join(root, ".gitignore"), "control-loop\n");
    git("add", ".");
    git("commit", "-m", "Synthetic conditional include baseline");
    const hook = join(root, ".git", "hooks", "post-index-change");
    const effect = join(support, "hook-effect");
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
    await writeFile(hook, script, { mode: 0o755 });
    git("update-index", "--assume-unchanged", "app.ts");
    git("update-index", "--no-assume-unchanged", "app.ts");
    expect(await readFile(effect, "utf8")).toContain("effect");
    await unlink(effect);
    const loop = join(root, "control-loop");
    await symlink(loop, loop, directoryLinkType);
    const link = await readlink(loop);
    const include = join(loop, "included");
    git(
      "config",
      `includeIf.onbranch:${mode === "active" ? "main" : "future-branch"}.path`,
      "../control-loop/included",
    );
    const state = await readGitState(root);
    // Git for Windows ignores this unresolved junction include; Unix reports ELOOP.
    const nativeRejectsLoop = mode === "active" && process.platform !== "win32";
    let nativeFailure = "";
    if (nativeRejectsLoop) {
      nativeFailure = configFailure(root, "--list");
      expect(nativeFailure).toContain("control-loop/included");
    } else {
      expect(git("config", "--includes", "--list")).toContain(
        `includeif.onbranch:${mode === "active" ? "main" : "future-branch"}.path=../control-loop/included`,
      );
    }
    let effectsBefore = "";
    const { outcome, launches, afterTurn } = await observeIssuePatch(
      root,
      async (output) => {
        expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
          include,
        );
        effectsBefore = await readFile(effect, "utf8").catch(() => "");
        if (mode === "inactive becomes accessible") {
          await unlink(loop);
          await mkdir(loop);
          await writeFile(include, "[synthetic]\n value = accessible\n");
        }
        await writeFile(join(root, "app.ts"), "after\n");
      },
    );
    const effectsAfter = await readFile(effect, "utf8").catch(() => "");
    if (
      mode === "unchanged inactive" ||
      (mode === "active" && !nativeRejectsLoop)
    ) {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readlink(loop)).toBe(link);
      expect(effectsAfter.length).toBeGreaterThan(effectsBefore.length);
    } else if (mode === "inactive becomes accessible") {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(launches).toBe(1);
      expect(outcome.stderr).toContain(
        "Git conditional include became accessible during the patch",
      );
      expect(afterTurn).toEqual([]);
      expect(effectsAfter).toBe(effectsBefore);
      expect(await readFile(include, "utf8")).toBe(
        "[synthetic]\n value = accessible\n",
      );
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(launches).toBe(0);
      expect(outcome.stderr).toContain(nativeFailure);
      expect(await readlink(loop)).toBe(link);
      expect(effectsAfter).toBe("");
    }
    expect(await readGitState(root)).toEqual(state);
    expect(await readFile(hook, "utf8")).toBe(script);
    expect(await readFile(join(root, "app.ts"), "utf8")).toBe(
      nativeRejectsLoop ? "before\n" : "after\n",
    );
  });
}

for (const role of ["hook", "conditional include"] as const) {
  // These fixtures use the Unix symlink-loop behavior of executable entries.
  test
    .skipIf(process.platform === "win32")
    .each(["directory", "missing"] as const)(
    `unavailable ${role} can become an ordinary %s entry`,
    async (transition) => {
      const root = await fixtures.create("patch-unavailable-transition-");
      const git = initializePatchGit(root);
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
      const { outcome, launches, afterTurn, controls } =
        await observeIssuePatch(root, async () => {
          await unlink(unavailable);
          if (transition === "directory") {
            await mkdir(unavailable);
            await writeFile(
              join(unavailable, "ordinary.txt"),
              "ordinary data\n",
            );
          }
          await writeFile(source, "after\n");
        });
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
