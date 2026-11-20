import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
  rm,
  readlink,
  symlink,
  chmod,
} from "node:fs/promises";
import { join } from "node:path";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";
import {
  runGitRepositoryCommand,
  runWorkflow,
  completePatches,
  patchRiskAssessment,
  publicationRepository,
  resultWithFindings,
  savedScan,
  patchDirectories,
  initializePatchGit,
  observeIssuePatch,
  patchArtifactFromPrompt,
  runIssuePatch,
  runPublicationCommand,
  runPublicationWorkflow,
} from "./cli-patch-fixtures.js";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = patchDirectories();

async function repository(prefix: string) {
  const root = await fixtures.create(prefix);
  const git = initializePatchGit(root);
  await writeFile(join(root, "app.ts"), "before\n");
  git("add", ".");
  git("commit", "-m", "Synthetic hook-entry baseline");
  return { root, git };
}

test.skipIf(process.platform === "win32")(
  "empty hooksPath follows native root entries without protecting checkout shadows",
  async () => {
    const { root, git } = await repository("patch-empty-hook-path-");
    const shadow = join(root, "post-index-change");
    await writeFile(shadow, "ordinary source\n");
    git("add", ".");
    git("commit", "-m", "Synthetic ordinary hook-name source");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    git("config", "core.hooksPath", "");
    const config = await readFile(join(root, ".git", "config"));
    const bundle = await fixtures.create("patch-empty-hook-node-");
    // Query native paths only: do not execute unknown hooks at the POSIX root.
    const program = `
import { execFileSync } from "node:child_process";
import { rename, writeFile } from "node:fs/promises";
import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(bundle))};
const root = ${JSON.stringify(root)};
const shadow = ${JSON.stringify(shadow)};
const nativeHook = execFileSync("git", ["rev-parse", "--git-path", "hooks/post-index-change"], {cwd: root}).toString().trim();
const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => {
  if (args.some((arg) => ["read-tree", "update-index", "add", "write-tree"].includes(arg)) && !args.includes("core.hooksPath=/dev/null"))
    throw new Error("The fixture must not execute filesystem-root hooks.");
  return execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], {cwd: repository, input: options?.input, env: {...process.env, ...(options?.indexFile === undefined ? {} : {GIT_INDEX_FILE: options.indexFile}), ...options?.environment}}).toString(options?.encoding ?? "utf8");
});
if (!controls) throw new Error("Synthetic repository was not discovered.");
await writeFile(shadow + ".replacement", "updated ordinary source\\n");
await rename(shadow + ".replacement", shadow);
let error;
try { await controls.validate(); } catch (failure) { error = failure.message; }
process.stdout.write(JSON.stringify({nativeHook, paths: controls.readOnlyPaths, error}));
`;
    const result = JSON.parse(
      execFileSync("node", ["--input-type=module", "-e", program], {
        encoding: "utf8",
      }),
    ) as {
      nativeHook: string;
      paths: string[];
      error?: string;
    };
    expect(result.nativeHook).toBe("/post-index-change");
    expect(result.paths).not.toContain(shadow);
    expect(result.error).toBeUndefined();
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(config);
    expect(await readFile(shadow, "utf8")).toBe("updated ordinary source\n");
  },
);

test.each([false, true])(
  "a regular hooksPath stays ordinary data until an executable entry appears (activated: %p)",
  async (activate) => {
    const { root, git } = await repository("patch-file-hook-path-");
    const source = join(root, "app.ts");
    const support = await fixtures.create("patch-file-hook-support-");
    const operatorHooks = join(support, "hooks");
    const effect = join(support, "effect");
    await mkdir(operatorHooks);
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
    await writeFile(join(operatorHooks, "post-index-change"), script, {
      mode: 0o755,
    });
    git(
      "-c",
      `core.hooksPath=${operatorHooks}`,
      "update-index",
      "--assume-unchanged",
      "app.ts",
    );
    git(
      "-c",
      `core.hooksPath=${operatorHooks}`,
      "update-index",
      "--no-assume-unchanged",
      "app.ts",
    );
    expect(await readFile(effect, "utf8")).toContain("effect");
    await unlink(effect);
    git("config", "core.hooksPath", "app.ts");
    expect(git("rev-parse", "--git-path", "hooks/post-index-change")).toBe(
      "app.ts/post-index-change",
    );
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const config = await readFile(join(root, ".git", "config"));
    const { outcome, launches, afterTurn, controls } = await observeIssuePatch(
      root,
      async () => {
        await writeFile(source, "after\n");
        if (activate) {
          await rename(source, join(root, "retained-app.ts"));
          await mkdir(source);
          await writeFile(join(source, "post-index-change"), script, {
            mode: 0o755,
          });
        }
      },
    );
    expect(launches).toBe(1);
    expect(controls).not.toContain(source);
    if (activate) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Git hook became accessible during the patch",
      );
      expect(afterTurn).toEqual([]);
      expect(await readFile(join(root, "retained-app.ts"), "utf8")).toBe(
        "after\n",
      );
      expect(await readFile(join(source, "post-index-change"), "utf8")).toBe(
        script,
      );
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(afterTurn.length).toBeGreaterThan(0);
      expect(await readFile(source, "utf8")).toBe("after\n");
    }
    expect(await readFile(effect).catch(() => null)).toBeNull();
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(config);
    expect(
      await readFile(join(operatorHooks, "post-index-change"), "utf8"),
    ).toBe(script);
  },
);

test.each([false, true])(
  "a directory named for a hook stays editable until replaced by an executable (activated: %p)",
  async (activate) => {
    const { root, git } = await repository("patch-directory-hook-entry-");
    const directory = join(root, "update");
    const source = join(directory, "module.ts");
    await mkdir(directory);
    await writeFile(source, "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic ordinary hook-name directory");
    const support = await fixtures.create("patch-directory-hook-support-");
    const effect = join(support, "effect");
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
    const operator = join(support, "update");
    await writeFile(operator, script, { mode: 0o755 });
    git("-c", `core.hooksPath=${support}`, "hook", "run", "update");
    expect(await readFile(effect, "utf8")).toBe("effect");
    await unlink(effect);
    git("config", "core.hooksPath", ".");
    expect(git("rev-parse", "--git-path", "hooks/update")).toBe("update");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const config = await readFile(join(root, ".git", "config"));
    const { outcome, launches, afterTurn, controls } = await observeIssuePatch(
      root,
      async () => {
        await writeFile(source, "after\n");
        if (activate) {
          await rename(directory, join(root, "retained-update"));
          await writeFile(directory, script, { mode: 0o755 });
        }
      },
    );
    expect(launches).toBe(1);
    expect(controls).toContain(join(root, ".git"));
    expect(controls).not.toContain(directory);
    expect(controls).not.toContain(source);
    if (activate) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Git hook became accessible during the patch",
      );
      expect(afterTurn).toEqual([]);
      expect(
        await readFile(join(root, "retained-update", "module.ts"), "utf8"),
      ).toBe("after\n");
      expect(await readFile(directory, "utf8")).toBe(script);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual(["update/module.ts"]);
      expect(afterTurn.length).toBeGreaterThan(0);
      expect(await readFile(source, "utf8")).toBe("after\n");
    }
    expect(await readFile(effect).catch(() => null)).toBeNull();
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(config);
    expect(await readFile(operator, "utf8")).toBe(script);
  },
);

test.each(["add", "rename", "remove", "replace directory"] as const)(
  "ordinary hook-name directories support source changes: %s",
  async (operation) => {
    const root = await fixtures.create("patch-hook-directory-transition-");
    const retained = await fixtures.create("patch-retained-hook-directory-");
    const git = initializePatchGit(root);
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
    const { outcome, launches, afterTurn, controls } = await observeIssuePatch(
      root,
      async () => {
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
      },
    );
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

// Exercise POSIX filesystem traversal through a symlink before "..".
test
  .skipIf(process.platform === "win32")
  .each(["actual-hook", "ordinary-shadow"])(
  "preserves physical symlink traversal when the model replaces %s",
  async (mutation) => {
    const root = await fixtures.create("patch-physical-hook-");
    const support = await fixtures.create("patch-physical-hook-support-");
    const hooks = join(root, "actual", "hooks");
    const actualHook = join(hooks, "post-index-change");
    const shadow = join(root, "hooks", "post-index-change");
    const effect = join(support, "hook-effect");
    const link = join(root, "link");
    await mkdir(join(root, "actual", "child"), { recursive: true });
    await mkdir(hooks);
    await mkdir(join(root, "hooks"));
    await symlink("actual/child", link);
    const shellPath = `'${effect.replaceAll("'", "'\\''")}'`;
    const script = (value: string) =>
      `#!/bin/sh\nprintf '${value}\\n' >> ${shellPath}\n`;
    await writeFile(actualHook, script("operator"), { mode: 0o755 });
    await writeFile(shadow, "ordinary source\n");
    await writeFile(join(root, "app.txt"), "before\n");
    const git = initializePatchGit(root);
    git("add", ".");
    git("commit", "-m", "Synthetic physical hook baseline");
    git("config", "core.hooksPath", "link/../hooks");
    expect(
      git("rev-parse", "--path-format=absolute", "--git-path", "hooks"),
    ).toBe(hooks);
    git("update-index", "--assume-unchanged", "app.txt");
    git("update-index", "--no-assume-unchanged", "app.txt");
    expect(await readFile(effect, "utf8")).toContain("operator");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const actualReplacement = mutation === "actual-hook";
    // Node resolves symlink/.. physically; Bun's realpath normalizes it lexically.
    const source = `
import { execFileSync } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(support))};
const root = ${JSON.stringify(root)};
const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => {
  return execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], { cwd: repository, input: options?.input, env: { ...process.env, ...(options?.indexFile === undefined ? {} : { GIT_INDEX_FILE: options.indexFile }), ...options?.environment } }).toString(options?.encoding ?? "utf8");
});
if (!controls) throw new Error("Synthetic repository was not discovered.");
const beforeTurnEffects = await readFile(${JSON.stringify(effect)}, "utf8");
const edited = ${JSON.stringify(actualReplacement ? actualHook : shadow)};
await rename(edited, ${JSON.stringify(join(support, "original-input"))});
await writeFile(edited, ${JSON.stringify(actualReplacement ? script("rewritten") : "edited ordinary source\n")}, { mode: ${actualReplacement ? 0o755 : 0o644} });
await writeFile(join(root, "app.txt"), "after\\n");
const bookkeeping = [];
let error;
let files = [];
try {
  await controls.validate();
  const stage = (args) => {
    bookkeeping.push(args);
    return execFileSync("git", args, { cwd: root, env: { ...process.env, GIT_INDEX_FILE: ${JSON.stringify(join(support, "snapshot-index"))} } }).toString().trim();
  };
  stage(["read-tree", "HEAD"]);
  stage(["--literal-pathspecs", "add", "--all"]);
  const tree = stage(["write-tree"]);
  files = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", "HEAD", tree], { cwd: root }).toString().split("\\0").filter(Boolean);
} catch (failure) { error = failure.message; }
process.stdout.write(JSON.stringify({ paths: controls.readOnlyPaths, error, bookkeeping, beforeTurnEffects, files }));
`;
    const result = JSON.parse(
      execFileSync("node", ["--input-type=module", "-e", source], {
        encoding: "utf8",
      }),
    ) as {
      paths: string[];
      error?: string;
      bookkeeping: string[][];
      beforeTurnEffects: string;
      files: string[];
    };
    expect(result.paths).toContain(actualHook);
    expect(result.paths).not.toContain(shadow);
    const afterEffects = await readFile(effect, "utf8");
    if (actualReplacement) {
      expect(result.error).toContain(
        "Git configuration or hooks changed location during the patch",
      );
      expect(result.bookkeeping).toEqual([]);
      expect(afterEffects).toBe(result.beforeTurnEffects);
      expect(await readFile(actualHook, "utf8")).toBe(script("rewritten"));
      expect(await readFile(shadow, "utf8")).toBe("ordinary source\n");
    } else {
      expect(result.error).toBeUndefined();
      expect(result.files).toEqual(["app.txt", "hooks/post-index-change"]);
      expect(result.bookkeeping.length).toBeGreaterThan(0);
      expect(afterEffects.length).toBeGreaterThan(
        result.beforeTurnEffects.length,
      );
      expect(
        afterEffects
          .split("\n")
          .filter(Boolean)
          .every((line) => line === "operator"),
      ).toBe(true);
      expect(await readFile(actualHook, "utf8")).toBe(script("operator"));
      expect(await readFile(shadow, "utf8")).toBe("edited ordinary source\n");
    }
    expect(await readlink(link)).toBe("actual/child");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, "app.txt"), "utf8")).toBe("after\n");
  },
);

test.each([
  ...["unchanged", "stage unrelated", "rewrite selected"].flatMap((hook) =>
    [false, true].map((assess) => ({
      hook,
      assess,
      lostResult: false,
      scope: "root",
    })),
  ),
  ...["stage unrelated", "rewrite selected"].map((hook) => ({
    hook,
    assess: true,
    lostResult: true,
    scope: "root",
  })),
  ...["root", "src"].map((scope) => ({
    hook: "post-index stage unrelated",
    assess: true,
    lostResult: false,
    scope,
  })),
])(
  "checks the committed tree after a $hook hook, assessment=$assess, lost result=$lostResult, scope=$scope",
  async ({ hook, assess, lostResult, scope }) => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "other.ts"), "original unrelated\n");
    // The captured tree already contains the filtered contents. A native hook's
    // Git process must not reselect checkout-provided commands during commit.
    git("config", "filter.snapshot.clean", "git hash-object --stdin");
    git("config", "filter.snapshot.required", "true");
    const global = join(
      await fixtures.create("publication-operator-config-"),
      "gitconfig",
    );
    git(
      "config",
      "--file",
      global,
      "filter.operator.clean",
      "git hash-object --stdin",
    );
    const branchConfig = join(directory, ".git", "publication-branch-config");
    git(
      "config",
      "--file",
      branchConfig,
      "filter.branchonly.clean",
      "git hash-object --stdin",
    );
    git(
      "config",
      "--file",
      global,
      "includeIf.onbranch:codex-security/**.path",
      branchConfig,
    );
    const inactiveConfig = join(directory, ".git", "inactive-branch-config");
    git(
      "config",
      "--file",
      inactiveConfig,
      "filter.operator.clean",
      "git version",
    );
    git(
      "config",
      "--file",
      global,
      "includeIf.onbranch:never-published.path",
      inactiveConfig,
    );
    git("add", "other.ts");
    git("commit", "-m", "Synthetic unrelated file");
    // The separate edit arrives after the clean-filter preflight, before the native hook.
    const postIndex = hook === "post-index stage unrelated";
    const hooks = join(directory, ".git", "hooks");
    const hookPath = join(
      hooks,
      postIndex ? "post-index-change" : "pre-commit",
    );
    git("config", "--local", "core.hooksPath", hooks);
    await writeFile(
      hookPath,
      [
        "#!/bin/sh",
        "set -eu",
        'test "$(git config --get filter.snapshot.clean)" = ""',
        'test "$(git config --get filter.snapshot.required)" = false',
        'test "$(git config --get filter.branchonly.clean)" = ""',
        'test "$(git config --get filter.branchonly.required)" = false',
        'test "$(git config --get filter.operator.clean)" = "git hash-object --stdin"',

        ...(postIndex
          ? [
              'case "${GIT_INDEX_FILE:-}" in *codex-security-patch-tree-*) ;; *) exit 0;; esac',
              '[ "$(git branch --show-current)" = "codex-security/patch-scan-1" ] || exit 0',
            ]
          : []),
        "printf 'hook ran\\n' > .git/hook-ran",
        postIndex
          ? "git -c core.hooksPath=/dev/null add -A"
          : hook === "stage unrelated"
            ? "git add -A"
            : hook === "rewrite selected"
              ? "printf 'hook rewritten\\n' > src/finding-1.ts\ngit add -- src/finding-1.ts"
              : ":",
        "",
      ].join("\n"),
    );
    await chmod(hookPath, 0o755);
    const indexPath = git(
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    );
    let indexBefore: Buffer<ArrayBuffer> | undefined;
    let assessments = 0;
    let pushes = 0;
    let creations = 0;
    const cwd = scope === "root" ? directory : join(directory, scope);
    const result = resultWithFindings(["high"]);
    if (scope !== "root")
      result.findings.findings[0]!.locations[0]!.path = "finding-1.ts";
    const onRepositoryCommand: typeof runGitRepositoryCommand = async (
      command,
      args,
      cwd,
      options,
    ) => {
      if (command === "git") {
        if (args[0] === "switch" && args[1] === "-c") {
          await writeFile(
            join(directory, "other.ts"),
            "unrelated local edit\n",
          );
          indexBefore = await readFile(indexPath);
        }
        if (args[0] === "push") pushes++;
        const output = await runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { GIT_CONFIG_GLOBAL: global, ...options?.environment },
        });
        if (lostResult && args[0] === "commit")
          throw new Error("Synthetic commit result lost.");
        return output;
      }
      if (args[1] === "create") creations++;
      return args[1] === "list"
        ? "[]"
        : "https://github.example.test/example/repository/pull/1";
    };
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        ...(assess ? ["--assess-patch-risk"] : []),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: cwd,
        environment: { GIT_CONFIG_GLOBAL: global },
        result,
        onWorkbench: () => savedScan(result, "scan-1", cwd),
        onRepositoryCommand,
        onCodex: async (args, output) => {
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          ) {
            assessments++;
            const artifact = patchArtifactFromPrompt(output.appServer.prompt);
            expect(artifact.changedFiles).toEqual(["src/finding-1.ts"]);
            const patch = await readFile(artifact.path, "utf8");
            expect(patch).toContain("+fixed");
            expect(patch).not.toContain("unrelated local edit");
            expect(patch).not.toContain("hook rewritten");
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(assessments).toBe(assess ? 1 : 0);
    expect(await readFile(join(directory, ".git", "hook-ran"), "utf8")).toBe(
      "hook ran\n",
    );
    expect(await readFile(join(directory, "other.ts"), "utf8")).toBe(
      "unrelated local edit\n",
    );
    const branch = "codex-security/patch-scan-1";
    expect(git("show", "HEAD:src/finding-1.ts")).toBe(
      hook === "rewrite selected" ? "hook rewritten" : "fixed",
    );
    expect(git("show", "HEAD:other.ts")).toBe(
      hook === "stage unrelated" || postIndex
        ? "unrelated local edit"
        : "original unrelated",
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      hook === "rewrite selected" ? "hook rewritten\n" : "fixed\n",
    );
    if (hook === "unchanged") {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(pushes).toBe(1);
      expect(creations).toBe(1);
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      expect(git("show", "HEAD:other.ts")).toBe("original unrelated");
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      return;
    }
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain(
      lostResult
        ? "Synthetic commit result lost."
        : "The patch commit does not match the captured selected changes",
    );
    expect(pushes).toBe(0);
    expect(creations).toBe(0);
    expect(await readFile(indexPath)).toEqual(indexBefore!);
    expect(git("branch", "--show-current")).toBe(branch);
    expect(git("ls-remote", "origin")).toBe("");
    expect(
      git(
        "config",
        "--local",
        "--get",
        "--default",
        "",
        `branch.${branch}.codexSecurityPatchCommit`,
      ),
    ).toBe("");
    const resumed = await runWorkflow(
      ["patch", "--resume-pr", branch, "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand,
      },
    );
    expect(resumed.exitCode).toBe(2);
    expect(resumed.stderr).toContain(
      "No verified patch commit is saved for this branch.",
    );
    expect(pushes).toBe(0);
    expect(creations).toBe(0);
  },
);

for (const mode of [
  "replace direct hook",
  "replace nested hook",
  "activate missing hook",
  "change nested configuration",
  "unchanged trusted hook",
  "ordinary file beside root hooks",
  "dormant worktree",
] as const) {
  test(`captures dormant publication hook references: ${mode}`, async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-inactive-hook-support-");
    const rootHooks = mode === "ordinary file beside root hooks";
    const hooks = rootHooks ? directory : join(directory, "tracked-hooks");
    const hook = join(hooks, "pre-commit");
    const effect = join(support, "effect");
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const trusted = `#!/bin/sh\nprintf trusted > ${shellPath}\n`;
    const alternate = join(directory, "alternate");
    const alternateHook = join(alternate, "tracked-hooks", "pre-commit");
    const dormantWorktree = mode === "dormant worktree";
    if (dormantWorktree) {
      await mkdir(join(alternate, "tracked-hooks"), { recursive: true });
      await writeFile(alternateHook, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    }
    const changed = `#!/bin/sh\nprintf changed > ${shellPath}\n`;
    if (!rootHooks) await mkdir(hooks);
    const missingHook = mode === "activate missing hook";
    if (!missingHook) await writeFile(hook, trusted, { mode: 0o755 });
    const config = join(directory, ".git", "branch-config");
    const nested = mode.includes("nested");
    const nestedConfig = join(directory, ".git", "nested-config");
    await writeFile(
      config,
      nested
        ? `[include]\n path = ${JSON.stringify(nestedConfig.replaceAll("\\", "/"))}\n`
        : `[core]\n hooksPath = ${rootHooks ? JSON.stringify(directory.replaceAll("\\", "/")) : "tracked-hooks"}\n`,
    );
    if (dormantWorktree)
      await writeFile(
        config,
        `[core]\n worktree = ${JSON.stringify(alternate.replaceAll("\\", "/"))}\n hooksPath = tracked-hooks\n`,
      );
    if (nested)
      await writeFile(nestedConfig, "[core]\n hooksPath = tracked-hooks\n");
    git("add", ".");
    git("commit", "--allow-empty", "-m", "Synthetic dormant hook baseline");
    git("config", "includeIf.onbranch:codex-security/**.path", "branch-config");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    const configuration = await readFile(config);
    const remoteRefs = git("ls-remote", remote);
    let launches = 0;
    let pushes = 0;
    let creations = 0;
    const afterTurn: string[][] = [];
    const outcome = await runPublicationWorkflow("issue", {
      currentDirectory: directory,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command === "git") {
          if (launches > 0) afterTurn.push([...args]);
          if (args.includes("push")) pushes++;
          return runGitRepositoryCommand(command, args, cwd, options);
        }
        if (args[1] === "create") creations++;
        return args[1] === "list"
          ? "[]"
          : "https://github.example.test/example/repository/pull/1";
      },
      onCodex: async (_args, output) => {
        launches++;
        const paths = output?.appServer?.permissions?.readOnlyPaths ?? [];
        if (!missingHook) expect(paths).toContain(hook);
        if (nested) expect(paths).toContain(nestedConfig);
        if (dormantWorktree) {
          expect(paths).not.toContain(alternateHook);
          await writeFile(alternateHook, changed);
        }
        await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
        if (mode.startsWith("replace")) {
          await rename(hook, join(support, "original-hook"));
          await writeFile(hook, changed, { mode: 0o755 });
        } else if (missingHook) {
          await writeFile(hook, changed, { mode: 0o755 });
        } else if (mode === "change nested configuration") {
          await writeFile(nestedConfig, "[core]\n hooksPath = .\n");
        } else if (rootHooks) {
          await writeFile(join(directory, "ordinary.txt"), "ordinary edit\n");
        }
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches).toBe(1);
    const rejected =
      mode.startsWith("replace") ||
      missingHook ||
      mode === "change nested configuration";
    if (rejected) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        missingHook
          ? "Git hook became accessible during the patch"
          : mode === "change nested configuration"
            ? "Git configuration changed during the patch"
            : "Git configuration or hooks changed location during the patch",
      );
      expect(afterTurn).toEqual([]);
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
      expect(git("ls-remote", remote)).toBe(remoteRefs);
      expect(pushes).toBe(0);
      expect(creations).toBe(0);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(await readFile(effect, "utf8")).toBe("trusted");
      expect(await readFile(hook, "utf8")).toBe(trusted);
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      if (rootHooks)
        expect(git("show", "HEAD:ordinary.txt")).toBe("ordinary edit");
      expect(pushes).toBe(1);
      expect(creations).toBe(1);
      if (dormantWorktree) {
        expect(git("config", "--get", "core.worktree")).toBe(
          alternate.replaceAll("\\", "/"),
        );
        expect(git("rev-parse", "--show-toplevel").replaceAll("\\", "/")).toBe(
          directory.replaceAll("\\", "/"),
        );
        expect(await readFile(alternateHook, "utf8")).toBe(changed);
        // Git consumes direct core.worktree during setup, before onbranch includes.
        git("config", "--local", "core.worktree", alternate);
        expect(git("rev-parse", "--show-toplevel").replaceAll("\\", "/")).toBe(
          alternate.replaceAll("\\", "/"),
        );
      }
    }
    expect(await readFile(config)).toEqual(configuration);
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
  });
}

for (const nested of [false, true]) {
  test(
    `native model permissions preserve dormant trusted hook bytes, nested: ${nested}`,
    async () => {
      const { directory, git } = await publicationRepository(fixtures);
      const support = await fixtures.create("patch-inactive-hook-native-");
      const home = join(support, "home");
      await mkdir(home);
      await writeFile(join(home, "config.toml"), patchSnapshotWindowsConfig());
      const environment = patchSnapshotEnvironment(
        await fixtures.create("patch-inactive-hook-native-temp-"),
        { ...process.env, CODEX_HOME: home },
      );
      const hooks = join(directory, "tracked-hooks");
      const hook = join(hooks, "pre-commit");
      const effect = join(support, "effect");
      const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
      const trusted = `#!/bin/sh\nprintf trusted > ${shellPath}\n`;
      const changed = `#!/bin/sh\nprintf changed > ${shellPath}\n`;
      await mkdir(hooks);
      await writeFile(hook, trusted, { mode: 0o755 });
      git("add", ".");
      git("commit", "-m", "Synthetic native dormant hook baseline");
      const config = join(directory, ".git", "branch-config");
      await writeFile(
        config,
        nested
          ? "[include]\n path = nested-config\n"
          : "[core]\n hooksPath = tracked-hooks\n",
      );
      if (nested)
        await writeFile(
          join(directory, ".git", "nested-config"),
          "[core]\n hooksPath = tracked-hooks\n",
        );
      git(
        "config",
        "includeIf.onbranch:codex-security/**.path",
        "branch-config",
      );
      const script = join(directory, ".git", "synthetic-hook-probe.cjs");
      await writeFile(
        script,
        `const fs = require("node:fs");
let denied = false;
try { fs.writeFileSync(${JSON.stringify(hook)}, ${JSON.stringify(changed)}); }
catch (error) { if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error; denied = true; }
fs.writeFileSync(${JSON.stringify(join(directory, "src/finding-1.ts"))}, "fixed\\n");
fs.writeSync(1, JSON.stringify({ denied }));
`,
      );
      let denied: boolean | undefined;
      let hookProtected = false;
      const nativeStderr: Buffer[] = [];
      const outcome = await runPublicationWorkflow("issue", {
        currentDirectory: directory,
        environment,
        onRepositoryCommand: runPublicationCommand,
        onCodex: async (_args, output) => {
          const paths = output?.appServer?.permissions?.readOnlyPaths ?? [];
          hookProtected = paths.includes(hook);
          const alias = `alias.attempt=!node ${JSON.stringify(script.replaceAll("\\", "/"))}`;
          const result = await runRepositoryCommand(
            "git",
            ["-c", alias, "attempt"],
            directory,
            {
              onStderr: (chunk) => nativeStderr.push(chunk),
              sandbox: {
                directory,
                environment,
                profile: {
                  extends: ":workspace",
                  network: { enabled: false },
                  workspace_roots: {},
                  filesystem: Object.fromEntries(
                    paths.map((path) => [path, { ".": "read" }]),
                  ),
                },
              },
            },
          );
          denied = (JSON.parse(result) as { denied: boolean }).denied;
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(
        outcome.exitCode,
        outcome.stderr + Buffer.concat(nativeStderr).toString("utf8"),
      ).toBe(0);
      expect({
        hookProtected,
        denied,
        hook: await readFile(hook, "utf8"),
        effect: await readFile(effect, "utf8"),
      }).toEqual({
        hookProtected: true,
        denied: true,
        hook: trusted,
        effect: "trusted",
      });
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      expect(git("show", "HEAD:tracked-hooks/pre-commit")).toBe(trusted.trim());
    },
    process.platform === "win32" ? 120_000 : 30_000,
  );
}

for (const mode of [
  "malformed",
  "unknown hook user",
  "missing nested include",
  "unknown nested include user",
  "recursive include",
] as const) {
  test(`keeps dormant configuration errors inactive: ${mode}`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const config = join(directory, ".git", "branch-config");
    const contents =
      mode === "malformed"
        ? "[malformed\n"
        : mode === "unknown hook user"
          ? "[core]\n hooksPath = ~synthetic_missing_patch_hook_1251/hooks\n"
          : `[include]\n path = ${
              mode === "recursive include"
                ? "branch-config"
                : mode === "missing nested include"
                  ? "missing-config"
                  : "~synthetic_missing_patch_hook_1251/config"
            }\n`;
    await writeFile(config, contents);
    git("config", "includeIf.onbranch:future-branch.path", "branch-config");
    const head = git("rev-parse", "HEAD");
    let launches = 0;
    const outcome = await runIssuePatch(directory, {
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["src/finding-1.ts"]);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(config, "utf8")).toBe(contents);
  });
}
