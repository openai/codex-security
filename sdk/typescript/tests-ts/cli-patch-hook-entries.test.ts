import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function repository(prefix: string) {
  const root = await fixtures.create(prefix);
  const git = repositoryGit(root);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
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
}, true);
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
        await writeFile(source, "after\n");
        if (activate) {
          await rename(source, join(root, "retained-app.ts"));
          await mkdir(source);
          await writeFile(join(source, "post-index-change"), script, {
            mode: 0o755,
          });
        }
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
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
        await writeFile(source, "after\n");
        if (activate) {
          await rename(directory, join(root, "retained-update"));
          await writeFile(directory, script, { mode: 0o755 });
        }
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
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
