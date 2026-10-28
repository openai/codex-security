import { afterEach, expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  readlink,
  symlink,
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

for (const mode of [
  "unchanged inactive",
  "inactive becomes accessible",
  "active",
] as const) {
  test(`preserves native conditional include behavior for a symlink loop: ${mode}`, async () => {
    const root = await fixtures.create("patch-include-loop-");
    const support = await fixtures.create("patch-include-loop-support-");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
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
    await symlink(
      loop,
      loop,
      process.platform === "win32" ? "junction" : "dir",
    );
    const link = await readlink(loop);
    const include = join(loop, "included");
    git(
      "config",
      `includeIf.onbranch:${mode === "active" ? "main" : "future-branch"}.path`,
      "../control-loop/included",
    );
    const head = await readFile(join(root, ".git", "HEAD"));
    const reference = await readFile(
      join(root, ".git", "refs", "heads", "main"),
    );
    const index = await readFile(join(root, ".git", "index"));
    const configuration = await readFile(join(root, ".git", "config"));
    // Git for Windows ignores this unresolved junction include; Unix reports ELOOP.
    const nativeRejectsLoop = mode === "active" && process.platform !== "win32";
    let nativeFailure = "";
    if (nativeRejectsLoop) {
      try {
        git("config", "--includes", "--list");
        throw new Error(
          "Expected native Git to reject the active include loop",
        );
      } catch (error) {
        const failure = error as Error & { status?: number; stderr?: Buffer };
        expect(failure.status).toBe(128);
        nativeFailure = String(failure.stderr).trim();
        expect(nativeFailure).toContain("control-loop/included");
      }
    } else {
      expect(git("config", "--includes", "--list")).toContain(
        `includeif.onbranch:${mode === "active" ? "main" : "future-branch"}.path=../control-loop/included`,
      );
    }
    let launches = 0;
    let effectsBefore = "";
    const afterTurn: string[][] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (launches > 0) afterTurn.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
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
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
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
    expect(await readFile(join(root, ".git", "HEAD"))).toEqual(head);
    expect(await readFile(join(root, ".git", "refs", "heads", "main"))).toEqual(
      reference,
    );
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(configuration);
    expect(await readFile(hook, "utf8")).toBe(script);
    expect(await readFile(join(root, "app.ts"), "utf8")).toBe(
      nativeRejectsLoop ? "before\n" : "after\n",
    );
  });
}
