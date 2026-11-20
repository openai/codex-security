import { expect, test } from "bun:test";
import {
  chmod,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
  copyFile,
  mkdir,
  readlink,
  symlink,
  link,
  open,
  utimes,
} from "node:fs/promises";
import { join, sep } from "node:path";
import {
  verifiedPatchResponse,
  repositoryGit,
  runGitRepositoryCommand,
  publicationRepository,
  resultWithFindings,
  savedScan,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
  runSavedPublication,
  observeIssuePatch,
} from "./cli-patch-fixtures.js";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { capturePatchGitControls } from "../src/patch-git-controls.js";

const fixtures = patchDirectories();

for (const mode of [
  "edit inactive file",
  "replace inactive file",
  "activate permissions",
  "replace with executable",
  "overlapping configuration",
] as const) {
  test.skipIf(process.platform === "win32")(
    `patch preserves Unix hook executability: ${mode}`,
    async () => {
      const root = await fixtures.create("patch-hook-executability-");
      const support = await fixtures.create(
        "patch-hook-executability-support-",
      );
      const git = initializePatchGit(root);
      const source = join(root, "app.ts");
      const hook = join(root, "post-index-change");
      const effect = join(support, "effect");
      const shellPath = `'${effect.replaceAll("'", "'\\''")}'`;
      const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
      const configuration = "[synthetic]\n value = original\n";
      const original =
        mode === "overlapping configuration" ? configuration : script;
      await writeFile(source, "before\n");
      await writeFile(hook, original, { mode: 0o644 });
      git("add", ".");
      git("commit", "-m", "Synthetic inactive hook baseline");
      const operator = join(support, "post-index-change");
      await writeFile(operator, script, { mode: 0o755 });
      git(
        "-c",
        `core.hooksPath=${support}`,
        "update-index",
        "--assume-unchanged",
        "app.ts",
      );
      git(
        "-c",
        `core.hooksPath=${support}`,
        "update-index",
        "--no-assume-unchanged",
        "app.ts",
      );
      expect(await readFile(effect, "utf8")).toContain("effect");
      await unlink(effect);
      git("config", "core.hooksPath", ".");
      if (mode === "overlapping configuration")
        git("config", "include.path", "../post-index-change");
      expect((await stat(hook)).mode & 0o111).toBe(0);
      git("update-index", "--assume-unchanged", "app.ts");
      git("update-index", "--no-assume-unchanged", "app.ts");
      expect(await readFile(effect).catch(() => null)).toBeNull();
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const config = await readFile(join(root, ".git", "config"));
      const changed =
        mode === "overlapping configuration"
          ? "[synthetic]\n value = changed\n"
          : `${script}# Synthetic source edit\n`;
      const {
        outcome,
        launches,
        afterTurn,
        controls: protectedPaths,
      } = await observeIssuePatch(root, async () => {
        await writeFile(source, "after\n");
        if (mode === "activate permissions") {
          await chmod(hook, 0o755);
        } else if (mode === "edit inactive file") {
          await writeFile(hook, changed);
        } else {
          await writeFile(`${hook}.replacement`, changed, {
            mode: mode === "replace with executable" ? 0o755 : 0o644,
          });
          await rename(`${hook}.replacement`, hook);
        }
      });
      expect(launches).toBe(1);
      expect(protectedPaths).toContain(join(root, ".git"));
      if (mode === "overlapping configuration") {
        expect(protectedPaths).toContain(hook);
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location",
        );
        expect(afterTurn).toEqual([]);
      } else {
        expect(protectedPaths).not.toContain(hook);
        if (
          mode === "activate permissions" ||
          mode === "replace with executable"
        ) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain("Git hook became accessible");
          expect(afterTurn).toEqual([]);
          expect((await stat(hook)).mode & 0o111).not.toBe(0);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files).toEqual([
            "app.ts",
            "post-index-change",
          ]);
          expect(afterTurn.some((args) => args.includes("write-tree"))).toBe(
            true,
          );
          expect((await stat(hook)).mode & 0o111).toBe(0);
        }
      }
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(await readFile(hook, "utf8")).toBe(
        mode === "activate permissions" ? original : changed,
      );
      expect(await readFile(source, "utf8")).toBe("after\n");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, ".git", "config"))).toEqual(config);
      expect(await readFile(operator, "utf8")).toBe(script);
    },
  );
}

for (const mode of ["existing native", "new native", "ordinary exe"] as const) {
  test.skipIf(mode === "ordinary exe" && process.platform === "win32")(
    `patch binds native executable hook selection: ${mode}`,
    async () => {
      const root = await fixtures.create("patch-executable-hook-");
      const support = await fixtures.create("patch-executable-hook-support-");
      const git = initializePatchGit(root);
      await writeFile(join(root, "app.ts"), "before\n");
      await writeFile(join(root, ".gitignore"), "synthetic-hooks\n0\n1\n");
      git("add", ".");
      git("commit", "-m", "Synthetic executable hook baseline");
      const hooks = join(root, "synthetic-hooks");
      await mkdir(hooks);
      git("config", "core.hooksPath", hooks);
      const suffix =
        process.platform === "win32" || mode === "ordinary exe" ? ".exe" : "";
      const hook = join(hooks, `post-index-change${suffix}`);
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const effect = join(support, "hook-effect");
      const program = `require("node:fs").writeFileSync(${JSON.stringify(effect)}, "effect");\n`;
      await writeFile(join(root, "0"), program);
      await writeFile(join(root, "1"), program);
      await copyFile(node, hook);
      if (mode === "ordinary exe") {
        execFileSync(hook, ["1", "0"], { cwd: root });
        expect(await readFile(effect, "utf8")).toBe("effect");
        await unlink(effect);
      }
      git("update-index", "--assume-unchanged", "app.ts");
      git("update-index", "--no-assume-unchanged", "app.ts");
      if (mode === "ordinary exe")
        expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      else {
        expect(await readFile(effect, "utf8")).toBe("effect");
        await unlink(effect);
      }
      if (mode === "new native") await unlink(hook);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      let launches = 0;
      let protectedPaths: readonly string[] = [];
      const postTurnWrites: string[][] = [];
      const outcome = await runIssuePatch(root, {
        onRepositoryCommand: (command, args, cwd, options) => {
          if (
            launches > 0 &&
            args.some((value) =>
              ["add", "read-tree", "update-index", "write-tree"].includes(
                value,
              ),
            )
          )
            postTurnWrites.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          launches++;
          protectedPaths = output?.appServer?.permissions?.readOnlyPaths ?? [];
          await unlink(effect).catch(() => {});
          if (mode !== "new native")
            await rename(hook, join(hooks, "retired-binary"));
          await copyFile(node, hook);
          await writeFile(join(root, "app.ts"), "after\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(launches).toBe(1);
      if (mode === "ordinary exe") {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(protectedPaths).not.toContain(hook);
        expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      } else {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          mode === "new native"
            ? "Git hook became accessible during the patch"
            : "Git configuration or hooks changed location during the patch",
        );
        if (mode === "existing native") expect(protectedPaths).toContain(hook);
        expect(postTurnWrites).toEqual([]);
      }
      expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}

for (const kind of [
  "directory without search permission",
  "directory below an unsearchable parent",
  "unused hook loop",
  "snapshot hook loop",
] as const) {
  // These controls exercise Unix search permission and executable symlink rules.
  test.skipIf(process.platform === "win32").each([false, true])(
    `preserves native Git handling of ${kind} (becomes accessible: %p)`,
    async (activate) => {
      const root = await fixtures.create("patch-inaccessible-hooks-");
      const support = await fixtures.create(
        "patch-inaccessible-hooks-support-",
      );
      const git = initializePatchGit(root);
      await writeFile(join(root, "app.ts"), "before\n");
      await writeFile(
        join(root, ".gitignore"),
        "operator-hooks/\noperator-parent/\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic inaccessible-hook baseline");
      const deniedParent = kind === "directory below an unsearchable parent";
      const denied =
        deniedParent || kind === "directory without search permission";
      const hooks = join(
        root,
        ...(deniedParent ? ["operator-parent"] : []),
        "operator-hooks",
      );
      const permissionDirectory = deniedParent
        ? join(root, "operator-parent")
        : hooks;
      await mkdir(hooks, { recursive: true });
      const operator = join(hooks, "post-index-change");
      const unavailable =
        kind === "unused hook loop" ? join(hooks, "pre-commit") : operator;
      const effect = join(support, "operator-effect");
      const activatedEffect = join(support, "activated-effect");
      const script = (path: string) => {
        const shellPath = `'${path.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
        return `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
      };
      const operatorScript = script(effect);
      const activatedScript = script(activatedEffect);
      await writeFile(operator, operatorScript, { mode: 0o755 });
      git("config", "core.hooksPath", hooks);
      git("update-index", "--assume-unchanged", "app.ts");
      git("update-index", "--no-assume-unchanged", "app.ts");
      expect(await readFile(effect, "utf8")).toContain("effect");
      await unlink(effect);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const configuration = await readFile(join(root, ".git", "config"));
      try {
        if (denied) {
          await chmod(permissionDirectory, 0o000);
          if (deniedParent)
            await expect(stat(hooks)).rejects.toHaveProperty("code", "EACCES");
        } else {
          if (kind === "snapshot hook loop") await unlink(operator);
          await symlink(unavailable, unavailable);
        }
        let effectsBefore = "";
        const { outcome, launches, afterTurn, controls } =
          await observeIssuePatch(root, async () => {
            effectsBefore = await readFile(effect, "utf8").catch(() => "");
            if (activate) {
              if (denied) await chmod(permissionDirectory, 0o755);
              else {
                await unlink(unavailable);
                await writeFile(unavailable, activatedScript, {
                  mode: 0o755,
                });
              }
            }
            await writeFile(join(root, "app.ts"), "after\n");
          });
        const effectsAfter = await readFile(effect, "utf8").catch(() => "");
        expect(launches).toBe(1);
        expect(controls).not.toContain(unavailable);
        if (kind === "unused hook loop") expect(controls).toContain(operator);
        if (activate) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain("became accessible");
          expect(afterTurn).toEqual([]);
          expect(effectsAfter).toBe(effectsBefore);
          if (!denied)
            expect(await readFile(unavailable, "utf8")).toBe(activatedScript);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
          if (!denied) expect(await readlink(unavailable)).toBe(unavailable);
          if (kind === "unused hook loop")
            expect(effectsAfter.length).toBeGreaterThan(effectsBefore.length);
          else expect(effectsAfter).toBe("");
        }
        expect(await readFile(activatedEffect).catch(() => null)).toBeNull();
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(root, ".git", "index"))).toEqual(index);
        expect(await readFile(join(root, ".git", "config"))).toEqual(
          configuration,
        );
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
        if (denied) await chmod(permissionDirectory, 0o755);
        if (kind !== "snapshot hook loop")
          expect(await readFile(operator, "utf8")).toBe(operatorScript);
      } finally {
        await chmod(permissionDirectory, 0o755);
      }
    },
  );
}

const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

for (const change of [
  "unchanged",
  "contents",
  ...(process.platform === "win32" ? [] : ["execute permission"]),
])
  test.each(["post-checkout", "pre-commit", "pre-push"])(
    `publication preserves hardlinked hooks (change: ${change}, hook: %s)`,
    async (hookName) => {
      const mutate = change !== "unchanged";
      const { directory, git, remote } = await publicationRepository(fixtures);
      const outside = await fixtures.create("patch-hook-witness-");
      const witness = join(outside, "effect");
      const alias = join(directory, "hook-source.sh");
      const hook = join(directory, ".git", "hooks", hookName);
      const script = (value: string) =>
        `#!/bin/sh\nprintf '${value}\\n' > ${quote(witness.split(sep).join("/"))}\n`;
      await writeFile(alias, script("trusted"), { mode: 0o755 });
      await chmod(alias, 0o755);
      git("add", "hook-source.sh");
      git("commit", "-m", "Synthetic hook source");
      await link(alias, hook);
      const initial = await stat(hook, { bigint: true });
      const head = git("rev-parse", "HEAD");
      const result = resultWithFindings(["high"]);
      let boundaries = 0;
      let modelCalls = 0;
      const outcome = await runSavedPublication(directory, {
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          if (["switch", "commit", "push"].includes(args[0]!)) boundaries++;
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          modelCalls++;
          const paths = output?.appServer?.permissions?.readOnlyPaths ?? [];
          expect(paths).toContain(hook);
          expect(paths).not.toContain(alias);
          if (change === "contents") await writeFile(alias, script("modified"));
          if (change === "execute permission") await chmod(alias, 0o644);
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          output?.stdout.write(
            verifiedPatchResponse(
              ["src/finding-1.ts", ...(mutate ? ["hook-source.sh"] : [])],
              "Synthetic regression passed.",
            ),
          );
          return 0;
        },
      });
      const final = await stat(hook, { bigint: true });
      const effect = await readFile(witness, "utf8").catch(() => null);
      expect(modelCalls, outcome.stderr).toBe(1);
      expect(final.dev).toBe(initial.dev);
      expect(final.ino).toBe(initial.ino);
      expect(final.nlink).toBe(2n);
      if (change === "execute permission")
        expect(await readFile(hook, "utf8")).toBe(script("trusted"));
      expect(outcome.exitCode, outcome.stderr).toBe(mutate ? 2 : 0);
      expect(effect).toBe(mutate ? null : "trusted\n");
      if (mutate) {
        expect(outcome.stderr.replaceAll(sep, "/")).toContain(
          `Git hook changed during the patch: ${hook}`.replaceAll(sep, "/"),
        );
        expect(boundaries).toBe(0);
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(
          repositoryGit(remote)("for-each-ref", "--format=%(refname)"),
        ).toBe("");
      } else {
        expect(boundaries).toBe(3);
        expect(git("rev-parse", "HEAD")).not.toBe(head);
        expect(
          repositoryGit(remote)("for-each-ref", "--format=%(refname)"),
        ).toContain("refs/heads/codex-security/patch-scan-1");
      }
    },
  );

for (const mutate of [false, true])
  test.skipIf(process.platform !== "linux" || process.getuid?.() === 0)(
    `patch preserves unreadable native hooks unless their aliases change (mutate: ${mutate})`,
    async () => {
      const directory = await fixtures.create("patch-unreadable-native-hook-");
      const git = initializePatchGit(directory);
      await writeFile(join(directory, "app.ts"), "before\n");
      await writeFile(join(directory, ".gitignore"), "hook-alias\n");
      git("add", ".");
      git("commit", "-m", "Synthetic native hook baseline");
      const hook = join(directory, ".git", "hooks", "post-checkout");
      const alias = join(directory, "hook-alias");
      await copyFile("/usr/bin/true", hook);
      const contents = await readFile(hook);
      await link(hook, alias);
      await chmod(hook, 0o311);
      try {
        // Exact whole-second mtime can be restored through the portable API.
        await utimes(hook, 1_000_000_000, 1_000_000_000);
        const before = await stat(hook, { bigint: true });
        await expect(readFile(hook)).rejects.toMatchObject({ code: "EACCES" });
        expect(git("hook", "run", "post-checkout")).toBe("");
        const controls = await capturePatchGitControls(
          directory,
          async (_root, checkout, args, options) =>
            runGitRepositoryCommand("git", args, checkout, options),
        );
        expect(controls).toBeDefined();
        await expect(controls!.validate()).resolves.toBeUndefined();

        if (mutate) {
          const file = await open(alias, constants.O_WRONLY);
          try {
            await file.write(
              Buffer.from([contents[contents.length - 1]! ^ 1]),
              0,
              1,
              contents.length - 1,
            );
          } finally {
            await file.close();
          }
          await utimes(alias, 1_000_000_000, 1_000_000_000);
        }

        const after = await stat(hook, { bigint: true });
        expect(after.dev).toBe(before.dev);
        expect(after.ino).toBe(before.ino);
        expect(after.nlink).toBe(2n);
        expect(after.size).toBe(before.size);
        expect(after.mtimeNs).toBe(before.mtimeNs);
        await expect(readFile(hook)).rejects.toMatchObject({ code: "EACCES" });
        if (mutate) {
          expect(after.ctimeNs).not.toBe(before.ctimeNs);
          await expect(controls!.validate()).rejects.toThrow(
            `Git hook changed during the patch: ${hook}`,
          );
        } else {
          await expect(controls!.validate()).resolves.toBeUndefined();
          expect(git("hook", "run", "post-checkout")).toBe("");
        }
      } finally {
        await chmod(hook, 0o700);
      }
    },
  );
