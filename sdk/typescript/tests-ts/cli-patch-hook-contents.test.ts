import { afterEach, expect, test } from "bun:test";
import { constants } from "node:fs";
import {
  chmod,
  copyFile,
  link,
  open,
  readFile,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { capturePatchGitControls } from "../src/patch-git-controls.js";
import { join, sep } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

for (const mutate of [false, true])
  test.each(["post-checkout", "pre-commit", "pre-push"])(
    `publication preserves hardlinked hook contents (mutate: ${mutate}, hook: %s)`,
    async (hookName) => {
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
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
            if (mutate) await writeFile(alias, script("modified"));
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: [
                      "src/finding-1.ts",
                      ...(mutate ? ["hook-source.sh"] : []),
                    ],
                    verification: "Synthetic regression passed.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      const final = await stat(hook, { bigint: true });
      const effect = await readFile(witness, "utf8").catch(() => null);
      expect(modelCalls).toBe(1);
      expect(final.dev).toBe(initial.dev);
      expect(final.ino).toBe(initial.ino);
      expect(final.nlink).toBe(2n);
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
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
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
          true,
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
