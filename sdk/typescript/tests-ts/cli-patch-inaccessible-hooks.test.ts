import { afterEach, expect, test } from "bun:test";
import {
  chmod,
  mkdir,
  readFile,
  readlink,
  stat,
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
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
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
        let launches = 0;
        let controls: readonly string[] = [];
        let effectsBefore = "";
        const afterTurn: string[][] = [];
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--json"],
          {
            currentDirectory: root,
            onRepositoryCommand: (command, args, cwd, options) => {
              if (launches > 0) afterTurn.push([...args]);
              return runGitRepositoryCommand(command, args, cwd, options);
            },
            onCodex: async (_args, output) => {
              launches++;
              controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
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
              output?.stdout.write("Synthetic patch complete.\n");
              return 0;
            },
          },
        );
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
