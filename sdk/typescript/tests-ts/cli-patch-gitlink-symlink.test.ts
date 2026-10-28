import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  rename,
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

async function initialize(root: string) {
  const git = repositoryGit(root);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  await writeFile(join(root, "app.ts"), "before\n");
  git("add", ".");
  git("commit", "-m", "Synthetic baseline");
  return git;
}

for (const raw of [false, true]) {
  test.skipIf(
    process.platform === "win32" || (raw && process.platform !== "linux"),
  )(
    `patch leaves a symlink replacing a tracked gitlink as data (raw name: ${raw})`,
    async () => {
      const root = await fixtures.create("patch-gitlink-symlink-");
      const foreign = await fixtures.create("patch-gitlink-unselected-");
      const support = await fixtures.create("patch-gitlink-support-");
      const git = await initialize(root);
      const other = await initialize(foreign);
      const source = join(root, "source");
      await mkdir(source);
      const inner = await initialize(source);
      const revision = inner("rev-parse", "HEAD");
      const name = raw
        ? Buffer.concat([Buffer.from("source-"), Buffer.from([0xff])])
        : Buffer.from("source");
      const selectedPath = Buffer.concat([Buffer.from(`${root}/`), name]);
      if (raw) await rename(source, selectedPath);
      execFileSync("git", ["update-index", "-z", "--index-info"], {
        cwd: root,
        input: Buffer.concat([
          Buffer.from(`160000 ${revision}\t`),
          name,
          Buffer.from([0]),
        ]),
      });
      git("commit", "-m", "Synthetic selected gitlink");
      await rename(selectedPath, join(support, "original"));
      await symlink(foreign, selectedPath);
      const effect = join(support, "hook-effect");
      const hook = join(foreign, ".git", "hooks", "synthetic-fsmonitor");
      await writeFile(
        hook,
        `#!/bin/sh\nprintf effect > '${effect.replaceAll("'", "'\\''")}'\nprintf '\\0'\n`,
        { mode: 0o755 },
      );
      other("config", "core.fsmonitor", hook);
      other("ls-files", "--cached");
      expect(await readFile(effect, "utf8")).toBe("effect");
      await unlink(effect);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const otherHead = other("rev-parse", "HEAD");
      const otherIndex = await readFile(join(foreign, ".git", "index"));
      const targetCommands: string[][] = [];
      let launches = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              cwd === foreign ||
              args.some(
                (arg) => arg === foreign || arg.startsWith(`${foreign}/`),
              )
            )
              targetCommands.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            launches++;
            expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
              join(foreign, ".git"),
            );
            await writeFile(join(root, "app.ts"), "after\n");
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(targetCommands).toEqual([]);
      expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(other("rev-parse", "HEAD")).toBe(otherHead);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(foreign, ".git", "index"))).toEqual(
        otherIndex,
      );
      expect(await readFile(join(foreign, "app.ts"), "utf8")).toBe("before\n");
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}
