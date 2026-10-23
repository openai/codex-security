import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
const hasLfs = spawnSync("git", ["lfs", "version"]).status === 0;

for (const used of [false, true]) {
  test.skipIf(used && !hasLfs).each(["file", "file ancestor"])(
    `non-directory LFS storage remains optional when used=${used}: %s`,
    async (mode) => {
      const root = await fixtures.create("patch-nondirectory-lfs-");
      const repository = join(root, "repository");
      await mkdir(repository);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "core.autocrlf", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (used) {
        git("lfs", "install", "--local", "--skip-repo");
        await writeFile(
          join(repository, ".gitattributes"),
          "*.bin filter=lfs diff=lfs merge=lfs -text\n",
        );
      }
      git("add", ".");
      git("commit", "-m", "Synthetic optional storage baseline");
      const blocker = join(root, "cache-file");
      const contents = "Synthetic ordinary file\n";
      await writeFile(blocker, contents);
      const storage = mode === "file" ? blocker : join(blocker, "storage");
      git("config", "lfs.storage", storage);
      const config = await readFile(join(repository, ".git", "config"));
      const head = git("rev-parse", "HEAD");
      expect(git("status", "--porcelain")).toBe("");
      const index = await readFile(join(repository, ".git", "index"));
      let started = false;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: repository,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            started = true;
            expect(output!.appServer!.snapshotStoragePaths).toEqual([]);
            expect(
              output!.appServer!.permissions!.modelOnlyReadOnlyPaths ?? [],
            ).toEqual([]);
            await writeFile(join(repository, "app.ts"), "fixed\n");
            if (used)
              await writeFile(
                join(repository, "payload.bin"),
                "Synthetic LFS payload\n",
              );
            output!.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(started, outcome.stderr).toBe(true);
      expect(outcome.exitCode, outcome.stderr).toBe(used ? 2 : 0);
      if (used) expect(outcome.stderr).toContain("clean filter 'lfs' failed");
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(await readFile(blocker, "utf8")).toBe(contents);
      expect(await readFile(join(repository, ".git", "config"))).toEqual(
        config,
      );
      expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
      expect(git("rev-parse", "HEAD")).toBe(head);
    },
  );
}
