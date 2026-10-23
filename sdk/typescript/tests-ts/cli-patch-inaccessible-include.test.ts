import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
      const scan = resultWithFindings(["high"]);
      let launches = 0;
      const bookkeeping: string[][] = [];
      const publication: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(scan, "scan-1", directory),
          onCodex: async (args, output) => {
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
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
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
        },
      );
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
