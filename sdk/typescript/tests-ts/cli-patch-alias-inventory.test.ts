import { afterEach, expect, test } from "bun:test";
import { readFile, rename, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  { alias: true, state: "unstaged" },
  { alias: true, state: "staged" },
  { alias: false, state: "unstaged" },
  { alias: true, state: "clean" },
  { alias: true, state: "unrelated" },
])(
  "preserves the dirty publication inventory through a rename (alias: $alias, state: $state)",
  async ({ alias, state }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    await writeFile(join(directory, "old.ts"), "Original source\n");
    await writeFile(join(directory, "unrelated.ts"), "Unrelated baseline\n");
    git("add", ".");
    git("commit", "-m", "Synthetic alias rename baseline");
    const before = git("rev-parse", "HEAD");
    const dirty = state === "unstaged" || state === "staged";
    const content = dirty ? "Pre-existing local edit\n" : "Original source\n";
    if (dirty) await writeFile(join(directory, "old.ts"), content);
    if (state === "staged") git("add", "old.ts");
    if (state === "unrelated") {
      await writeFile(
        join(directory, "unrelated.ts"),
        "Unrelated local edit\n",
      );
      git("add", "unrelated.ts");
    }
    const index = await readFile(join(directory, ".git", "index"));
    const aliasRoot = await fixtures.create("patch-rename-alias-");
    const selected = alias ? join(aliasRoot, "linked-repository") : directory;
    if (alias)
      await symlink(
        directory,
        selected,
        process.platform === "win32" ? "junction" : "dir",
      );
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "new.ts";
    let pushes = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        result,
        onWorkbench: () => savedScan(result, "scan-1", selected),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          if (args[0] === "push") {
            pushes++;
            return "";
          }
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          await rename(join(selected, "old.ts"), join(selected, "new.ts"));
          output!.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic rename verified.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(dirty ? 2 : 0);
    expect(pushes).toBe(dirty ? 0 : 1);
    expect(await readFile(join(directory, "new.ts"), "utf8")).toBe(content);
    await expect(readFile(join(directory, "old.ts"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    if (dirty) {
      expect(outcome.stderr).toContain(
        "Cannot publish files with uncommitted changes before patching",
      );
      expect(git("rev-parse", "HEAD")).toBe(before);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
    } else {
      expect(git("show", "HEAD:new.ts")).toBe(content.trimEnd());
      expect(git("ls-tree", "HEAD", "old.ts")).toBe("");
      expect(git("show", "HEAD:unrelated.ts")).toBe("Unrelated baseline");
      expect(git("diff", "--cached", "--name-only")).toBe(
        state === "unrelated" ? "unrelated.ts" : "",
      );
    }
    expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
      "",
    );
  },
);
