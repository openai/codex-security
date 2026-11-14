import { afterEach, expect, test } from "bun:test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const flow of ["saved patch", "scan threshold"] as const) {
  test.each(["none", "tracked", "untracked"] as const)(
    `${flow} checks a no_change result against %s edits`,
    async (edit) => {
      const { directory, git } = await publicationRepository(fixtures);
      await writeFile(join(directory, "local.txt"), "staged local work\n");
      git("add", "local.txt");
      await writeFile(join(directory, "local.txt"), "unstaged local work\n");
      const head = git("rev-parse", "HEAD");
      const refs = git("ls-remote", "origin");
      const indexPath = git(
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "index",
      );
      let indexBefore: Buffer<ArrayBuffer> | undefined;
      let turns = 0;
      let publications = 0;
      const result = resultWithFindings(["high"]);
      const changedFile =
        edit === "tracked" ? "src/finding-1.ts" : "new-file.ts";
      const outcome = await runWorkflow(
        [
          ...(flow === "saved patch"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", "--patch", "--fail-on-severity", "high"]),
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "create") publications++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            turns++;
            indexBefore = await readFile(indexPath);
            if (edit !== "none")
              await writeFile(
                join(directory, changedFile),
                "unverified edit\n",
              );
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "no_change",
                    files: [],
                    verification: "Synthetic verification reported no change.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(turns).toBe(1);
      expect(outcome.exitCode, outcome.stderr).toBe(
        edit === "none" && flow === "scan threshold" ? 0 : 2,
      );
      const value = JSON.parse(outcome.stdout);
      expect(value.patches).toEqual([
        expect.objectContaining(
          edit === "none"
            ? { occurrenceId: "occ_1", status: "no_change", files: [] }
            : {
                occurrenceId: "occ_1",
                status: "failed",
                files: [changedFile],
                reason: "Patch reported no changes, but files changed.",
              },
        ),
      ]);
      if (flow === "saved patch") {
        expect(value.error.code).toBe(
          edit === "none" ? "NO_PATCH_APPLIED" : "PATCH_FAILED",
        );
        expect(value.files).toEqual(edit === "none" ? [] : [changedFile]);
      }
      expect(value).not.toHaveProperty("pullRequest");
      expect(publications).toBe(0);
      expect(git("branch", "--show-current")).toBe("main");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("ls-remote", "origin")).toBe(refs);
      expect(await readFile(indexPath)).toEqual(indexBefore!);
      expect(await readFile(join(directory, "local.txt"), "utf8")).toBe(
        "unstaged local work\n",
      );
      if (edit !== "none")
        expect(await readFile(join(directory, changedFile), "utf8")).toBe(
          "unverified edit\n",
        );
    },
  );
}
