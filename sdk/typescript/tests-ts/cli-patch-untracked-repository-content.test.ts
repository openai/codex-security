import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const kind of [
  "untracked",
  "ignored",
  "metadata",
  "ignored metadata",
  "committed",
  "raw",
  "scrubbed",
  "directory link",
] as const) {
  for (const copied of [false, true]) {
    test.skipIf(
      (kind === "raw" && process.platform !== "linux") ||
        (kind === "directory link" && process.platform === "win32"),
    )(
      `preserves embedded repository content during ${kind} publication, copied: ${copied}`,
      async () => {
        const { directory, git, remote } =
          await publicationRepository(fixtures);
        if (kind.startsWith("ignored")) {
          await writeFile(join(directory, ".gitignore"), "nested/\n");
          git("add", ".gitignore");
          git("commit", "-m", "Synthetic ignored baseline");
        }
        const nested = join(directory, "nested");
        await mkdir(nested);
        const nestedGit = repositoryGit(nested);
        nestedGit("init", "--initial-branch=main");
        nestedGit("config", "user.name", "Synthetic User");
        nestedGit("config", "user.email", "synthetic@example.test");
        nestedGit("config", "commit.gpgsign", "false");
        await writeFile(join(nested, ".gitignore"), "local.txt\n");
        nestedGit("add", ".gitignore");
        nestedGit("commit", "-m", "Synthetic nested baseline");
        let content = "SYNTHETIC_LOCAL_ONLY_CONTENT\n";
        let source: string | Buffer = join(nested, "local.txt");
        if (kind.endsWith("metadata")) {
          nestedGit(
            "config",
            "http.extraHeader",
            "Authorization: Bearer SYNTHETIC_METADATA_CREDENTIAL",
          );
          source = join(nested, ".git", "config");
          content = await readFile(source, "utf8");
        }
        if (kind === "raw")
          source = Buffer.concat([
            Buffer.from(`${nested}/local-`),
            Buffer.from([0xff]),
          ]);
        if (kind === "directory link") {
          const outside = await fixtures.create("publication-link-target-");
          await writeFile(join(outside, "local.txt"), content);
          await symlink(outside, join(nested, "linked"));
          source = join(nested, "linked", "local.txt");
        } else await writeFile(source, content);
        if (kind === "committed") {
          nestedGit("add", "-f", "local.txt");
          nestedGit("commit", "-m", "Synthetic nested content");
        }
        const blocked = copied && kind !== "directory link";
        expect(git("status", "--porcelain=v1", "--untracked-files=all")).toBe(
          kind.startsWith("ignored") ? "" : "?? nested/",
        );
        const head = git("rev-parse", "HEAD");
        const nestedHead = nestedGit("rev-parse", "HEAD");
        const configuration = await readFile(join(nested, ".git", "config"));
        let index: Buffer<ArrayBuffer> | undefined;
        let nestedIndex: Buffer<ArrayBuffer> | undefined;
        let pushes = 0;
        let creations = 0;
        let assessments = 0;
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            "scan-1",
            ...(kind === "scrubbed" ? ["--assess-patch-risk"] : []),
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () =>
              savedScan(resultWithFindings(["high"]), "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) => {
              if (command === "git") {
                if (args.includes("push")) pushes++;
                return runGitRepositoryCommand(command, args, cwd, options);
              }
              if (args[1] === "create") creations++;
              return args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1";
            },
            onCodex: async (_args, output) => {
              if (
                output!.appServer!.prompt.includes("immutable patch artifact")
              ) {
                assessments++;
                await writeFile(
                  join(directory, "selected.txt"),
                  "Synthetic scrubbed working copy\n",
                );
                output!.stdout.write(patchRiskAssessment().report);
                return 0;
              }
              index = await readFile(join(directory, ".git", "index"));
              nestedIndex = await readFile(join(nested, ".git", "index"));
              await writeFile(
                join(directory, "selected.txt"),
                copied ? await readFile(source) : "New independent content\n",
              );
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status: "verified",
                      files: ["selected.txt"],
                      verification: "Synthetic verification.",
                    },
                  ],
                }),
              );
              return 0;
            },
          },
        );
        expect(index, outcome.stderr).toBeDefined();
        expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
        expect({ pushes, creations }).toEqual(
          blocked ? { pushes: 0, creations: 0 } : { pushes: 1, creations: 1 },
        );
        if (blocked) {
          expect(outcome.stderr).toContain("pre-existing");
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(await readFile(join(directory, ".git", "index"))).toEqual(
            index!,
          );
          expect(repositoryGit(remote)("for-each-ref")).toBe("");
        } else {
          expect(git("show", "HEAD:selected.txt")).toBe(
            copied ? content.trim() : "New independent content",
          );
          expect(git("ls-tree", "HEAD", "nested")).toBe("");
        }
        expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
        expect(await readFile(join(nested, ".git", "index"))).toEqual(
          nestedIndex!,
        );
        expect(await readFile(join(nested, ".git", "config"))).toEqual(
          configuration,
        );
        expect(await readFile(source, "utf8")).toBe(content);
        expect(assessments).toBe(kind === "scrubbed" ? 1 : 0);
        expect(await readFile(join(directory, "selected.txt"), "utf8")).toBe(
          kind === "scrubbed"
            ? "Synthetic scrubbed working copy\n"
            : copied
              ? content
              : "New independent content\n",
        );
      },
    );
  }
}

test("supplied-issue publication retains the clean-checkout requirement for an untracked repository", async () => {
  const { directory, git, remote } = await publicationRepository(fixtures);
  const nested = join(directory, "nested");
  await mkdir(nested);
  const nestedGit = repositoryGit(nested);
  nestedGit("init", "--initial-branch=main");
  nestedGit("config", "user.name", "Synthetic User");
  nestedGit("config", "user.email", "synthetic@example.test");
  nestedGit("config", "commit.gpgsign", "false");
  await writeFile(join(nested, "local.txt"), "Synthetic local content\n");
  nestedGit("add", "local.txt");
  nestedGit("commit", "-m", "Synthetic nested baseline");
  const head = git("rev-parse", "HEAD");
  git("status", "--porcelain=v1");
  const index = await readFile(join(directory, ".git", "index"));
  const nestedIndex = await readFile(join(nested, ".git", "index"));
  let models = 0;
  let publications = 0;
  const outcome = await runWorkflow(
    ["patch", "Synthetic issue", "--create-pr"],
    {
      currentDirectory: directory,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command === "git") {
          if (args.includes("push")) publications++;
          return runGitRepositoryCommand(command, args, cwd, options);
        }
        if (args[1] === "create") publications++;
        return "[]";
      },
      onCodex: async () => {
        models++;
        return 0;
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(2);
  expect(outcome.stderr).toContain(
    "Pull request creation for supplied issues requires a clean working tree.",
  );
  expect({ models, publications }).toEqual({ models: 0, publications: 0 });
  expect(git("rev-parse", "HEAD")).toBe(head);
  expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
  expect(await readFile(join(nested, ".git", "index"))).toEqual(nestedIndex);
  expect(repositoryGit(remote)("for-each-ref")).toBe("");
  expect(await readFile(join(nested, "local.txt"), "utf8")).toBe(
    "Synthetic local content\n",
  );
});
