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

for (const [indexState, stage] of [
  ["staged", undefined],
  ["staged", 0],
  ["unmerged", undefined],
  ["unmerged", 1],
  ["unmerged", 2],
  ["unmerged", 3],
] as const) {
  test(`preserves ${indexState} content during publication, copied stage: ${stage ?? "none"}`, async () => {
    const copied = stage !== undefined;
    const { directory, git, remote } = await publicationRepository(fixtures);
    const file = join(directory, "unrelated.txt");
    const baseline = "Committed fixture baseline\n";
    const marker = "Synthetic staged-only content\n";
    await writeFile(file, baseline);
    git("add", "--", "unrelated.txt");
    git("commit", "-m", "Add independent fixture file");
    await writeFile(file, marker);
    if (indexState === "staged") {
      git("add", "--", "unrelated.txt");
    } else {
      git("update-index", "--force-remove", "--", "unrelated.txt");
      const entries: string[] = [];
      for (const indexStage of [1, 2, 3]) {
        await writeFile(file, `Synthetic unmerged stage ${indexStage}\n`);
        const blob = git("hash-object", "-w", "--", "unrelated.txt");
        entries.push(`100644 ${blob} ${indexStage}\tunrelated.txt\n`);
      }
      await runGitRepositoryCommand(
        "git",
        ["update-index", "--index-info"],
        directory,
        { input: entries.join("") },
      );
    }
    await writeFile(file, baseline);
    const before = git("ls-files", "--stage", "unrelated.txt");
    const head = git("rev-parse", "HEAD");
    let pushes = 0;
    const result = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onCodex: async (_args, output) => {
          await writeFile(
            join(directory, "selected.txt"),
            stage === undefined
              ? "Independent change\n"
              : git(
                  "show",
                  stage === 0 ? ":unrelated.txt" : `:${stage}:unrelated.txt`,
                ) + "\n",
          );
          output!.stdout.write(
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
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git") {
            if (args.includes("push")) {
              pushes++;
              if (copied)
                throw new Error("Unexpected publication of staged content");
            }
            return runGitRepositoryCommand(command, args, cwd, options);
          }
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
      },
    );
    expect(git("ls-files", "--stage", "unrelated.txt")).toBe(before);
    expect(await readFile(file, "utf8")).toBe(baseline);
    expect(pushes).toBe(copied ? 0 : 1);
    expect(result.exitCode, result.stderr).toBe(copied ? 2 : 0);
    if (copied) {
      expect(result.stderr).toContain("pre-existing staged content");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(repositoryGit(remote)("for-each-ref")).toBe("");
    }
  });
}

for (const kind of [
  "untracked",
  "ignored",
  "metadata",
  "Subversion working copy",
  "ignored metadata",
  "committed",
  "initialized submodule",
  "untracked file in initialized submodule",
  "tracked edit in initialized submodule",
  "staged-only edit in initialized submodule",
  "sha256 staged-only edit in initialized submodule",
  "sha256 unmerged edit in initialized submodule",
  "raw",
  "scrubbed",
  "directory link",
  "internal directory link",
] as const) {
  for (const copied of [false, true]) {
    test.skipIf(kind === "raw" && process.platform !== "linux")(
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
        nestedGit(
          "init",
          "--initial-branch=main",
          ...(kind.startsWith("sha256") ? ["--object-format=sha256"] : []),
        );
        nestedGit("config", "user.name", "Synthetic User");
        nestedGit("config", "user.email", "synthetic@example.test");
        nestedGit("config", "commit.gpgsign", "false");
        const stagedEdit = kind.endsWith(
          "staged-only edit in initialized submodule",
        );
        const unmergedEdit =
          kind === "sha256 unmerged edit in initialized submodule";
        const trackedEdit =
          stagedEdit ||
          unmergedEdit ||
          kind === "tracked edit in initialized submodule";
        const committedContent = "Committed fixture baseline\n";
        const ordinarySubmoduleFile =
          kind === "untracked file in initialized submodule";
        await writeFile(
          join(nested, ".gitignore"),
          ordinarySubmoduleFile ? "different.txt\n" : "local.txt\n",
        );
        nestedGit("add", ".gitignore");
        nestedGit("commit", "-m", "Synthetic nested baseline");
        let content = "SYNTHETIC_LOCAL_ONLY_CONTENT\n";
        let source: string | Buffer = join(nested, "local.txt");
        if (kind === "Subversion working copy") {
          await mkdir(join(nested, ".svn"));
          source = join(nested, ".svn", "wc.db");
          content = "SQLite format 3\0SYNTHETIC_PRIVATE_WORKING_COPY_DATA\n";
        }
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
        if (kind.endsWith("directory link")) {
          const target =
            kind === "directory link"
              ? await fixtures.create("publication-link-target-")
              : join(nested, "private-target");
          await mkdir(target, { recursive: true });
          await writeFile(join(target, "local.txt"), content);
          await symlink(
            target,
            join(nested, "linked"),
            process.platform === "win32" ? "junction" : "dir",
          );
          source = join(nested, "linked", "local.txt");
        } else await writeFile(source, content);
        if (kind === "committed" || trackedEdit) {
          if (trackedEdit) await writeFile(source, committedContent);
          nestedGit("add", "-f", "local.txt");
          nestedGit("commit", "-m", "Synthetic nested content");
          if (trackedEdit) await writeFile(source, content);
          if (unmergedEdit) {
            // A DD conflict has only stage 1, with no stage-0 worktree match.
            const object = nestedGit("hash-object", "-w", "--", "local.txt");
            nestedGit("update-index", "--force-remove", "--", "local.txt");
            await runGitRepositoryCommand(
              "git",
              ["update-index", "--index-info"],
              nested,
              { input: `100644 ${object} 1\tlocal.txt\n` },
            );
            await writeFile(source, committedContent);
            expect(nestedGit("status", "--porcelain=v1")).toBe("DD local.txt");
          } else if (stagedEdit) {
            nestedGit("add", "--", "local.txt");
            await writeFile(source, committedContent);
          }
        }
        if (kind.endsWith("initialized submodule")) {
          const childRemote = await fixtures.create(
            "publication-child-origin-",
          );
          git("clone", "--bare", nested, childRemote);
          nestedGit("remote", "add", "origin", childRemote);
          nestedGit("fetch", "origin");
          git("config", "-f", ".gitmodules", "submodule.nested.path", "nested");
          git(
            "config",
            "-f",
            ".gitmodules",
            "submodule.nested.url",
            childRemote,
          );
          git("add", ".gitmodules", "nested");
          git("commit", "-m", "Synthetic registered submodule");
          git("submodule", "init");
          git("submodule", "absorbgitdirs", "--", "nested");
          expect(
            git("ls-files", "--others", "--ignored", "--exclude-standard"),
          ).toBe("");
          if (ordinarySubmoduleFile) {
            expect(
              nestedGit("ls-files", "--others", "--exclude-standard"),
            ).toBe("local.txt");
          }
        }
        const copiedPrivateContent = copied && kind !== "directory link";
        const blocked = copiedPrivateContent || kind === "scrubbed";
        const assessed =
          kind === "scrubbed" || (kind === "untracked" && !copied);
        expect(git("status", "--porcelain=v1", "--untracked-files=all")).toBe(
          kind.startsWith("ignored") || kind === "initialized submodule"
            ? ""
            : ordinarySubmoduleFile || trackedEdit
              ? "M nested"
              : "?? nested/",
        );
        const head = git("rev-parse", "HEAD");
        const nestedHead = nestedGit("rev-parse", "HEAD");
        const nestedStorage = nestedGit("rev-parse", "--absolute-git-dir");
        const configuration = await readFile(join(nestedStorage, "config"));
        const originalGitlink = git("ls-tree", "HEAD", "nested");
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
            ...(assessed ? ["--assess-patch-risk"] : []),
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () =>
              savedScan(resultWithFindings(["high"]), "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) => {
              if (command === "git") {
                if (args.includes("push")) {
                  pushes++;
                  if ((ordinarySubmoduleFile || trackedEdit) && copied)
                    throw new Error("Unexpected push of pre-existing content");
                }
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
                if (kind === "scrubbed")
                  await writeFile(
                    join(directory, "selected.txt"),
                    "Synthetic scrubbed working copy\n",
                  );
                output!.stdout.write(patchRiskAssessment().report);
                return 0;
              }
              index = await readFile(join(directory, ".git", "index"));
              nestedIndex = await readFile(join(nestedStorage, "index"));
              await writeFile(
                join(directory, "selected.txt"),
                copied
                  ? stagedEdit || unmergedEdit
                    ? nestedGit(
                        "show",
                        unmergedEdit ? ":1:local.txt" : ":local.txt",
                      ) + "\n"
                    : await readFile(source)
                  : "New independent content\n",
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
        if (kind === "directory link") {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "symbolic link outside the scanned repository",
          );
          expect(index).toBeUndefined();
          expect({ pushes, creations }).toEqual({ pushes: 0, creations: 0 });
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(repositoryGit(remote)("for-each-ref")).toBe("");
          expect(await readFile(source, "utf8")).toBe(content);
          return;
        }
        expect(index, outcome.stderr).toBeDefined();
        expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
        expect({ pushes, creations }).toEqual(
          blocked ? { pushes: 0, creations: 0 } : { pushes: 1, creations: 1 },
        );
        if (blocked) {
          expect(outcome.stderr).toContain(
            copiedPrivateContent
              ? "pre-existing"
              : "working tree differs from the verified changes",
          );
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(await readFile(join(directory, ".git", "index"))).toEqual(
            index!,
          );
          expect(repositoryGit(remote)("for-each-ref")).toBe("");
        } else {
          expect(git("show", "HEAD:selected.txt")).toBe(
            copied ? content.trim() : "New independent content",
          );
          expect(git("ls-tree", "HEAD", "nested")).toBe(originalGitlink);
        }
        expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
        expect(await readFile(join(nestedStorage, "index"))).toEqual(
          nestedIndex!,
        );
        expect(await readFile(join(nestedStorage, "config"))).toEqual(
          configuration,
        );
        expect(await readFile(source, "utf8")).toBe(
          stagedEdit || unmergedEdit ? committedContent : content,
        );
        if (stagedEdit)
          expect(nestedGit("show", ":local.txt")).toBe(content.trim());
        expect(assessments).toBe(assessed ? 1 : 0);
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
