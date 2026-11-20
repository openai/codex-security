import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, symlink, utimes, writeFile } from "node:fs/promises";
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
  "metadata in initialized submodule",
  "untracked file in initialized submodule",
  "tracked edit in initialized submodule",
  "clean filter edit in initialized submodule",
  "ident edit in initialized submodule",
  "filtered ident edit in initialized submodule",
  "empty driver ident edit in initialized submodule",
  "encoded ident edit in initialized submodule",
  "assume-unchanged edit in initialized submodule",
  "skip-worktree edit in initialized submodule",
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
        const objectFormat = kind.startsWith("sha256") ? "sha256" : "sha1";
        const { directory, git, remote } = await publicationRepository(
          fixtures,
          objectFormat,
        );
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
          `--object-format=${objectFormat}`,
        );
        nestedGit("config", "user.name", "Synthetic User");
        nestedGit("config", "user.email", "synthetic@example.test");
        nestedGit("config", "commit.gpgsign", "false");
        const stagedEdit = kind.endsWith(
          "staged-only edit in initialized submodule",
        );
        const unmergedEdit =
          kind === "sha256 unmerged edit in initialized submodule";
        const hiddenFlag = kind.startsWith("assume-unchanged")
          ? "--assume-unchanged"
          : kind.startsWith("skip-worktree")
            ? "--skip-worktree"
            : undefined;
        const ordinaryIdent = kind.endsWith(
          "ident edit in initialized submodule",
        );
        const encodedIdent =
          kind === "encoded ident edit in initialized submodule";
        const driver =
          kind === "filtered ident edit in initialized submodule"
            ? "noop"
            : kind === "empty driver ident edit in initialized submodule"
              ? ""
              : undefined;
        const nestedConfig = kind === "metadata in initialized submodule";
        const encoding = encodedIdent ? "utf16le" : "utf8";
        if (ordinaryIdent) {
          // These names overlap Git's display of missing and boolean attributes.
          for (const driver of ["unspecified", "unset"])
            nestedGit("config", "filter." + driver + ".smudge", "exit 1");
        }
        const cleanFilter =
          kind === "clean filter edit in initialized submodule";
        if (cleanFilter) {
          await writeFile(
            join(nested, ".gitattributes"),
            "local.txt -text filter=normalize\n",
          );
          nestedGit("add", ".gitattributes");
          nestedGit(
            "config",
            "filter.normalize.clean",
            "sed '/SYNTHETIC_LOCAL_ONLY_CONTENT/d'",
          );
        }
        const trackedEdit =
          cleanFilter ||
          ordinaryIdent ||
          hiddenFlag !== undefined ||
          stagedEdit ||
          unmergedEdit ||
          kind === "tracked edit in initialized submodule";
        // Git's ident conversion can hide changes inside an expanded $Id$.
        const ident = ordinaryIdent || hiddenFlag === "--assume-unchanged";
        const committedContent = ident
          ? (encodedIdent ? "# Résumé 雪\n" : "") + "$Id$\n"
          : "Committed fixture baseline\n";
        if (ident) {
          await writeFile(
            join(nested, ".gitattributes"),
            "local.txt ident " +
              (encodedIdent
                ? "-text -filter working-tree-encoding=UTF-16LE"
                : driver !== undefined
                  ? "-text filter=" + driver
                  : "-text") +
              "\n.gitignore ident -text\n",
          );
          nestedGit("add", ".gitattributes");
        }
        const ordinarySubmoduleFile =
          kind === "untracked file in initialized submodule";
        await writeFile(
          join(nested, ".gitignore"),
          ordinarySubmoduleFile
            ? "different.txt\n"
            : (ident ? "# $Id$\n" : "") + "local.txt\n",
        );
        nestedGit("add", ".gitignore");
        nestedGit("commit", "-m", "Synthetic nested baseline");
        let content = ident
          ? "$Id: SYNTHETIC_LOCAL_ONLY_CONTENT $\n"
          : "SYNTHETIC_LOCAL_ONLY_CONTENT\n";
        if (cleanFilter) content = committedContent + content;
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
          if (trackedEdit) await writeFile(source, committedContent, encoding);
          nestedGit("add", "-f", "local.txt");
          nestedGit("commit", "-m", "Synthetic nested content");
          if (hiddenFlag)
            nestedGit(
              "update-index",
              hiddenFlag,
              "--",
              "local.txt",
              ".gitignore",
            );
          if (ordinaryIdent) {
            const output = await runGitRepositoryCommand(
              "git",
              ["cat-file", "--filters", "HEAD:local.txt"],
              nested,
              { encoding: "base64" },
            );
            const rendered = Buffer.from(output, "base64").toString(encoding);
            const expansion =
              "$Id: " + nestedGit("rev-parse", ":local.txt") + " $";
            expect(rendered).toContain(expansion);
            if (encodedIdent) expect(rendered).toContain("Résumé 雪");
            content = copied
              ? rendered.replace(
                  expansion,
                  "$Id: SYNTHETIC_LOCAL_ONLY_CONTENT $",
                )
              : rendered;
          }
          if (trackedEdit) await writeFile(source, content, encoding);
          // A smudge command can synthesize the private bytes from the live
          // worktree, hiding them if it runs during provenance comparison.
          if (driver !== undefined)
            nestedGit(
              "config",
              "filter." + driver + ".smudge",
              "cat local.txt",
            );
          if (ident) {
            expect(nestedGit("hash-object", "--", "local.txt")).toBe(
              nestedGit("rev-parse", ":local.txt"),
            );
            const rendered = await runGitRepositoryCommand(
              "git",
              ["cat-file", "--filters", "HEAD:.gitignore"],
              nested,
              { trim: false },
            );
            expect(rendered).toContain(
              `$Id: ${nestedGit("rev-parse", ":.gitignore")} $`,
            );
            await writeFile(join(nested, ".gitignore"), rendered);
          }
          // Stage the filtered bytes with an older mtime so Git trusts its
          // index stat cache during the passive check with filters disabled.
          if (cleanFilter) await utimes(source, 1_000_000_000, 1_000_000_000);
          if (ordinaryIdent || cleanFilter) {
            nestedGit("add", "--", "local.txt", ".gitignore");
            if (cleanFilter) {
              // The index stat cache remains valid if the filter is removed.
              const info = join(nested, ".git", "info");
              await mkdir(info, { recursive: true });
              await writeFile(join(info, "attributes"), "local.txt !filter\n");
            }
            expect(nestedGit("status", "--porcelain=v1")).toBe("");
            expect(nestedGit("diff", "--cached", "--name-only")).toBe("");
            expect(nestedGit("ls-files", "-v", "--", "local.txt")).toBe(
              "H local.txt",
            );
          }
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
          if (nestedConfig) {
            nestedGit(
              "config",
              "http.extraHeader",
              "Authorization: Bearer SYNTHETIC_METADATA_CREDENTIAL",
            );
            source = join(
              nestedGit("rev-parse", "--absolute-git-dir"),
              "config",
            );
            content = await readFile(source, "utf8");
          }
          expect(
            git("ls-files", "--others", "--ignored", "--exclude-standard"),
          ).toBe("");
          if (ordinarySubmoduleFile) {
            expect(
              nestedGit("ls-files", "--others", "--exclude-standard"),
            ).toBe("local.txt");
          }
        }
        // Git’s normal checked-out representation remains publishable.
        const independentContent =
          hiddenFlag || ordinaryIdent
            ? await readFile(join(nested, ".gitignore"), "utf8")
            : "New independent content\n";
        const copiedPrivateContent = copied && kind !== "directory link";
        const blocked = copiedPrivateContent || kind === "scrubbed";
        const assessed =
          kind === "scrubbed" || (kind === "untracked" && !copied);
        expect(git("status", "--porcelain=v1", "--untracked-files=all")).toBe(
          hiddenFlag ||
            cleanFilter ||
            ordinaryIdent ||
            kind.startsWith("ignored") ||
            nestedConfig ||
            kind === "initialized submodule"
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
        const nestedIndex = await readFile(join(nestedStorage, "index"));
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
                  if (
                    !ordinaryIdent &&
                    (ordinarySubmoduleFile || trackedEdit) &&
                    copied
                  )
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
              await writeFile(
                join(directory, "selected.txt"),
                copied || ordinaryIdent
                  ? stagedEdit || unmergedEdit
                    ? nestedGit(
                        "show",
                        unmergedEdit ? ":1:local.txt" : ":local.txt",
                      ) + "\n"
                    : await readFile(source)
                  : independentContent,
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
          if (ordinaryIdent) {
            const blob = await runGitRepositoryCommand(
              "git",
              ["show", "HEAD:selected.txt"],
              directory,
              { encoding: "base64" },
            );
            expect(Buffer.from(blob, "base64")).toEqual(await readFile(source));
          } else {
            expect(git("show", "HEAD:selected.txt")).toBe(
              copied ? content.trim() : independentContent.trim(),
            );
          }
          expect(git("ls-tree", "HEAD", "nested")).toBe(originalGitlink);
        }
        expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
        expect(await readFile(join(nestedStorage, "index"))).toEqual(
          nestedIndex,
        );
        expect(await readFile(join(nestedStorage, "config"))).toEqual(
          configuration,
        );
        expect(await readFile(source, encoding)).toBe(
          stagedEdit || unmergedEdit ? committedContent : content,
        );
        if (stagedEdit)
          expect(nestedGit("show", ":local.txt")).toBe(content.trim());
        expect(assessments).toBe(assessed ? 1 : 0);
        expect(await readFile(join(directory, "selected.txt"), encoding)).toBe(
          kind === "scrubbed"
            ? "Synthetic scrubbed working copy\n"
            : copied || ordinaryIdent
              ? content
              : independentContent,
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
