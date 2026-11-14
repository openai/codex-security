import { afterEach, describe, expect, test, mock } from "bun:test";
import { hash } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  realpath,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  delimiter,
  dirname,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { dependencies } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  readAppliedText,
  resultWithFindings,
  savedScan,
  completePatches,
  patchRiskAssessment,
  runWorkflow,
  repositoryGit,
  runGitRepositoryCommand,
  publicationRepository as createPublicationRepository,
} from "./cli-patch-fixtures.js";

describe("patch change tracking", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  const publicationRepository = () => createPublicationRepository(fixtures);

  test.each([
    "external link",
    "dangling link",
    "regular file",
    "linked worktree",
  ])(
    "nested risk snapshots validate the parent pack directory: %s",
    async (kind) => {
      const { directory, git } = await publicationRepository();
      const linked = kind === "linked worktree";
      const checkout = linked
        ? await fixtures.create("patch-linked-worktree-")
        : directory;
      if (linked) git("worktree", "add", "--detach", checkout, "HEAD");
      const parentGit = repositoryGit(checkout);
      const nestedName = linked ? `nested${delimiter}checkout` : "nested";
      const nested = join(checkout, nestedName);
      await mkdir(nested);
      const childGit = repositoryGit(nested);
      childGit("init", "--quiet");
      childGit(
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=test@example.test",
        "commit",
        "--allow-empty",
        "-m",
        "Nested baseline",
      );
      parentGit("add", nestedName);
      parentGit("commit", "-m", "Record nested checkout");

      const outside = await fixtures.create("patch-external-pack-");
      const pack = parentGit(
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "objects/pack",
      );
      const objectDirectory = await realpath(dirname(pack));
      await rm(pack, { recursive: true });
      if (kind === "regular file") await writeFile(pack, "synthetic");
      else if (!linked) {
        await symlink(
          outside,
          pack,
          process.platform === "win32" ? "junction" : "dir",
        );
        if (kind === "dangling link") await rm(outside, { recursive: true });
      }
      const model = mock(async () => 0);
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: checkout,
          onRepositoryCommand: async (tool, args, cwd, options) => {
            if (!args.includes("pack-objects"))
              return runGitRepositoryCommand(tool, args, cwd, options);
            expect(options?.patchSnapshot).toEqual([objectDirectory]);
            expect(options?.environment?.["GIT_OBJECT_DIRECTORY"]).toBe(
              objectDirectory,
            );
            const childPack = join(nested, ".git", "objects", "pack");
            if (process.platform !== "win32") await chmod(childPack, 0o555);
            try {
              return await runGitRepositoryCommand(tool, args, cwd, options);
            } finally {
              if (process.platform !== "win32") await chmod(childPack, 0o755);
            }
          },
          onCodex: model,
        },
      );
      if (linked) {
        expect(model, outcome.stderr).toHaveBeenCalled();
        expect(
          (await readdir(pack)).some((file) => file.endsWith(".pack")),
        ).toBe(true);
      } else {
        expect(model, outcome.stderr).not.toHaveBeenCalled();
        expect(outcome.stderr).toContain("pack");
        if (kind === "dangling link")
          await expect(readdir(outside)).rejects.toMatchObject({
            code: "ENOENT",
          });
        else expect(await readdir(outside)).toEqual([]);
      }
    },
  );

  test.each([
    "published",
    "missing",
    "published-removed-worktree",
    "missing-removed-worktree",
    "published-removed-worktree-dangling",
    "missing-removed-worktree-dangling",
    "published-removed-worktree-renamed",
    "missing-removed-worktree-renamed",
    "published-removed-worktree-renamed-other-store",
    "missing-removed-worktree-renamed-other-store",
    "push-no",
    "submodule-false",
  ])(
    "publishes assessed nested updates with %s commits/settings",
    async (mode) => {
      const missing = mode.startsWith("missing");
      const worktreeRemoved = mode.includes("removed-worktree");
      const dangling = mode.endsWith("-dangling");
      const renamed = mode.includes("-renamed");
      const otherStore = mode.endsWith("-other-store");
      const { directory, git, remote } = await publicationRepository();
      const nested = join(directory, "nested");
      await mkdir(nested);
      const nestedGit = repositoryGit(nested);
      nestedGit("init", "--initial-branch=main");
      nestedGit("config", "user.name", "Synthetic User");
      nestedGit("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "original\n");
      nestedGit("add", ".");
      nestedGit("commit", "-m", "Synthetic nested baseline");
      const nestedRemote = await fixtures.create("patch-nested-origin-");
      git("clone", "--bare", nested, nestedRemote);
      nestedGit("remote", "add", "origin", nestedRemote);
      nestedGit("fetch", "origin");
      git("config", "-f", ".gitmodules", "submodule.nested.path", "nested");
      git("config", "-f", ".gitmodules", "submodule.nested.url", nestedRemote);
      git("add", ".gitmodules");
      git("add", "nested");
      git("commit", "-m", "Synthetic gitlink");
      git("submodule", "init");
      git("submodule", "absorbgitdirs", "--", "nested");
      const nestedGitDirectory = nestedGit("rev-parse", "--absolute-git-dir");
      const nestedIndexPath = join(nestedGitDirectory, "index");
      if (mode === "push-no") git("config", "push.recurseSubmodules", "no");
      if (mode === "submodule-false")
        git("config", "submodule.recurse", "false");
      const before = nestedGit("rev-parse", "HEAD");
      let after = before;
      let nestedIndex = await readFile(nestedIndexPath);
      let assessments = 0;
      let creations = 0;
      const onRepositoryCommand: NonNullable<
        NonNullable<Parameters<typeof dependencies>[0]>["onRepositoryCommand"]
      > = (command, args, cwd, options) => {
        if (command === "git")
          return runGitRepositoryCommand(command, args, cwd, options);
        if (args[1] === "list") return "[]";
        creations++;
        return "https://github.example.test/example/repository/pull/1";
      };
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: directory,
          onRepositoryCommand,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("-original");
              expect(patch).toContain("+fixed");
              expect(artifact.changedFiles).toContain("nested/app.ts");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (dangling) nestedGit("checkout", "--detach");
            await writeFile(join(nested, "app.ts"), "fixed\n");
            nestedGit("commit", "-am", "Synthetic nested update");
            after = nestedGit("rev-parse", "HEAD");
            if (mode.startsWith("published"))
              nestedGit("push", "origin", `${after}:refs/heads/main`);
            nestedIndex = await readFile(nestedIndexPath);
            if (worktreeRemoved) {
              git("add", "nested");
              if (dangling) {
                nestedGit("checkout", "--detach", before);
                nestedIndex = await readFile(nestedIndexPath);
              }
              await rm(nested, { recursive: true });
              await mkdir(nested);
              if (renamed) {
                git(
                  "config",
                  "--file",
                  ".gitmodules",
                  "--rename-section",
                  "submodule.nested",
                  "submodule.renamed",
                );
                if (otherStore) {
                  const other = join(directory, ".git", "modules", "renamed");
                  git("clone", "--bare", nestedGitDirectory, other);
                  git(
                    "--git-dir",
                    other,
                    "update-ref",
                    "refs/remotes/other/main",
                    after,
                  );
                }
              }
            }
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(missing ? 2 : 0);
      const savedCommit = git("rev-parse", "HEAD");
      if (missing) {
        expect(outcome.stderr).toContain("--resume-pr");
        expect(outcome.stderr).toContain(
          worktreeRemoved
            ? "not available in its remote-tracking refs"
            : "not be found on any remote",
        );
        expect(creations).toBe(0);
        expect(git("ls-remote", "origin")).toBe("");
        if (worktreeRemoved) {
          const refused = await runWorkflow(
            ["patch", "--resume-pr", git("branch", "--show-current"), "--json"],
            {
              currentDirectory: directory,
              onRepositoryCommand,
              onCodex: () => {
                throw new Error("Resuming must reuse the saved commit");
              },
            },
          );
          expect(refused.exitCode, refused.stderr).toBe(2);
          expect(git("rev-parse", "HEAD")).toBe(savedCommit);
          expect(git("ls-remote", "origin")).toBe("");
          expect(creations).toBe(0);
        }
        nestedGit(
          "--git-dir",
          nestedGitDirectory,
          "push",
          "origin",
          `${after}:refs/heads/main`,
        );
        const resumed = await runWorkflow(
          ["patch", "--resume-pr", git("branch", "--show-current"), "--json"],
          {
            currentDirectory: directory,
            onRepositoryCommand,
            onCodex: () => {
              throw new Error("Resuming must reuse the saved commit");
            },
          },
        );
        expect(resumed.exitCode, resumed.stderr).toBe(0);
        expect(git("rev-parse", "HEAD")).toBe(savedCommit);
      }
      expect(creations).toBe(1);
      expect(git("config", "--list")).not.toContain(
        "push.recursesubmodules=check",
      );
      if (mode.startsWith("published") || missing) {
        const checkout = await fixtures.create("patch-nested-checkout-");
        git(
          "clone",
          "--branch",
          git("branch", "--show-current"),
          remote,
          checkout,
        );
        repositoryGit(checkout)(
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "update",
          "--init",
        );
        expect(await readAppliedText(join(checkout, "nested/app.ts"))).toBe(
          "fixed\n",
        );
      }
      expect(assessments).toBe(1);
      expect(after).not.toBe(before);
      expect(git("ls-tree", "HEAD", "nested")).toBe(
        `160000 commit ${after}\tnested`,
      );
      expect(
        repositoryGit(remote)("ls-tree", git("rev-parse", "HEAD"), "nested"),
      ).toBe(`160000 commit ${after}\tnested`);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      expect(git("status", "--porcelain")).toBe("");
      expect(await readFile(nestedIndexPath)).toEqual(nestedIndex);
      if (worktreeRemoved)
        await expect(readFile(join(nested, "app.ts"))).rejects.toMatchObject({
          code: "ENOENT",
        });
      else
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
    },
  );

  test.each(
    ["root", "package", "recursive"].flatMap((scope) =>
      ["move", "registered-move", "flatten", "revision"].map(
        (change) => [scope, change] as const,
      ),
    ),
  )("assesses coherent nested %s content after %s", async (scope, change) => {
    const { directory, git } = await publicationRepository();
    const path = scope === "recursive" ? "nested/child" : "nested";
    const nested = join(directory, path);
    await mkdir(nested, { recursive: true });
    await mkdir(join(directory, "package"));
    const nestedGit = repositoryGit(nested);
    nestedGit("init", "--initial-branch=main");
    nestedGit("config", "user.name", "Synthetic User");
    nestedGit("config", "user.email", "synthetic@example.test");
    await writeFile(join(nested, "app.ts"), "before\n");
    nestedGit("add", ".");
    nestedGit("commit", "-m", "Synthetic baseline");
    const parentGit =
      scope === "recursive" ? repositoryGit(join(directory, "nested")) : git;
    if (scope === "recursive") {
      parentGit("init", "--initial-branch=main");
      parentGit("config", "user.name", "Synthetic User");
      parentGit("config", "user.email", "synthetic@example.test");
      parentGit("add", "child");
      parentGit("commit", "-m", "Synthetic parent");
    }
    if (change === "registered-move") {
      const name = scope === "recursive" ? "child" : "nested";
      parentGit("config", "-f", ".gitmodules", `submodule.${name}.path`, name);
      parentGit(
        "config",
        "-f",
        ".gitmodules",
        `submodule.${name}.url`,
        "https://example.test/synthetic.git",
      );
      parentGit("add", ".gitmodules", name);
      parentGit("submodule", "init");
      parentGit("submodule", "absorbgitdirs", name);
    }
    if (change === "flatten") {
      nestedGit(
        "init",
        "--separate-git-dir",
        join(directory, ".git", "retained-nested"),
      );
      nestedGit("config", "core.worktree", nested);
    }
    git("add", "nested");
    git("commit", "-m", "Synthetic gitlink");
    const moving = change === "move" || change === "registered-move";
    const configurationPath = join(
      nestedGit("rev-parse", "--absolute-git-dir"),
      "config",
    );
    const destination = moving ? `${path}-moved` : path;
    let assessments = 0;
    let afterTurn = false;
    let movedIndexes: { path: string; contents: Buffer<ArrayBuffer> }[] = [];
    const bookkeeping: string[][] = [];
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory:
          scope === "package" ? join(directory, "package") : directory,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (
            afterTurn &&
            !args.includes("core.hooksPath=/dev/null") &&
            args.some((value) =>
              ["add", "read-tree", "update-index", "write-tree"].includes(
                value,
              ),
            )
          )
            bookkeeping.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          ) {
            assessments++;
            const artifact = JSON.parse(
              output.appServer.prompt
                .split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            ) as { path: string; sha256: string; changedFiles: string[] };
            const patch = await readFile(artifact.path);
            expect(hash("sha256", patch)).toBe(artifact.sha256);
            expect(patch.toString()).toContain("Subproject commit");
            const verification = await fixtures.create("coherent-risk-apply-");
            await mkdir(join(verification, path), { recursive: true });
            await writeFile(join(verification, path, "app.ts"), "before\n");
            repositoryGit(verification)(
              "apply",
              "--allow-empty",
              "--include=*.ts",
              artifact.path,
            );
            expect(
              await readAppliedText(join(verification, destination, "app.ts")),
            ).toBe(change === "revision" ? "before\n" : "after\n");
            if (moving)
              expect(
                await readFile(join(verification, path, "app.ts")).catch(
                  () => null,
                ),
              ).toBeNull();
            expect(artifact.changedFiles).toContain(
              change === "revision" ? path : `${destination}/app.ts`,
            );
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          if (change === "revision")
            nestedGit("commit", "--allow-empty", "-m", "Synthetic revision");
          else {
            if (change === "registered-move")
              parentGit(
                "mv",
                scope === "recursive" ? "child" : "nested",
                scope === "recursive" ? "child-moved" : "nested-moved",
              );
            else if (change === "move")
              await rename(nested, join(directory, destination));
            else {
              parentGit(
                "rm",
                "--cached",
                scope === "recursive" ? "child" : "nested",
              );
              await rm(join(nested, ".git"), { recursive: true });
            }
            await writeFile(join(directory, destination, "app.ts"), "after\n");
            if (change === "flatten") {
              parentGit("add", ".");
              parentGit("commit", "-m", "Synthetic flatten");
            }
          }
          if (moving)
            movedIndexes = await Promise.all(
              [
                directory,
                ...(scope === "recursive" ? [join(directory, "nested")] : []),
                join(directory, destination),
              ].map(async (checkout) => {
                const path = join(
                  repositoryGit(checkout)("rev-parse", "--absolute-git-dir"),
                  "index",
                );
                return { path, contents: await readFile(path) };
              }),
            );
          output?.stdout.write("Fixed.");
          afterTurn = true;
          return 0;
        },
      },
    );
    if (moving) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr.replaceAll(sep, "/")).toContain(
        `Git configuration changed during the patch: ${configurationPath}`.replaceAll(
          sep,
          "/",
        ),
      );
      expect(assessments).toBe(0);
      expect(bookkeeping).toEqual([]);
      for (const { path, contents } of movedIndexes)
        expect(await readFile(path)).toEqual(contents);
      expect(git("ls-remote", "origin")).toBe("");
      expect(
        await readFile(join(directory, destination, "app.ts"), "utf8"),
      ).toBe("after\n");
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
    }
  });

  test.each(
    ["saved", "supplied"].flatMap((mode) =>
      ["root", "package", "recursive"].flatMap((scope) =>
        ["edit", "rename", "replace", "remove"].map(
          (change) => [mode, scope, change] as const,
        ),
      ),
    ),
  )(
    "assesses nested patch content from %s mode at %s for %s",
    async (mode, scope, change) => {
      const { directory, git } = await publicationRepository();
      const objectDirectory = await realpath(
        git("rev-parse", "--path-format=absolute", "--git-path", "objects"),
      );
      const indexCommands = new Set<string>();
      const nestedPath = scope === "recursive" ? "nested/child" : "nested";
      const nested = join(directory, nestedPath);
      await mkdir(nested, { recursive: true });
      await mkdir(join(directory, "package"));
      const nestedGit = repositoryGit(nested);
      nestedGit("init", "--initial-branch=main");
      nestedGit("config", "user.name", "Synthetic User");
      nestedGit("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "original\n");
      nestedGit("add", ".");
      nestedGit("commit", "-m", "Synthetic nested baseline");
      if (scope === "recursive") {
        const parentGit = repositoryGit(join(directory, "nested"));
        parentGit("init", "--initial-branch=main");
        parentGit("config", "user.name", "Synthetic User");
        parentGit("config", "user.email", "synthetic@example.test");
        parentGit("add", "child");
        parentGit("commit", "-m", "Synthetic recursive gitlink");
      }
      if (change === "remove") {
        nestedGit(
          "init",
          "--separate-git-dir",
          join(directory, ".git", "retained-nested"),
        );
        nestedGit("config", "core.worktree", nested);
      }
      if (scope === "root" && change === "edit") {
        // Expanded submodule entries can match a diff driver in the parent.
        await writeFile(
          join(directory, ".gitattributes"),
          "nested/*.ts diff=synthetic\n",
        );
        git(
          "config",
          `diff.synthetic.${mode === "saved" ? "textconv" : "command"}`,
          "printf 'converted\\n'",
        );
        git("add", ".gitattributes");
      }
      git("add", "nested");
      git("commit", "-m", "Synthetic gitlink");
      await writeFile(join(nested, "app.ts"), "original\nuser change\n");
      const nestedIndexPath = join(
        nestedGit("rev-parse", "--absolute-git-dir"),
        "index",
      );
      const indexes = [
        ...new Set([directory, join(directory, "nested"), nested]),
      ].map((path) =>
        path === nested ? nestedIndexPath : join(path, ".git/index"),
      );
      const before = await Promise.all(indexes.map((path) => readFile(path)));
      const originalChildIndex = before[indexes.indexOf(nestedIndexPath)]!;
      const result = resultWithFindings(["high"]);
      const reported = `${nestedPath}/${change === "rename" ? "new.ts" : "app.ts"}`;
      result.findings.findings[0]!.locations[0]!.path = `${nestedPath}/app.ts`;
      let assessments = 0;
      let retiredAdministration: string | undefined;
      let afterTurn = false;
      const bookkeeping: string[][] = [];
      const outcome = await runWorkflow(
        [
          "patch",
          ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory:
            scope === "root" ? directory : join(directory, "package"),
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            const index = options?.environment?.["GIT_INDEX_FILE"];
            if (
              index &&
              basename(index) === "index" &&
              basename(dirname(index)).startsWith("codex-security-patch-risk-")
            ) {
              const indexDirectory = dirname(index);
              expect(options?.patchSnapshot).toEqual([
                objectDirectory,
                indexDirectory,
              ]);
              expect(options?.sandbox?.profile["filesystem"]).toEqual({
                ":root": "read",
                [objectDirectory]: { ".": "write" },
                [indexDirectory]: { ".": "write" },
              });
              indexCommands.add(args[0]!);
            }
            if (
              afterTurn &&
              !args.includes("core.hooksPath=/dev/null") &&
              args.some((value) =>
                ["add", "read-tree", "update-index", "write-tree"].includes(
                  value,
                ),
              )
            )
              bookkeeping.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[]; sha256: string };
              const patch = await readFile(artifact.path);
              expect(artifact.changedFiles.sort()).toEqual(
                [
                  ...new Set([
                    `${nestedPath}/app.ts`,
                    reported,
                    ...(mode === "supplied" &&
                    (change === "replace" || change === "remove")
                      ? [nestedPath]
                      : []),
                  ]),
                ].sort(),
              );
              expect(patch.toString()).toContain(
                `diff --git a/${reported} b/${reported}`,
              );
              if (change !== "remove")
                expect(patch.toString()).toContain("+patch change");
              if (change === "edit" || change === "replace")
                expect(patch.toString()).not.toContain("+user change");
              else expect(patch.toString()).toContain("deleted file mode");
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              const verification = await fixtures.create("patch-risk-apply-");
              await mkdir(join(verification, nestedPath), { recursive: true });
              await writeFile(
                join(verification, nestedPath, "app.ts"),
                "original\nuser change\n",
              );
              repositoryGit(verification)(
                "apply",
                `--include=${nestedPath}/*.ts`,
                artifact.path,
              );
              if (change === "remove") {
                expect(
                  await readFile(join(verification, reported)).catch(
                    () => null,
                  ),
                ).toBeNull();
              } else
                expect(
                  await readAppliedText(join(verification, reported)),
                ).toBe("original\nuser change\npatch change\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            output?.appServer?.onPermissions?.({
              directory,
              environment: {},
              profile: { filesystem: { ":root": "read" } },
            });
            if (change === "rename") await rm(join(nested, "app.ts"));
            if (change === "replace") {
              retiredAdministration = join(
                await fixtures.create("patch-retired-administration-"),
                "git",
              );
              // Keep the old inode live while constructing a distinct replacement.
              await rename(join(nested, ".git"), retiredAdministration);
            }
            if (change === "replace" || change === "remove")
              await rm(nested, { recursive: true });
            if (change === "replace") {
              await mkdir(nested);
              nestedGit("init", "--initial-branch=main");
              nestedGit("config", "user.name", "Synthetic User");
              nestedGit("config", "user.email", "synthetic@example.test");
            }
            if (change !== "remove")
              await writeFile(
                join(directory, reported),
                "original\nuser change\npatch change\n",
              );
            if (change === "replace") {
              nestedGit("add", ".");
              nestedGit("commit", "-m", "Synthetic replacement");
              before[indexes.indexOf(nestedIndexPath)] = await readFile(
                join(nested, ".git/index"),
              );
            }
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: [reported],
                    verification: "Synthetic regression passed.",
                  },
                ],
              }),
            );
            afterTurn = true;
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        change === "replace" ? 2 : 0,
      );
      expect(assessments).toBe(change === "replace" ? 0 : 1);
      if (assessments > 0)
        expect(indexCommands).toEqual(
          new Set(["read-tree", "update-index", "write-tree"]),
        );
      if (change === "replace") {
        expect(outcome.stderr).toContain(
          "Git metadata outside the pre-patch administration directories",
        );
        expect(bookkeeping).toEqual([]);
        expect(await readFile(join(directory, reported), "utf8")).toBe(
          "original\nuser change\npatch change\n",
        );
        expect(await readFile(join(retiredAdministration!, "index"))).toEqual(
          originalChildIndex,
        );
      }
      for (const [index, path] of indexes.entries()) {
        expect(await readFile(path)).toEqual(before[index]!);
      }
    },
  );

  test.each([
    "gitfile",
    "unregistered-gitfile",
    "configured-worktree",
    "sparse-link-before",
    "sparse-link-during",
    "sparse-link-ancestor-before",
    "sparse-link-ancestor-during",
  ])(
    "does not snapshot another worktree through nested %s metadata",
    async (kind) => {
      const parent = await fixtures.create("synthetic-nested-binding-");
      const root = join(parent, "outer");
      const nested = join(root, "nested");
      const external = join(parent, "external");
      for (const checkout of [root, nested, external]) {
        await mkdir(checkout, { recursive: true });
        const git = repositoryGit(checkout);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(checkout, "app.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
      }
      const git = repositoryGit(root);
      const outside = repositoryGit(external);
      const sparseLink = kind.startsWith("sparse-link");
      const gitfile = kind.endsWith("gitfile");
      const metadata = repositoryGit(gitfile || sparseLink ? external : nested);
      if (gitfile) {
        await rm(join(nested, ".git"), { recursive: true });
        await writeFile(
          join(nested, ".git"),
          `gitdir: ${join(external, ".git")}\n`,
        );
      }
      if (!sparseLink && kind !== "unregistered-gitfile")
        metadata("config", "core.worktree", external);
      git("add", "nested");
      git("commit", "-m", "Synthetic nested dependency");
      const linkExternal = () =>
        symlink(
          kind.includes("ancestor") ? root : external,
          nested,
          process.platform === "win32" ? "junction" : "dir",
        );
      if (sparseLink) {
        await rm(nested, { recursive: true });
        git("sparse-checkout", "set", "--no-cone", "/app.ts");
        if (kind.endsWith("before")) await linkExternal();
      }
      await writeFile(
        join(external, "app.ts"),
        "outside uncommitted content\n",
      );
      const blob = outside("hash-object", "app.ts");
      expect(() => metadata("cat-file", "-e", blob)).toThrow();
      const rootIndex = await readFile(join(root, ".git", "index"));
      const externalIndex = await readFile(join(external, ".git", "index"));
      let modelCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            modelCalls += 1;
            if (kind.endsWith("during")) await linkExternal();
            await writeFile(join(root, "app.ts"), "fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        kind.includes("ancestor")
          ? "ancestor worktree"
          : sparseLink
            ? "outside the selected repository"
            : gitfile
              ? "Nested Git administration is outside the selected repository"
              : "worktree root does not match",
      );
      expect(modelCalls).toBe(kind.endsWith("during") ? 1 : 0);
      expect(() => metadata("cat-file", "-e", blob)).toThrow();
      expect(await readFile(join(root, ".git", "index"))).toEqual(rootIndex);
      expect(await readFile(join(external, ".git", "index"))).toEqual(
        externalIndex,
      );
      expect(await readFile(join(external, "app.ts"), "utf8")).toBe(
        "outside uncommitted content\n",
      );
    },
  );

  test.each(
    [false, true].flatMap((recursive) =>
      ["root", "package"].flatMap((scope) =>
        [
          "restore",
          "restore-edit",
          "restore-commit",
          "restore-new",
          "restore-delete",
          "remove-worktree",
          "remove-worktree-dirty",
          "remove-worktree-commit",
        ].map((operation) => ({ recursive, scope, operation })),
      ),
    ),
  )(
    "reports submodule content changes for $operation from $scope: recursive=$recursive",
    async ({ recursive, scope, operation }) => {
      const commitChange = operation.endsWith("-commit");
      const root = await fixtures.create("synthetic-submodule-state-");
      const origin = await fixtures.create("synthetic-submodule-origin-");
      const leaf = recursive
        ? await fixtures.create("synthetic-submodule-leaf-")
        : undefined;
      for (const directory of [root, origin, ...(leaf ? [leaf] : [])]) {
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(directory, "app.ts"), "baseline\n");
        if (commitChange) {
          await writeFile(join(directory, "gone.ts"), "remove\n");
          await writeFile(join(directory, "unchanged.ts"), "unchanged\n");
        }
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
      }
      if (leaf) {
        const upstream = repositoryGit(origin);
        upstream(
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "add",
          leaf,
          "inner",
        );
        upstream("commit", "-am", "Synthetic nested dependency");
      }
      const git = repositoryGit(root);
      await mkdir(join(root, "package"));
      await writeFile(join(root, "package/app.ts"), "outer baseline\n");
      git(
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        origin,
        "vendor",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic dependency");
      const initialize = () =>
        git(
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "update",
          "--init",
          "--recursive",
        );
      initialize();
      const prefix = recursive ? "vendor/inner" : "vendor";
      const nested = join(root, prefix);
      const configurations = [
        root,
        join(root, "vendor"),
        ...(recursive ? [nested] : []),
      ].map((checkout) =>
        join(
          repositoryGit(checkout)("rev-parse", "--absolute-git-dir"),
          "config",
        ),
      );
      const configurationBytes = await Promise.all(
        configurations.map((path) => readFile(path)),
      );
      if (operation.startsWith("restore")) {
        await rm(join(root, "vendor"), { recursive: true });
        await mkdir(join(root, "vendor"));
      }
      if (operation === "remove-worktree-dirty") {
        await writeFile(join(nested, "app.ts"), "local dirty content\n");
        await writeFile(join(nested, "new.ts"), "local new content\n");
      }
      await writeFile(join(root, "unrelated.txt"), "staged local content\n");
      git("add", "unrelated.txt");
      let index = await readFile(join(root, ".git/index"));
      let staged = git("diff", "--cached");
      const head = git("rev-parse", "HEAD");
      const onCodex = mock(
        async (
          _args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          ) {
            const artifact = JSON.parse(
              output.appServer.prompt
                .split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            ) as { path: string; changedFiles: string[] };
            expect(artifact.changedFiles).not.toContain(
              `${prefix}/unchanged.ts`,
            );
            expect(artifact.changedFiles).toContain(`${prefix}/gone.ts`);
            expect(artifact.changedFiles).toContain(`${prefix}/added.ts`);
            const verification = await fixtures.create("restored-risk-apply-");
            await mkdir(join(verification, prefix), { recursive: true });
            await writeFile(join(verification, prefix, "app.ts"), "baseline\n");
            await writeFile(join(verification, prefix, "gone.ts"), "remove\n");
            await writeFile(
              join(verification, prefix, "unchanged.ts"),
              "unchanged\n",
            );
            repositoryGit(verification)(
              "apply",
              "--check",
              "--include=*.ts",
              artifact.path,
            );
            repositoryGit(verification)(
              "apply",
              "--include=*.ts",
              artifact.path,
            );
            expect(
              await readAppliedText(join(verification, prefix, "app.ts")),
            ).toBe("fixed\n");
            expect(
              await readFile(join(verification, prefix, "gone.ts")).catch(
                () => null,
              ),
            ).toBeNull();
            expect(
              await readFile(
                join(verification, prefix, "unchanged.ts"),
                "utf8",
              ),
            ).toBe("unchanged\n");
            expect(
              await readAppliedText(join(verification, prefix, "added.ts")),
            ).toBe("added\n");
            expect(await readFile(join(root, ".git/index"))).toEqual(index);
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          if (operation.startsWith("restore")) initialize();
          if (commitChange) {
            await writeFile(join(nested, "app.ts"), "fixed\n");
            await rm(join(nested, "gone.ts"));
            await writeFile(join(nested, "added.ts"), "added\n");
            const child = repositoryGit(nested);
            child("add", ".");
            child(
              "-c",
              "user.name=Synthetic User",
              "-c",
              "user.email=synthetic@example.test",
              "commit",
              "-am",
              "Synthetic child change",
            );
          }
          if (operation === "restore-edit")
            await writeFile(join(nested, "app.ts"), "fixed\n");
          if (operation === "restore-new")
            await writeFile(join(nested, "new.ts"), "new fix\n");
          if (operation === "restore-delete") await rm(join(nested, "app.ts"));
          if (operation === "remove-worktree-commit") {
            if (recursive)
              repositoryGit(join(root, "vendor"))(
                "-c",
                "user.name=Synthetic User",
                "-c",
                "user.email=synthetic@example.test",
                "commit",
                "-am",
                "Synthetic recursive update",
              );
            git("add", "vendor");
            index = await readFile(join(root, ".git/index"));
            staged = git("diff", "--cached");
          }
          if (operation.startsWith("remove-worktree")) {
            await rm(join(root, "vendor"), { recursive: true });
            await mkdir(join(root, "vendor"));
          }
          output?.stdout.write("Prepared dependencies and checked the result.");
          return 0;
        },
      );
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          ...(commitChange ? ["--assess-patch-risk"] : []),
          "--json",
        ],
        {
          currentDirectory: scope === "root" ? root : join(root, "package"),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex,
        },
      );
      const clean = operation === "restore" || operation === "remove-worktree";
      expect(outcome.exitCode, outcome.stderr).toBe(clean ? 2 : 0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: !clean,
        files: clean
          ? []
          : commitChange
            ? [
                ...(operation === "remove-worktree-commit" && recursive
                  ? ["vendor"]
                  : []),
                prefix,
                `${prefix}/added.ts`,
                `${prefix}/app.ts`,
                `${prefix}/gone.ts`,
              ]
            : operation === "restore-new"
              ? [`${prefix}/new.ts`]
              : operation === "remove-worktree-dirty"
                ? [`${prefix}/app.ts`, `${prefix}/new.ts`]
                : [`${prefix}/app.ts`],
      });
      expect(onCodex).toHaveBeenCalledTimes(commitChange ? 2 : 1);
      expect(await readFile(join(root, ".git/index"))).toEqual(index);
      expect(git("diff", "--cached")).toBe(staged);
      expect(git("rev-parse", "HEAD")).toBe(head);
      for (const [position, path] of configurations.entries())
        expect(await readFile(path)).toEqual(configurationBytes[position]!);
    },
  );

  test("captures materialized out-of-cone edits without deleting absent sparse files", async () => {
    const root = await fixtures.create("patch-sparse-changes-");
    const nested = join(root, "nested");
    await mkdir(join(nested, "included"), { recursive: true });
    await mkdir(join(nested, "outside"));
    const git = repositoryGit(root),
      inner = repositoryGit(nested);
    for (const command of [git, inner]) {
      command("init", "--initial-branch=main");
      command("config", "user.name", "Synthetic User");
      command("config", "user.email", "test@example.test");
    }
    for (const path of [
      "included/app",
      "outside/edited",
      "outside/removed",
      "outside/absent",
    ])
      await writeFile(join(nested, path), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Nested baseline");
    git("add", "nested");
    git("commit", "-m", "Registered child");
    inner("sparse-checkout", "set", "--cone", "included");
    await mkdir(join(nested, "outside"), { recursive: true });
    await writeFile(join(nested, "outside/removed"), "original\n");
    const operatorIndex = await readFile(join(nested, ".git/index"));
    const nestedTrees: string[] = [];
    const run = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: async (tool, args, cwd, options) => {
        const result = await runGitRepositoryCommand(tool, args, cwd, options);
        if (args.includes("write-tree") && args.includes(nested))
          nestedTrees.push(result.trim());
        return result;
      },
      onCodex: async (_args, output) => {
        await mkdir(join(nested, "outside"), { recursive: true });
        await rm(join(nested, "included/app"));
        await rm(join(nested, "outside/removed"));
        await writeFile(join(nested, "included/new"), "included\n");
        await writeFile(join(nested, "outside/edited"), "modified\n");
        await writeFile(join(nested, "outside/new"), "added\n");
        output!.stdout.write("Fixed child file.");
        return 0;
      },
    });
    expect(run.exitCode, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout).files).toEqual([
      "nested/included/app",
      "nested/included/new",
      "nested/outside/edited",
      "nested/outside/new",
      "nested/outside/removed",
    ]);
    expect(nestedTrees.length).toBeGreaterThanOrEqual(2);
    for (const tree of nestedTrees)
      expect(inner("ls-tree", tree, "outside/absent")).toContain(
        "outside/absent",
      );
    const finalTree = nestedTrees.at(-1)!;
    expect(inner("ls-tree", nestedTrees[0]!, "outside/removed")).toContain(
      "outside/removed",
    );
    expect(inner("ls-tree", finalTree, "outside/removed")).toBe("");
    expect(inner("ls-tree", finalTree, "included/app")).toBe("");
    expect(inner("show", finalTree + ":included/new")).toBe("included");
    expect(inner("show", finalTree + ":outside/edited")).toBe("modified");
    expect(inner("show", finalTree + ":outside/new")).toBe("added");
    expect(await readFile(join(nested, ".git/index"))).toEqual(operatorIndex);
  });

  test.each([
    "reapply",
    "reapply and stage another file",
    "switch",
    "stage another file",
    "commit another file",
    "rewrite the same index and delete",
    "stage the deletion",
  ] as const)(
    "respects native sparse index changes when the turn chooses to %s",
    async (operation) => {
      const root = await fixtures.create("patch-sparse-index-");
      const git = repositoryGit(root);
      const path = "outside/file";
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "test@example.test");
      for (const dir of ["inside", "outside"]) await mkdir(join(root, dir));
      await writeFile(join(root, "inside/other"), "baseline\n");
      await writeFile(join(root, path), "original\n");
      git("add", ".");
      git("commit", "-m", "Baseline");
      git("switch", "-c", "replacement");
      await writeFile(join(root, path), "next\n");
      git("commit", "-am", "Replacement");
      git("switch", "main");
      git("sparse-checkout", "set", "--cone", "inside");
      git("checkout-index", "--ignore-skip-worktree-bits", "--", path);
      // Keep the materialized file's stat data in its skipped index entry.
      // A clean reapply can then remove the file without changing that entry.
      git(
        "-c",
        "core.sparseCheckout=false",
        "update-index",
        "--no-skip-worktree",
        "--",
        path,
      );
      git("-c", "core.sparseCheckout=false", "update-index", "--refresh");
      git(
        "-c",
        "core.sparseCheckout=false",
        "update-index",
        "--skip-worktree",
        "--",
        path,
      );
      let tree = "";
      const result = await runWorkflow(["patch", "Synthetic issue", "--json"], {
        currentDirectory: root,
        onRepositoryCommand: async (tool, args, cwd, options) => {
          const output = await runGitRepositoryCommand(
            tool,
            args,
            cwd,
            options,
          );
          if (args.includes("write-tree")) tree = output.trim();
          return output;
        },
        onCodex: async (_args, output) => {
          if (
            operation === "reapply" ||
            operation === "reapply and stage another file"
          ) {
            git("update-index", "--refresh");
            git("sparse-checkout", "reapply");
          } else if (operation === "switch") git("switch", "replacement");
          else {
            await rm(join(root, path));
            if (operation === "rewrite the same index and delete")
              git("update-index", "--force-write-index");
            if (operation === "stage the deletion")
              git("rm", "--cached", "--sparse", "--", path);
          }
          await writeFile(join(root, "inside/other"), "edited\n");
          if (
            operation === "stage another file" ||
            operation === "reapply and stage another file"
          )
            git("add", "inside/other");
          if (operation === "commit another file")
            git("commit", "-m", "Other edit", "--", "inside/other");
          output!.stdout.write("Completed synthetic change.");
          return 0;
        },
      });
      if (
        operation === "rewrite the same index and delete" ||
        operation === "stage another file" ||
        operation === "commit another file" ||
        (operation === "reapply" && result.exitCode !== 0) ||
        (operation === "reapply and stage another file" &&
          result.exitCode !== 0)
      ) {
        expect(result.exitCode).toBe(2);
        expect(result.stdout + result.stderr).toContain(
          "Use git rm --cached --sparse -- <path> to stage an intended deletion",
        );
        return;
      }
      expect(result.exitCode, result.stderr).toBe(0);
      expect(tree).not.toBe("");
      expect(git("ls-tree", tree, path)).toBe(
        operation === "stage the deletion" ? "" : git("ls-tree", "HEAD", path),
      );
      expect(git("show", `${tree}:inside/other`)).toBe("edited");
    },
  );

  test.each(["root", "package"])(
    "reports sparse nested changes from %s when the recorded commit is unavailable",
    async (scope) => {
      const root = await fixtures.create("synthetic-sparse-submodule-");
      const nested = join(root, "vendor");
      await mkdir(nested);
      const git = repositoryGit(root);
      const inner = repositoryGit(nested);
      for (const repository of [git, inner]) {
        repository("init", "--initial-branch=main");
        repository("config", "user.name", "Synthetic User");
        repository("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "old dependency\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic dependency baseline");
      const recorded = inner("rev-parse", "HEAD");
      await mkdir(join(root, "package"));
      await writeFile(join(root, "app.ts"), "outer baseline\n");
      await writeFile(join(root, "package/app.ts"), "package baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic outer baseline");
      git("sparse-checkout", "set", "--no-cone", "/app.ts", "/package/app.ts");
      await rm(nested, { recursive: true });
      await mkdir(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "different history\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic replacement baseline");
      expect(inner("rev-parse", "--revs-only", `${recorded}^{tree}`)).toBe("");
      const index = await readFile(join(root, ".git/index"));
      const nestedIndex = await readFile(join(nested, ".git/index"));
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: scope === "root" ? root : join(root, "package"),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(join(root, "app.ts"), "fixed outer\n");
            await writeFile(join(nested, "app.ts"), "fixed nested\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual([
        "app.ts",
        "vendor/app.ts",
      ]);
      expect(await readFile(join(root, ".git/index"))).toEqual(index);
      expect(await readFile(join(nested, ".git/index"))).toEqual(nestedIndex);
    },
  );

  test.each(
    [
      "root",
      "package",
      ...(process.platform === "win32" ? [] : ["package-space"]),
    ].flatMap((scope) =>
      [
        "ordinary",
        "absolute",
        "relative",
        "object-directory",
        "custom-objects",
        "common-directory",
        "alternate-index",
      ].flatMap((settings) =>
        [
          "modify",
          ...(settings === "alternate-index" ? ["ignored", "new-ignored"] : []),
          ...(scope !== "package-space" && settings === "relative"
            ? ["replace", "remove"]
            : []),
        ].map((operation) => ({ scope, settings, operation })),
      ),
    ),
  )(
    "reports nested $operation changes from $scope with $settings Git settings",
    async ({ scope, settings, operation }) => {
      const parent = await fixtures.create("synthetic-nested-basis-");
      const root = join(
        parent,
        scope === "package-space" ? "checkout " : "checkout",
      );
      const directory = join(root, "package");
      const nested = join(directory, "nested");
      await mkdir(nested, { recursive: true });
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      if (settings === "alternate-index") {
        await writeFile(
          join(nested, ".gitignore"),
          "build.log\ngenerated.txt\n",
        );
        await writeFile(join(root, "build.log"), "outer tracked log\n");
      }
      inner("add", ".");
      inner("commit", "-m", "Synthetic inner baseline");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic outer baseline");
      if (operation === "remove") {
        inner(
          "init",
          "--separate-git-dir",
          join(root, ".git", "retained-nested"),
        );
        inner("config", "core.worktree", nested);
      }
      const childIndexPath = join(
        inner("rev-parse", "--absolute-git-dir"),
        "index",
      );
      if (settings === "custom-objects")
        await rename(
          join(root, ".git", "objects"),
          join(root, ".git", "custom-objects"),
        );
      const target = scope === "root" ? root : directory;
      const alternateIndex = join(parent, "parent-index");
      const gitEnvironment = {
        ...(settings === "alternate-index"
          ? { GIT_INDEX_FILE: alternateIndex }
          : {}),
        ...(settings !== "absolute" && settings !== "relative"
          ? {}
          : {
              GIT_DIR:
                settings === "relative"
                  ? relative(target, join(root, ".git"))
                  : join(root, ".git"),
              GIT_WORK_TREE:
                settings === "relative" ? relative(target, root) || "." : root,
            }),
        ...(settings === "object-directory" || settings === "custom-objects"
          ? {
              GIT_OBJECT_DIRECTORY: join(
                root,
                ".git",
                settings === "custom-objects" ? "custom-objects" : "objects",
              ),
            }
          : {}),
        ...(settings === "common-directory"
          ? { GIT_COMMON_DIR: join(root, ".git") }
          : {}),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.quotePath",
        GIT_CONFIG_VALUE_0: "false",
        SYNTHETIC_GIT_SETTING: "preserved",
      };
      if (operation === "replace" || operation === "remove") {
        await writeFile(join(root, "local.txt"), "staged user content\n");
        git("add", "local.txt");
      }
      const parentIndex = await readFile(join(root, ".git", "index"));
      let childIndex = await readFile(childIndexPath);
      const originalChildIndex = childIndex;
      if (settings === "alternate-index") {
        await writeFile(alternateIndex, parentIndex);
        await writeFile(join(nested, "build.log"), "ignored baseline\n");
      }
      const snapshots = new Map<string, Set<string>>();
      let boundToRoot = false;
      let afterTurn = false;
      let retiredAdministration: string | undefined;
      const bookkeeping: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: target,
          environment: gitEnvironment,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              afterTurn &&
              !args.includes("core.hooksPath=/dev/null") &&
              args.some((value) =>
                ["add", "read-tree", "update-index", "write-tree"].includes(
                  value,
                ),
              )
            )
              bookkeeping.push([...args]);
            if (target !== root && cwd === root) boundToRoot = true;
            expect(cwd).not.toBe(nested);
            if (args[0] === "-C") {
              expect(cwd).toBe(root);
              expect([root, nested]).toContain(args[1]!);
            }
            const index = options?.environment?.["GIT_INDEX_FILE"];
            if (index !== undefined) {
              expect(cwd).toBe(root);
              const checkout = args[0] === "-C" ? args[1]! : cwd;
              if (args.includes("core.hooksPath=/dev/null")) {
                expect(args).toContain("core.fsmonitor=false");
                expect(index).not.toBe(
                  checkout === nested
                    ? childIndexPath
                    : join(checkout, ".git", "index"),
                );
                expect(index).not.toBe(alternateIndex);
              } else {
                const indices = snapshots.get(checkout) ?? new Set<string>();
                indices.add(index);
                snapshots.set(checkout, indices);
              }
            }
            const environment = { ...gitEnvironment, ...options?.environment };
            if (
              (args[0] === "-C" && args[1] === nested) ||
              (args[0] === "rev-parse" &&
                args[1] === "--resolve-git-dir" &&
                resolve(args[2]!) === join(nested, ".git"))
            ) {
              expect(environment["GIT_DIR"]).toBeUndefined();
              expect(environment["GIT_WORK_TREE"]).toBeUndefined();
              expect(environment["GIT_OBJECT_DIRECTORY"]).toBeUndefined();
              expect(environment["GIT_COMMON_DIR"]).toBeUndefined();
            } else {
              if (index === undefined)
                expect(environment["GIT_INDEX_FILE"]).toBe(
                  gitEnvironment.GIT_INDEX_FILE,
                );
              expect(environment["GIT_OBJECT_DIRECTORY"]).toBe(
                gitEnvironment.GIT_OBJECT_DIRECTORY,
              );
              expect(environment["GIT_COMMON_DIR"]).toBe(
                gitEnvironment.GIT_COMMON_DIR,
              );
              expect(
                environment["GIT_DIR"] === undefined
                  ? undefined
                  : resolve(environment["GIT_DIR"]),
              ).toBe(
                settings === "relative" || boundToRoot
                  ? join(root, ".git")
                  : gitEnvironment.GIT_DIR,
              );
              expect(
                environment["GIT_WORK_TREE"] === undefined
                  ? undefined
                  : resolve(environment["GIT_WORK_TREE"]),
              ).toBe(
                settings === "relative" ||
                  boundToRoot ||
                  (target !== root && args.includes("--absolute-git-dir"))
                  ? root
                  : gitEnvironment.GIT_WORK_TREE,
              );
            }
            expect(environment).toMatchObject({
              GIT_CONFIG_KEY_0: "core.quotePath",
              GIT_CONFIG_VALUE_0: "false",
              SYNTHETIC_GIT_SETTING: "preserved",
            });
            if (environment["GIT_CONFIG_COUNT"] === "1") {
              // The coordinator's two path lookups do not read the index.
              expect(args[0]).toBe("rev-parse");
              expect(["--show-toplevel", "--absolute-git-dir"]).toContain(
                args[1] ?? "",
              );
            } else {
              expect(environment).toMatchObject({
                GIT_CONFIG_COUNT: "2",
                GIT_CONFIG_KEY_1: "core.fsmonitor",
                GIT_CONFIG_VALUE_1: "false",
              });
            }
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment,
            });
          },
          onCodex: async (_args, output) => {
            expect(output?.appServer?.directory).toBe(target);
            if (operation === "ignored") {
              await writeFile(join(nested, "build.log"), "ignored changed\n");
              output?.stdout.write("No source change needed.");
              return 0;
            }
            if (operation === "new-ignored") {
              await writeFile(join(nested, "generated.txt"), "generated fix\n");
              inner("add", "-f", "generated.txt");
              childIndex = await readFile(childIndexPath);
              output?.stdout.write("Fixed and checked.");
              return 0;
            }
            await writeFile(join(directory, "app.ts"), "fixed\n");
            if (operation === "replace") {
              retiredAdministration = join(
                await fixtures.create("patch-retired-administration-"),
                "git",
              );
              await rename(join(nested, ".git"), retiredAdministration);
            }
            if (operation !== "modify") await rm(nested, { recursive: true });
            if (operation === "replace") {
              await mkdir(nested);
              inner("init", "--initial-branch=main");
              inner("config", "user.name", "Synthetic User");
              inner("config", "user.email", "synthetic@example.test");
            }
            if (operation !== "remove")
              await writeFile(join(nested, "app.ts"), "fixed\n");
            if (operation === "replace") {
              inner("add", ".");
              inner("commit", "-m", "Synthetic replacement checkout");
              await writeFile(
                join(nested, "staged-child.txt"),
                "staged child content\n",
              );
              inner("add", "staged-child.txt");
              childIndex = await readFile(childIndexPath);
            }
            output?.stdout.write("Fixed and checked.");
            afterTurn = true;
            return 0;
          },
        },
      );
      if (operation === "replace") {
        expect(outcome.exitCode).toBe(2);
        expect(outcome.stderr).toContain(
          "Git metadata outside the pre-patch administration directories",
        );
        expect(bookkeeping).toEqual([]);
        expect(await readFile(join(directory, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
        expect(await readFile(join(root, ".git", "index"))).toEqual(
          parentIndex,
        );
        expect(await readFile(childIndexPath)).toEqual(childIndex);
        expect(await readFile(join(retiredAdministration!, "index"))).toEqual(
          originalChildIndex,
        );
        expect(snapshots.get(root)!.size).toBe(1);
        expect(snapshots.get(nested)!.size).toBe(1);
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(
        operation === "ignored" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout).files).toEqual(
        operation === "ignored"
          ? []
          : operation === "new-ignored"
            ? ["package/nested/generated.txt"]
            : [
                "package/app.ts",
                ...(operation !== "modify" ? ["package/nested"] : []),
                "package/nested/app.ts",
                ...(operation === "replace"
                  ? ["package/nested/staged-child.txt"]
                  : []),
              ],
      );
      if (operation === "ignored")
        expect(JSON.parse(outcome.stdout).error.code).toBe("NO_PATCH_APPLIED");
      if (settings === "alternate-index")
        expect(await readFile(alternateIndex)).toEqual(parentIndex);
      expect([...snapshots.keys()].sort()).toEqual([root, nested].sort());
      expect(snapshots.get(root)!.size).toBe(2);
      expect(snapshots.get(nested)!.size).toBe(operation === "remove" ? 1 : 2);
      expect(
        new Set([...snapshots.values()].flatMap((indices) => [...indices]))
          .size,
      ).toBe(operation === "remove" ? 3 : 4);
      if (settings === "custom-objects")
        await rename(
          join(root, ".git", "custom-objects"),
          join(root, ".git", "objects"),
        );
      expect(await readFile(join(root, ".git", "index"))).toEqual(parentIndex);
      expect(git("diff", "--cached", "--name-only")).toBe(
        operation === "replace" || operation === "remove" ? "local.txt" : "",
      );
      expect(await readFile(childIndexPath)).toEqual(childIndex);
      if (operation !== "remove") {
        expect(inner("diff", "--cached", "--name-only")).toBe(
          operation === "replace"
            ? "staged-child.txt"
            : operation === "new-ignored"
              ? "generated.txt"
              : "",
        );
      }
    },
  );
  test.each([
    "regular",
    "gitlink",
    ...(process.platform === "win32" ? [] : ["dangling-link"]),
  ])(
    "preserves a newly ignored %s while publishing the ignore rule",
    async (kind) => {
      const root = await fixtures.create("synthetic-ignore-transition-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(root, ".gitignore"), "# baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const head = git("rev-parse", "HEAD");
      if (kind === "regular")
        await writeFile(join(root, "local.env"), "synthetic local file\n");
      else if (kind === "gitlink")
        git("clone", "--local", root, join(root, "local.env"));
      else await symlink("absent-synthetic-target", join(root, "local.env"));
      const nestedIgnore =
        kind === "gitlink"
          ? await readFile(join(root, "local.env/.gitignore"))
          : undefined;
      const remote = await fixtures.create("synthetic-ignore-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = ".gitignore";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: root,
          onWorkbench: () => savedScan(result, "scan-1", root),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(join(root, ".gitignore"), "local.env\n");
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("show", "HEAD:.gitignore")).toBe("local.env");
      if (kind === "regular")
        expect(await readFile(join(root, "local.env"), "utf8")).toBe(
          "synthetic local file\n",
        );
      else if (kind === "gitlink") {
        expect(
          repositoryGit(join(root, "local.env"))("rev-parse", "HEAD"),
        ).toBe(head);
        expect(await readFile(join(root, "local.env/.gitignore"))).toEqual(
          nestedIgnore!,
        );
      } else
        expect(await readlink(join(root, "local.env"))).toBe(
          "absent-synthetic-target",
        );
    },
  );
});
