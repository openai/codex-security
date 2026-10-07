import { afterEach, describe, expect, test, mock } from "bun:test";
import { hash } from "node:crypto";
import {
  mkdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, relative, resolve } from "node:path";
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

  test("publishes a committed nested update after assessing its content", async () => {
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
    git("add", "nested");
    git("commit", "-m", "Synthetic gitlink");
    const before = nestedGit("rev-parse", "HEAD");
    let after = before;
    let nestedIndex = await readFile(join(nested, ".git/index"));
    let assessments = 0;
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
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
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
          await writeFile(join(nested, "app.ts"), "fixed\n");
          nestedGit("commit", "-am", "Synthetic nested update");
          after = nestedGit("rev-parse", "HEAD");
          nestedIndex = await readFile(join(nested, ".git/index"));
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
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
    expect(await readFile(join(nested, ".git/index"))).toEqual(nestedIndex);
    expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
  });

  test.each(
    ["root", "package", "recursive"].flatMap((scope) =>
      ["move", "flatten", "revision"].map((change) => [scope, change] as const),
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
    git("add", "nested");
    git("commit", "-m", "Synthetic gitlink");
    const destination = change === "move" ? `${path}-moved` : path;
    let assessments = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory:
          scope === "package" ? join(directory, "package") : directory,
        onRepositoryCommand: runGitRepositoryCommand,
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
            if (change === "move")
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
            if (change === "move")
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
          output?.stdout.write("Fixed.");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(assessments).toBe(1);
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
      git("add", "nested");
      git("commit", "-m", "Synthetic gitlink");
      await writeFile(join(nested, "app.ts"), "original\nuser change\n");
      const indexes = [
        ...new Set([directory, join(directory, "nested"), nested]),
      ].map((path) => join(path, ".git/index"));
      const before = await Promise.all(indexes.map((path) => readFile(path)));
      const result = resultWithFindings(["high"]);
      const reported = `${nestedPath}/${change === "rename" ? "new.ts" : "app.ts"}`;
      result.findings.findings[0]!.locations[0]!.path = `${nestedPath}/app.ts`;
      let assessments = 0;
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
          onRepositoryCommand: runGitRepositoryCommand,
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
            if (change === "rename") await rm(join(nested, "app.ts"));
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
              before[indexes.indexOf(join(nested, ".git/index"))] =
                await readFile(join(nested, ".git/index"));
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
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      for (const [index, path] of indexes.entries()) {
        if (change === "remove" && path === join(nested, ".git/index"))
          continue;
        expect(await readFile(path)).toEqual(before[index]!);
      }
    },
  );

  test.each([
    "gitfile",
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
      const metadata = repositoryGit(
        kind === "gitfile" || sparseLink ? external : nested,
      );
      if (kind === "gitfile") {
        await rm(join(nested, ".git"), { recursive: true });
        await writeFile(
          join(nested, ".git"),
          `gitdir: ${join(external, ".git")}\n`,
        );
      }
      if (!sparseLink) metadata("config", "core.worktree", external);
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
            : "Git metadata is not bound to the selected checkout",
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
          "init",
          "init-edit",
          "init-commit",
          "init-new",
          "init-delete",
          "deinit",
          "deinit-dirty",
        ].map((operation) => ({ recursive, scope, operation })),
      ),
    ),
  )(
    "reports submodule content changes for $operation from $scope: recursive=$recursive",
    async ({ recursive, scope, operation }) => {
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
        if (operation === "init-commit") {
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
      if (operation.startsWith("init"))
        git("submodule", "deinit", "-f", "--all");
      if (operation === "deinit-dirty") {
        await writeFile(join(nested, "app.ts"), "local dirty content\n");
        await writeFile(join(nested, "new.ts"), "local new content\n");
      }
      await writeFile(join(root, "unrelated.txt"), "staged local content\n");
      git("add", "unrelated.txt");
      const index = await readFile(join(root, ".git/index"));
      const staged = git("diff", "--cached");
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
            const verification = await fixtures.create(
              "initialized-risk-apply-",
            );
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
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          if (operation.startsWith("init")) initialize();
          if (operation === "init-commit") {
            await writeFile(join(nested, "app.ts"), "fixed\n");
            await rm(join(nested, "gone.ts"));
            const child = repositoryGit(nested);
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
          if (operation === "init-edit")
            await writeFile(join(nested, "app.ts"), "fixed\n");
          if (operation === "init-new")
            await writeFile(join(nested, "new.ts"), "new fix\n");
          if (operation === "init-delete") await rm(join(nested, "app.ts"));
          if (operation.startsWith("deinit"))
            git("submodule", "deinit", "-f", "--all");
          output?.stdout.write("Prepared dependencies and checked the result.");
          return 0;
        },
      );
      const gitTrace: unknown[] = [];
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          ...(operation === "init-commit" ? ["--assess-patch-risk"] : []),
          "--json",
        ],
        {
          currentDirectory: scope === "root" ? root : join(root, "package"),
          onRepositoryCommand: async (command, args, cwd, options) => {
            const directory = options?.directory ?? cwd;
            try {
              const stdout = await runGitRepositoryCommand(command, args, cwd, {
                ...options,
                trim: false,
              });
              if (
                args.includes("rev-parse") &&
                ["--is-inside-git-dir", "--show-toplevel"].includes(
                  args.at(-1) ?? "",
                )
              )
                gitTrace.push({ args, cwd: directory, stdout });
              return options?.trim === false ? stdout : stdout.trim();
            } catch (error) {
              const failure = error as Error & {
                code?: unknown;
                stdout?: unknown;
                stderr?: unknown;
              };
              gitTrace.push({
                args,
                cwd: directory,
                message: failure.message,
                code: failure.code,
                stdout: failure.stdout,
                stderr: failure.stderr,
              });
              throw error;
            }
          },
          onCodex,
        },
      );
      const diagnostics = JSON.stringify({
        outcome,
        modelCalls: onCodex.mock.calls.length,
        gitTrace,
      });
      const clean = operation === "init" || operation === "deinit";
      expect(outcome.exitCode, diagnostics).toBe(clean ? 2 : 0);
      expect(JSON.parse(outcome.stdout), diagnostics).toMatchObject({
        applied: !clean,
        files: clean
          ? []
          : operation === "init-commit"
            ? [prefix, `${prefix}/app.ts`, `${prefix}/gone.ts`].map((file) =>
                scope === "package" ? `../${file}` : file,
              )
            : operation === "init-new"
              ? [`${prefix}/new.ts`]
              : operation === "deinit-dirty"
                ? [`${prefix}/app.ts`, `${prefix}/new.ts`]
                : [`${prefix}/app.ts`],
      });
      expect(onCodex, diagnostics).toHaveBeenCalledTimes(
        operation === "init-commit" ? 2 : 1,
      );
      expect(await readFile(join(root, ".git/index"))).toEqual(index);
      expect(git("diff", "--cached")).toBe(staged);
      expect(git("rev-parse", "HEAD")).toBe(head);
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
        await writeFile(join(root, ".gitignore"), "outer-generated.txt\n");
      }
      inner("add", ".");
      inner("commit", "-m", "Synthetic inner baseline");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic outer baseline");
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
      let expectedAlternateIndex = parentIndex;
      let childIndex = await readFile(join(nested, ".git", "index"));
      if (settings === "alternate-index") {
        await writeFile(alternateIndex, parentIndex);
        await writeFile(join(nested, "build.log"), "ignored baseline\n");
      }
      const snapshots = new Map<string, Set<string>>();
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: target,
          environment: gitEnvironment,
          onRepositoryCommand: (command, args, cwd, options) => {
            expect(cwd).not.toBe(nested);
            const selectedWorktree = args.includes("--work-tree")
              ? args[args.indexOf("--work-tree") + 1]!
              : args[0] === "-C"
                ? args[1]!
                : cwd;
            if (args[0] === "-C") {
              expect(cwd).toBe(root);
              expect([root, directory, nested]).toContain(resolve(args[1]!));
            }
            const index = options?.environment?.["GIT_INDEX_FILE"];
            if (index !== undefined) {
              expect(cwd).toBe(root);
              if (
                gitEnvironment.GIT_INDEX_FILE === undefined ||
                resolve(options?.directory ?? cwd, index) !==
                  resolve(target, gitEnvironment.GIT_INDEX_FILE)
              ) {
                const checkout = selectedWorktree;
                const indices = snapshots.get(checkout) ?? new Set<string>();
                indices.add(index);
                snapshots.set(checkout, indices);
              }
            }
            const environment = { ...gitEnvironment, ...options?.environment };
            if (selectedWorktree === nested) {
              expect(environment["GIT_DIR"]).toBeUndefined();
              expect(environment["GIT_WORK_TREE"]).toBeUndefined();
              const objects = environment["GIT_OBJECT_DIRECTORY"];
              expect(
                objects === undefined
                  ? objects
                  : resolve(options?.directory ?? cwd, objects),
              ).toBe(gitEnvironment.GIT_OBJECT_DIRECTORY);
              expect(environment["GIT_COMMON_DIR"]).toBeUndefined();
            } else {
              if (index === undefined)
                expect(environment["GIT_INDEX_FILE"]).toBe(
                  gitEnvironment.GIT_INDEX_FILE,
                );
              const commandDirectory = options?.directory ?? cwd;
              for (const name of [
                "GIT_OBJECT_DIRECTORY",
                "GIT_COMMON_DIR",
              ] as const) {
                const value = environment[name];
                const objectDirectoryProbe =
                  name === "GIT_OBJECT_DIRECTORY" &&
                  args.join(" ") ===
                    "rev-parse --path-format=absolute --git-path objects" &&
                  options?.environment?.["GIT_OBJECT_DIRECTORY"] === ".";
                expect(
                  value === undefined || objectDirectoryProbe
                    ? value
                    : resolve(commandDirectory, value),
                ).toBe(objectDirectoryProbe ? "." : gitEnvironment[name]);
              }
              expect(commandDirectory).toBe(target);
              if (environment["GIT_DIR"] !== undefined)
                expect(resolve(commandDirectory, environment["GIT_DIR"])).toBe(
                  join(root, ".git"),
                );
              if (environment["GIT_WORK_TREE"] !== undefined)
                expect(
                  resolve(commandDirectory, environment["GIT_WORK_TREE"]),
                ).toBe(root);
            }
            expect(environment["GIT_CONFIG_COUNT"]).toBe("1");
            expect(environment["SYNTHETIC_GIT_SETTING"]).toBe("preserved");
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
              await writeFile(join(root, "outer-generated.txt"), "outer fix\n");
              await runGitRepositoryCommand(
                "git",
                ["add", "-f", "outer-generated.txt"],
                root,
                { environment: gitEnvironment },
              );
              expectedAlternateIndex = await readFile(alternateIndex);
              await writeFile(join(nested, "generated.txt"), "generated fix\n");
              inner("add", "-f", "generated.txt");
              childIndex = await readFile(join(nested, ".git", "index"));
              output?.stdout.write("Fixed and checked.");
              return 0;
            }
            await writeFile(join(directory, "app.ts"), "fixed\n");
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
              childIndex = await readFile(join(nested, ".git", "index"));
            }
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        operation === "ignored" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout).files).toEqual(
        operation === "ignored"
          ? []
          : operation === "new-ignored"
            ? ["outer-generated.txt", "package/nested/generated.txt"]
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
        expect(await readFile(alternateIndex)).toEqual(expectedAlternateIndex);
      if (operation === "new-ignored")
        expect(await readFile(join(root, "outer-generated.txt"), "utf8")).toBe(
          "outer fix\n",
        );
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
      if (operation !== "remove") {
        expect(await readFile(join(nested, ".git", "index"))).toEqual(
          childIndex,
        );
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

  test.each(["uncommitted", "committed", "committed and uncommitted"] as const)(
    "publishes the complete mixed patch with %s nested changes",
    async (change) => {
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
      await writeFile(join(directory, "root.ts"), "root original\n");
      git("add", "nested", "root.ts");
      git("commit", "-m", "Synthetic gitlink");
      const rootBefore = git("rev-parse", "HEAD");
      const remoteBefore = git("ls-remote", "origin");
      const before = nestedGit("rev-parse", "HEAD");
      let after = before;
      let nestedIndex = await readFile(join(nested, ".git/index"));
      let assessments = 0;
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
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
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
              expect(artifact.changedFiles).toContain("root.ts");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(join(nested, "app.ts"), "fixed\n");
            await writeFile(join(directory, "root.ts"), "root fixed\n");
            if (change !== "uncommitted")
              nestedGit("commit", "-am", "Synthetic nested update");
            if (change === "committed and uncommitted")
              await writeFile(join(nested, "extra.ts"), "uncommitted\n");
            after = nestedGit("rev-parse", "HEAD");
            nestedIndex = await readFile(join(nested, ".git/index"));
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(assessments).toBe(1);
      if (change !== "committed") {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(git("rev-parse", "HEAD")).toBe(rootBefore);
        expect(git("ls-remote", "origin")).toBe(remoteBefore);
        expect(await readFile(join(directory, "root.ts"), "utf8")).toBe(
          "root fixed\n",
        );
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
        expect(await readFile(join(nested, ".git/index"))).toEqual(nestedIndex);
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(after).not.toBe(before);
      expect(git("ls-tree", "HEAD", "nested")).toBe(
        `160000 commit ${after}\tnested`,
      );
      expect(
        repositoryGit(remote)("ls-tree", git("rev-parse", "HEAD"), "nested"),
      ).toBe(`160000 commit ${after}\tnested`);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      expect(
        repositoryGit(remote)("show", `${git("rev-parse", "HEAD")}:root.ts`),
      ).toBe("root fixed");
      expect(git("status", "--porcelain")).toBe("");
      expect(await readFile(join(nested, ".git/index"))).toEqual(nestedIndex);
      expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
    },
  );
});
