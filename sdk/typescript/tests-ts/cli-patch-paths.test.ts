import { expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, sep } from "node:path";
import {
  patchRiskAssessment,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
  publicationRepository,
  resultWithFindings,
  savedScan,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
  runSavedPublication,
  gitWithEnvironment,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

async function initialize(directory: string) {
  await mkdir(directory, { recursive: true });
  const git = initializePatchGit(directory);
  await writeFile(join(directory, "app.ts"), "original\n");
  git("add", ".");
  git("commit", "-m", "Synthetic baseline");
  return git;
}

test.each(["GIT_DIR", "GIT_WORK_TREE"])(
  "patch assessment preserves native directory-link traversal in relative %s",
  async (selector) => {
    const root = await fixtures.create("patch-relative-selector-");
    const checkout = join(root, "storage", "checkout");
    const caller = join(root, "caller");
    await initialize(checkout);
    await mkdir(caller);
    await mkdir(join(root, "storage", "child"));
    await symlink(
      process.platform === "win32"
        ? join(root, "storage")
        : join(root, "storage", "child"),
      join(caller, "alias"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const metadata = join(root, "storage", "metadata");
    await rename(join(checkout, ".git"), metadata);
    const environment = {
      GIT_DIR: metadata,
      GIT_WORK_TREE: checkout,
      // Windows resolves alias/.. lexically; POSIX traverses the link first.
      [selector]: `alias${sep}${process.platform === "win32" ? "" : `..${sep}`}${selector === "GIT_DIR" ? "metadata" : "checkout"}`,
    };
    const git = (args: string[]) =>
      runGitRepositoryCommand("git", args, caller, { environment });
    const before = await git(["rev-parse", "HEAD"]);
    expect(await realpath(await git(["rev-parse", "--show-toplevel"]))).toBe(
      await realpath(checkout),
    );
    let assessments = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: gitWithEnvironment(environment),
        onCodex: async (_args, output) => {
          if (output?.appServer?.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = JSON.parse(
              output.appServer.prompt
                .split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            );
            expect((await readFile(artifact.path, "utf8")).trim()).toBe(
              await git([
                "diff",
                "--binary",
                "--full-index",
                "--no-renames",
                "HEAD",
              ]),
            );
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          await writeFile(join(checkout, "app.ts"), "fixed\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(assessments).toBe(1);
    expect(await git(["rev-parse", "HEAD"])).toBe(before);
  },
);

for (const nested of [false, true]) {
  test
    .skipIf(process.platform !== "linux")
    .each(["unicode", "raw", "both", "delete raw"])(
    `patch assessment retains distinct filename bytes (${nested ? "nested" : "root"}): %s`,
    async (change) => {
      const root = await fixtures.create("patch-filename-bytes-");
      const outerGit = await initialize(root);
      const checkout = nested ? join(root, "nested-λ") : root;
      const git = nested ? await initialize(checkout) : outerGit;
      const raw = Buffer.concat([
        Buffer.from(`${checkout}/file-`),
        Buffer.from([255]),
        Buffer.from(".txt"),
      ]);
      const unicode = join(checkout, "file-\ufffd.txt");
      await writeFile(raw, "raw original\n");
      await writeFile(unicode, "unicode original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic byte names");
      if (nested) {
        outerGit("add", ".");
        outerGit("commit", "-m", "Synthetic nested checkout");
      }
      const index = await readFile(join(checkout, ".git", "index"));
      let assessments = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes("immutable patch artifact")
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              const patch = await readFile(artifact.path, "utf8");
              expect(patch.trim()).toBe(
                git(
                  "diff",
                  "--binary",
                  "--full-index",
                  "--no-renames",
                  ...(nested
                    ? ["--src-prefix=a/nested-λ/", "--dst-prefix=b/nested-λ/"]
                    : []),
                  "HEAD",
                ),
              );
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (change === "raw" || change === "both")
              await writeFile(raw, "raw fixed\n");
            if (change === "unicode" || change === "both")
              await writeFile(unicode, "unicode fixed\n");
            if (change === "delete raw") await rm(raw);
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      expect(await readFile(join(checkout, ".git", "index"))).toEqual(index);
    },
  );
}

test.skipIf(process.platform !== "linux").each([false, true])(
  "never snapshots a raw gitlink through its replacement-character alias (initialized: %p)",
  async (initialized) => {
    const root = await fixtures.create("patch-gitlink-byte-alias-");
    const git = await initialize(root);
    const support = await fixtures.create("patch-gitlink-byte-support-");
    const source = join(root, "nested");
    await initialize(source);
    const raw = Buffer.concat([
      Buffer.from(`${root}/nested-`),
      Buffer.from([0xff]),
    ]);
    await rename(source, raw);
    git("add", "--all");
    git("commit", "-m", "Synthetic raw gitlink");
    if (!initialized) {
      await rename(raw, join(support, "original"));
      await mkdir(raw);
    }
    const alias = join(root, "nested-\ufffd");
    await writeFile(join(root, ".git/info/exclude"), "nested-\ufffd/\n");
    const aliasGit = await initialize(alias);
    const effect = join(support, "hook-effect");
    await writeFile(
      join(alias, ".git/hooks/post-index-change"),
      `#!/bin/sh\nprintf synthetic-effect > '${effect.replaceAll("'", "'\\''")}'\n`,
      { mode: 0o755 },
    );
    const aliasHead = aliasGit("rev-parse", "HEAD");
    const aliasIndex = await readFile(join(alias, ".git/index"));
    const aliasCommands: string[][] = [];
    let modelCalls = 0;
    const outcome = await runIssuePatch(root, {
      onRepositoryCommand: (command, args, cwd, options) => {
        if (
          cwd === alias ||
          args.some((arg) => arg === alias || arg.startsWith(`${alias}/`))
        )
          aliasCommands.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        modelCalls++;
        await writeFile(join(root, "app.ts"), "fixed\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(aliasCommands).toEqual([]);
    await expect(readFile(effect)).rejects.toMatchObject({ code: "ENOENT" });
    expect(aliasGit("rev-parse", "HEAD")).toBe(aliasHead);
    expect(await readFile(join(alias, ".git/index"))).toEqual(aliasIndex);
    expect(outcome.exitCode, outcome.stderr).toBe(initialized ? 2 : 0);
    expect(modelCalls).toBe(initialized ? 0 : 1);
    if (initialized) expect(outcome.stderr).toContain("not valid UTF-8");
  },
);

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
    const outcome = await runSavedPublication(directory, {
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
    });
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
