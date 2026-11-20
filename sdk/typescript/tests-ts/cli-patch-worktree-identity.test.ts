import {
  addPublicationOrigin,
  runPublicationCommand,
  resultWithFindings,
  savedScan,
  completePatches,
  patchRiskSkill,
  patchDirectories,
  patchArtifactFromPrompt,
  patchRiskAssessment,
  runWorkflow,
  repositoryGit,
  initializePatchGit,
  gitWithEnvironment,
  runIssuePatch,
  runGitRepositoryCommand,
  runPublicationWorkflow,
} from "./cli-patch-fixtures.js";
import { gitText } from "./support/shell.js";
import { afterEach, describe, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { hash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  readFile,
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
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = patchDirectories();

test.each(["linked", "explicit"])(
  "preserves the selected worktree boundary for an external %s validation prompt",
  async (kind) => {
    const root = await fixtures.create("patch-external-validation-");
    const repository = join(root, "repository");
    const invocation = join(root, "invocation");
    const outside = join(root, "outside");
    const gitEnvironment = {
      GIT_DIR: join(repository, ".git"),
      GIT_WORK_TREE: repository,
    };
    let started = false;
    for (const directory of [repository, invocation, outside])
      await mkdir(directory);
    const git = initializePatchGit(repository);
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic initial commit");
    await writeFile(
      join(outside, "validation.md"),
      "Run the synthetic regression test.",
    );
    await symlink(
      outside,
      join(repository, "validation"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const outcome = await runWorkflow(
      [
        "patch",
        "Synthetic issue",
        "--assess-patch-risk",
        "--validation-prompt-file",
        join(
          kind === "linked" ? join(repository, "validation") : outside,
          "validation.md",
        ),
        "--json",
      ],
      {
        currentDirectory: invocation,
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: (_args, output) => {
          started = true;
          expect(output?.appServer?.prompt).toContain(
            "Run the synthetic regression test.",
          );
          return 1;
        },
      },
    );
    expect(started, outcome.stderr).toBe(kind === "explicit");
    if (kind === "linked")
      expect(outcome.stderr).toContain("directory links outside");
  },
);

test.each([
  "ordinary",
  "removed component",
  "explicit Git environment",
  "removed component with explicit Git environment",
])(
  "preserves disposable assessment worktrees and explicit Git settings: %s",
  async (kind) => {
    const root = await fixtures.create("patch-disposable-assessment-");
    const repository = join(root, "repository");
    const component = join(repository, "sub");
    const disposable = join(root, "disposable");
    const gitEnvironment = kind.includes("explicit Git environment")
      ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
      : {};
    await mkdir(component, { recursive: true });
    const git = initializePatchGit(repository);
    await writeFile(join(component, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic initial commit");
    git("worktree", "add", "--detach", disposable, "HEAD");
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: component,
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output, environment) => {
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            const selected = gitText(
              ["-C", disposable, "rev-parse", "--show-toplevel"],
              { cwd: output.appServer.directory, env: environment },
            ).trim();
            expect(resolve(selected)).toBe(
              kind.includes("explicit Git environment")
                ? repository
                : disposable,
            );
            output.stdout.write(patchRiskAssessment().report);
          } else {
            if (kind.startsWith("removed component"))
              await rm(component, { recursive: true });
            else await writeFile(join(component, "app.ts"), "fixed\n");
            output?.stdout.write("Patch complete.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
  },
);

describe("patch publication integrity", () => {
  const repositories = createTemporaryDirectories();
  afterEach(repositories.cleanup);
  test.each([
    ["committed", "root"],
    ["uncommitted", "root"],
    ["committed", "component"],
    ["uncommitted", "component"],
    ["removed worktree", "root"],
    ["removed worktree", "component"],
    ["removed worktree and assessed", "root"],
    ["removed worktree and assessed", "component"],
  ])(
    "preserves supplied-issue submodule publication with %s changes from %s",
    async (state, invocation) => {
      const removedWorktree = state.startsWith("removed worktree");
      const assessed = state.endsWith("assessed");
      const committed = state !== "uncommitted";
      const directory = await repositories.create(
        "patch-submodule-publication-",
      );
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      await mkdir(nested, { recursive: true });
      const component = join(checkout, "component");
      await mkdir(component);
      const currentDirectory =
        invocation === "component" ? component : checkout;
      const git = initializePatchGit(checkout);
      const inner = initializePatchGit(nested);
      for (const run of [git, inner]) {
        run("config", "commit.gpgsign", "false");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      const original = inner("rev-parse", "HEAD");
      await writeFile(join(nested, "app.ts"), "fixed\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested fix");
      const fixed = inner("rev-parse", "HEAD");
      inner("checkout", original);
      if (removedWorktree) {
        const childRemote = join(directory, "dependency.git");
        git("init", "--bare", childRemote);
        inner("remote", "add", "origin", childRemote);
        inner("push", "origin", "main");
        git(
          "config",
          "-f",
          ".gitmodules",
          "submodule.dependency.path",
          "dependency",
        );
        git(
          "config",
          "-f",
          ".gitmodules",
          "submodule.dependency.url",
          childRemote,
        );
      }
      git("add", ".");
      if (removedWorktree) git("submodule", "absorbgitdirs", "dependency");
      git("commit", "-m", "Synthetic parent baseline");
      git("config", "diff.relative", "true");
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const remote = join(directory, "remote.git");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let published = false;
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--create-pr",
          ...(assessed ? ["--assess-patch-risk"] : []),
          "--json",
        ],
        {
          currentDirectory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "list") return "";
            published = true;
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              assessments++;
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              const patch = await readFile(artifact.path, "utf8");
              expect(artifact.changedFiles).toContain("dependency/app.ts");
              expect(patch).toContain(`-Subproject commit ${original}`);
              expect(patch).toContain(`+Subproject commit ${fixed}`);
              expect(patch).toContain("-original\n+fixed\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (committed) inner("checkout", fixed);
            else await writeFile(join(nested, "app.ts"), "fixed\n");
            if (removedWorktree) {
              git("add", "dependency");
              await rm(nested, { recursive: true });
              await mkdir(nested);
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(committed ? 0 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: (committed
          ? ["dependency", "dependency/app.ts"]
          : ["dependency/app.ts"]
        ).map((file) =>
          relative(currentDirectory, join(checkout, file)).split(sep).join("/"),
        ),
      });
      expect(published).toBe(committed);
      expect(assessments).toBe(assessed ? 1 : 0);
      if (committed) {
        expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
          "dependency",
        );
        expect(git("rev-parse", "HEAD:dependency")).toBe(fixed);
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
        if (removedWorktree)
          expect(git("submodule", "status", "--", "dependency")).toStartWith(
            "-",
          );
      } else {
        expect(outcome.stderr).toContain("submodule");
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("branch", "--format=%(refname)")).toBe("refs/heads/main");
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
      }
    },
  );

  test.each([
    "unborn",
    "nested",
    "nested environment",
    "nested objects",
    "nested shared primary objects",
    "nested read-only local primary objects",
    "nested relative primary objects",
    "nested quoted primary objects",
    "nested missing local primary objects",
    "nested missing local relative primary objects",
    "nested alternate objects",
    "nested common",
    "nested relative alternates",
    "nested component relative alternates",
    "nested quoted relative alternates",
    "nested gitfile relative alternates",
    "nested replacements",
    "nested replacement namespace",
  ])("detects local patches in %s Git repositories", async (kind) => {
    const directory = await repositories.create("patch-git-state-");
    const selectedDirectory = kind.includes("component")
      ? join(directory, "component")
      : directory;
    if (selectedDirectory !== directory) await mkdir(selectedDirectory);
    const git = initializePatchGit(directory);
    await writeFile(join(directory, "app.ts"), "unsafe\n");
    let path = "app.ts";
    let alternateObjects: string | undefined;
    let primaryObjects: string | undefined;
    let parentIndex = "";
    let nestedIndex = "";
    if (kind.startsWith("nested")) {
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const nested = join(selectedDirectory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner(
        "init",
        "--initial-branch=main",
        ...(kind.includes("gitfile")
          ? ["--separate-git-dir", join(directory, ".git", "nested-metadata")]
          : []),
      );
      if (kind.includes("gitfile")) inner("config", "core.worktree", nested);
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      if (kind.includes("alternates") || kind === "nested alternate objects") {
        const pool = await repositories.create(
          kind.includes("quoted")
            ? `patch-shared${delimiter}objects-`
            : "patch-shared-objects-",
        );
        alternateObjects = join(pool, "objects");
        const gitDirectory = inner("rev-parse", "--absolute-git-dir");
        await rename(join(gitDirectory, "objects"), alternateObjects);
        await mkdir(join(gitDirectory, "objects"));
        expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
        if (kind.includes("relative"))
          alternateObjects = relative(directory, alternateObjects);
        if (kind.includes("quoted"))
          alternateObjects = JSON.stringify(alternateObjects);
      }
      if (kind.includes("primary objects")) {
        const pool = await repositories.create(
          kind.includes("quoted")
            ? `patch-shared${delimiter}primary-`
            : "patch-shared-primary-",
        );
        primaryObjects = join(pool, "objects");
        const gitDirectory = inner("rev-parse", "--absolute-git-dir");
        await rename(join(gitDirectory, "objects"), primaryObjects);
        if (!kind.includes("missing local"))
          await mkdir(join(gitDirectory, "objects"));
        if (kind.includes("read-only local"))
          await chmod(join(gitDirectory, "objects"), 0o555);
        await cp(join(directory, ".git", "objects"), primaryObjects, {
          recursive: true,
          force: false,
        });
        await rm(join(directory, ".git", "objects"), { recursive: true });
        await mkdir(join(directory, ".git", "objects"));
        expect(() => git("rev-parse", "HEAD^{tree}")).toThrow();
        expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
        parentIndex = hash(
          "sha256",
          await readFile(join(directory, ".git", "index")),
          "hex",
        );
        nestedIndex = hash(
          "sha256",
          await readFile(join(gitDirectory, "index")),
          "hex",
        );
        if (kind.includes("relative"))
          primaryObjects = relative(directory, primaryObjects);
      }
      if (kind.startsWith("nested replacement")) {
        const original = inner("rev-parse", "HEAD^{tree}");
        await writeFile(join(nested, "app.ts"), "fixed\n");
        inner("add", ".");
        const replacement = inner("write-tree");
        inner("reset", "--hard", "HEAD");
        inner("replace", original, replacement);
      }
      path = "nested/app.ts";
    }
    const gitEnvironment =
      kind === "nested environment"
        ? { GIT_DIR: ".git", GIT_WORK_TREE: directory }
        : kind === "nested objects"
          ? { GIT_OBJECT_DIRECTORY: join(directory, ".git", "objects") }
          : kind.includes("primary objects")
            ? { GIT_OBJECT_DIRECTORY: primaryObjects }
            : kind === "nested common"
              ? { GIT_COMMON_DIR: join(directory, ".git") }
              : kind.includes("alternates") ||
                  kind === "nested alternate objects"
                ? { GIT_ALTERNATE_OBJECT_DIRECTORIES: alternateObjects }
                : kind === "nested replacements"
                  ? { GIT_NO_REPLACE_OBJECTS: "1" }
                  : kind === "nested replacement namespace"
                    ? { GIT_REPLACE_REF_BASE: "refs/synthetic-replacements/" }
                    : {};
    const outcome = await runIssuePatch(
      selectedDirectory,
      {
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output) => {
          await writeFile(join(selectedDirectory, path), "fixed\n");
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      },
      {
        configure: (current) => {
          current.environment = { ...current.environment, ...gitEnvironment };
        },
      },
    );
    if (kind.includes("missing local"))
      expect(
        existsSync(join(selectedDirectory, "nested", ".git", "objects")),
      ).toBe(false);
    if (primaryObjects !== undefined) {
      expect(
        hash("sha256", await readFile(join(directory, ".git", "index")), "hex"),
      ).toBe(parentIndex);
      expect(
        hash(
          "sha256",
          await readFile(join(selectedDirectory, "nested", ".git", "index")),
          "hex",
        ),
      ).toBe(nestedIndex);
    }
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: [
        kind === "nested component relative alternates"
          ? `component/${path}`
          : path,
      ],
    });
  });
  test.each([
    "initialized during patching",
    "initialized without edits",
    "left uninitialized",
    "already initialized with local edits",
    "shallow initialized without edits",
    "shallow initialized with edits",
    "replaced without edits",
    "replaced with edits",
    "retargeted with unchanged local edits",
  ])("tracks patch changes when a registered child is %s", async (state) => {
    const root = await repositories.create("patch-submodule-initialization-");
    const repository = join(root, "repository");
    const source = join(root, "child-source");
    const child = join(repository, "dependency");
    await mkdir(repository);
    await mkdir(source);
    const git = initializePatchGit(repository);
    const sourceGit = initializePatchGit(source);
    await writeFile(join(source, "app.ts"), "unsafe\noriginal\n");
    await writeFile(join(source, "HEAD"), "ordinary tracked file\n");
    sourceGit("add", ".");
    sourceGit("commit", "-m", "Synthetic child baseline");
    const originalChildHead = sourceGit("rev-parse", "HEAD");
    git(
      "-c",
      "protocol.file.allow=always",
      "submodule",
      "add",
      pathToFileURL(source).href,
      "dependency",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    const retargeted = state === "retargeted with unchanged local edits";
    const replaced = state.startsWith("replaced");
    const retained =
      state === "already initialized with local edits" || retargeted;
    const initialized = retained || replaced;
    const shallow = state.startsWith("shallow initialized");
    const changed =
      (retained && !retargeted) ||
      state === "initialized during patching" ||
      state === "shallow initialized with edits" ||
      state === "replaced with edits";
    if (retained)
      await writeFile(
        join(child, "app.ts"),
        (await readFile(join(child, "app.ts"), "utf8")) + "local edit\n",
      );
    else if (!initialized) {
      await rm(child, { recursive: true });
      await mkdir(child);
    }
    if (shallow) {
      await rm(join(repository, ".git", "modules", "dependency"), {
        recursive: true,
      });
      await writeFile(join(source, "upstream.ts"), "new upstream file\n");
      sourceGit("add", ".");
      sourceGit("commit", "-m", "Synthetic upstream change");
    }
    const replacement = join(root, "replacement-source");
    if (replaced) {
      await mkdir(replacement);
      const replacementGit = initializePatchGit(replacement);
      await writeFile(join(replacement, "app.ts"), "unsafe\nreplacement\n");
      replacementGit("add", ".");
      replacementGit("commit", "-m", "Synthetic replacement child");
    }
    const alternateMetadata = join(
      repository,
      ".git",
      "modules",
      "alternate-dependency",
    );
    if (retargeted)
      await cp(
        join(repository, ".git", "modules", "dependency"),
        alternateMetadata,
        { recursive: true },
      );
    let expectedIndex = git("write-tree");
    const originalGitlink = git("ls-tree", "HEAD", "dependency");
    const gitTrace: unknown[] = [];
    let modelCalls = 0;
    let assessments = 0;
    let expectedContents: string | undefined;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: repository,
        onRepositoryCommand: async (command, args, cwd, options) => {
          expect(command).toBe("git");
          const directory = options?.directory ?? cwd;
          try {
            const execution = promisify(execFile)(command, [...args], {
              cwd: directory,
              env: { ...process.env, ...options?.environment },
              maxBuffer: options?.maxBuffer,
              encoding: options?.encoding === "base64" ? "buffer" : "utf8",
            });
            execution.child.stdin?.end(options?.input);
            const { stdout } = await execution;
            if (
              args.includes("rev-parse") &&
              ["--is-inside-git-dir", "--show-toplevel"].includes(
                args.at(-1) ?? "",
              )
            )
              gitTrace.push({
                args,
                cwd: directory,
                stdout: stdout.toString(),
              });
            const output = Buffer.isBuffer(stdout)
              ? stdout.toString(options?.encoding ?? "utf8")
              : stdout;
            return options?.trim === false ? output : output.trim();
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
        onCodex: async (_args, output) => {
          modelCalls++;
          expect(
            git("submodule", "status", "--", "dependency").startsWith("-"),
          ).toBe(!initialized);
          if (!initialized && state !== "left uninitialized")
            git(
              "-c",
              "protocol.file.allow=always",
              "submodule",
              "update",
              "--init",
              ...(shallow ? ["--remote", "--depth=1"] : []),
              "--",
              "dependency",
            );
          if (replaced) {
            await rm(child, { recursive: true });
            await rename(replacement, child);
            expect(() =>
              repositoryGit(child)(
                "cat-file",
                "-e",
                `${originalChildHead}^{commit}`,
              ),
            ).toThrow();
          }
          if (retargeted)
            await writeFile(
              join(child, ".git"),
              `gitdir: ${alternateMetadata}\n`,
            );
          if (shallow) {
            const childGit = repositoryGit(child);
            expect(childGit("rev-parse", "--is-shallow-repository")).toBe(
              "true",
            );
            expect(childGit("rev-parse", "HEAD")).toBe(
              sourceGit("rev-parse", "HEAD"),
            );
            expect(() =>
              childGit("cat-file", "-e", `${originalChildHead}^{commit}`),
            ).toThrow();
          }
          if (state !== "left uninitialized") {
            expectedContents = await readFile(join(child, "app.ts"), "utf8");
            if (changed) {
              expectedContents = expectedContents.replace("unsafe", "fixed");
              await writeFile(join(child, "app.ts"), expectedContents);
            }
          }
          expectedIndex = git("write-tree");
          output?.stdout.write("Checked the synthetic patch.");
          return 0;
        },
      },
      {
        configure: (current) => {
          current.assessPatchRisk = async () => {
            assessments++;
            return patchRiskAssessment();
          };
        },
      },
    );
    const diagnostics = JSON.stringify({ outcome, modelCalls, gitTrace });
    expect(modelCalls, diagnostics).toBe(1);
    // Replacing or retargeting captured administration fails before risk assessment.
    const administrationChanged = replaced || retargeted;
    const applied = !administrationChanged && (changed || shallow);
    expect(assessments, diagnostics).toBe(applied ? 1 : 0);
    expect(outcome.exitCode, diagnostics).toBe(applied ? 0 : 2);
    const result = JSON.parse(outcome.stdout);
    if (administrationChanged) {
      expect(result, diagnostics).not.toHaveProperty("applied");
      expect(result, diagnostics).not.toHaveProperty("filesChanged");
    }
    expect(result, diagnostics).toMatchObject(
      administrationChanged
        ? {
            files: [],
            error: {
              code: "PATCH_FAILED",
              message: `Nested Git administration changed during the patch: ${child}`,
            },
          }
        : {
            applied,
            files: [
              ...(shallow ? ["dependency"] : []),
              ...(shallow ? ["dependency/HEAD"] : []),
              ...(changed || shallow ? ["dependency/app.ts"] : []),
              ...(shallow ? ["dependency/upstream.ts"] : []),
            ],
            ...(applied ? {} : { error: { code: "NO_PATCH_APPLIED" } }),
          },
    );
    expect(git("write-tree")).toBe(expectedIndex);
    expect(git("ls-tree", "HEAD", "dependency")).toBe(originalGitlink);
    if (expectedContents === undefined)
      expect(git("submodule", "status", "--", "dependency")).toStartWith("-");
    else {
      expect(await readFile(join(child, "app.ts"), "utf8")).toBe(
        expectedContents,
      );
      expect(repositoryGit(child)("diff", "--name-only")).toBe(
        changed || retained ? "app.ts" : "",
      );
      if (retained) expect(expectedContents).toContain("local edit\n");
    }
  });

  test("keeps the outer executable boundary for nested patch snapshots", async () => {
    const repository = await repositories.create("patch-nested-executable-");
    const nested = join(repository, "dependency");
    await mkdir(nested);
    const git = initializePatchGit(repository);
    const inner = initializePatchGit(nested);
    await writeFile(join(nested, "app.ts"), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    const trusted = await resolveTrustedExecutable(
      "git",
      process.env,
      repository,
    );
    expect(trusted).not.toBeNull();
    const bin = join(repository, "bin");
    await mkdir(bin);
    const repositoryGitPath = join(bin, basename(trusted!.executable));
    await copyFile(trusted!.executable, repositoryGitPath);
    await chmod(repositoryGitPath, 0o755);
    const environment = {
      ...process.env,
      PATH: [bin, process.env["PATH"]].join(delimiter),
    };
    let nestedCommands = 0;
    const outcome = await runIssuePatch(repository, {
      onRepositoryCommand: async (command, args, cwd, options) => {
        // Exercise the same resolver used by the default command dependency.
        const selected = await resolveTrustedExecutable(
          command,
          environment,
          cwd,
        );
        expect(selected?.executable).not.toBe(repositoryGitPath);
        if (cwd === nested || args.includes(nested)) nestedCommands++;
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        await writeFile(join(nested, "app.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(nestedCommands).toBeGreaterThan(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["dependency/app.ts"],
    });
  });

  test("refuses a sparse gitlink redirected outside the patch checkout", async () => {
    const directory = await repositories.create("patch-sparse-gitlink-");
    const repository = join(directory, "repository");
    const nested = join(repository, "dependency");
    const external = join(directory, "external");
    await mkdir(nested, { recursive: true });
    await mkdir(external);
    const git = initializePatchGit(repository);
    const inner = initializePatchGit(nested);
    const outside = initializePatchGit(external);
    for (const [path, run] of [
      [nested, inner],
      [external, outside],
    ] as const) {
      await writeFile(join(path, "app.ts"), "original\n");
      run("add", ".");
      run("commit", "-m", "Synthetic baseline");
    }
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    git("config", "core.sparseCheckout", "true");
    await writeFile(
      join(repository, ".git", "info", "sparse-checkout"),
      "/*\n!/dependency\n",
    );
    git("update-index", "--skip-worktree", "dependency");
    await rm(nested, { recursive: true });
    await symlink(
      external,
      nested,
      process.platform === "win32" ? "junction" : "dir",
    );
    const outsideFile = join(external, "uncommitted.txt");
    await writeFile(
      outsideFile,
      "Synthetic bytes outside the selected checkout\n",
    );
    const blob = outside("hash-object", outsideFile);
    const index = outside("write-tree");
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    let modelCalls = 0;
    const outcome = await runIssuePatch(repository, {
      onCodex: async () => {
        modelCalls++;
        return 0;
      },
    });
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    expect(outside("write-tree")).toBe(index);
    expect(modelCalls).toBe(0);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("outside");
    expect(await readFile(outsideFile, "utf8")).toBe(
      "Synthetic bytes outside the selected checkout\n",
    );
  });

  test.each(["worktree", "metadata"])(
    "refuses a nested checkout rebound to external %s before writing objects",
    async (binding) => {
      const directory = await repositories.create("patch-nested-binding-");
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      const external = join(directory, "external");
      await mkdir(nested, { recursive: true });
      await mkdir(external);
      const git = initializePatchGit(checkout);
      const inner = initializePatchGit(nested);
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      const outsideFile = join(external, "outside.txt");
      await writeFile(
        outsideFile,
        "Synthetic bytes outside the selected checkout\n",
      );
      const blob = git("hash-object", outsideFile);
      expect(() => inner("cat-file", "-e", blob)).toThrow();
      let objects = inner;
      if (binding === "worktree") {
        inner("config", "core.worktree", external);
      } else {
        const outside = initializePatchGit(external);
        outside("add", ".");
        outside("commit", "-m", "Synthetic external baseline");
        await rm(join(nested, ".git"), { recursive: true });
        await writeFile(
          join(nested, ".git"),
          `gitdir: ${join(external, ".git")}\n`,
        );
        await writeFile(
          join(nested, "app.ts"),
          "Synthetic unpublished target bytes\n",
        );
        objects = outside;
      }
      const snapshotBlob = git("hash-object", join(nested, "app.ts"));
      if (binding === "metadata")
        expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      let modelCalls = 0;
      const outcome = await runIssuePatch(checkout, {
        onCodex: async () => {
          modelCalls++;
          return 0;
        },
      });
      if (binding === "worktree")
        expect(() => inner("cat-file", "-e", blob)).toThrow();
      else expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      expect(modelCalls).toBe(0);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toMatch(/worktree|metadata/u);
    },
  );

  test.each([
    ["inline", "root"],
    ["saved", "root"],
    ["saved", "component"],
  ])(
    "retains nested changed files when %s patch assessment targets a %s",
    async (kind, targetKind) => {
      const repository = await repositories.create("patch-git-state-");
      const component = join(repository, "component");
      const nested = join(component, "nested");
      await mkdir(nested, { recursive: true });
      const git = initializePatchGit(repository);
      await writeFile(join(component, "app.ts"), "unsafe\n");
      const inner = initializePatchGit(nested);
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const directory = targetKind === "root" ? repository : component;
      const path = relative(directory, join(nested, "app.ts"))
        .split(sep)
        .join("/");
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations = [{ path, startLine: 1 }];
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          ...(kind === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex: async (args, output) => {
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              assessments++;
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              const patch = await readFile(artifact.path);
              expect(artifact.changedFiles).toEqual([
                "component/nested/app.ts",
              ]);
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              expect(patch.toString()).toContain(
                "diff --git a/component/nested/app.ts b/component/nested/app.ts",
              );
              expect(patch.toString()).toContain("-unsafe\n+fixed");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            expect(output?.appServer?.directory).toBe(directory);
            await writeFile(join(nested, "app.ts"), "fixed\n");
            if (kind === "saved") completePatches(args, output);
            else output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["component/nested/app.ts"],
        ...(kind === "saved" ? { patches: [{ files: [path] }] } : {}),
      });
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
    },
  );

  test.each(
    [false, true].flatMap((component) =>
      [false, true].flatMap((relativeDiff) =>
        [false, true].map((dirty) => [component, relativeDiff, dirty] as const),
      ),
    ),
  )(
    "preserves dirty rename sources with component=%j relative diff=%j dirty=%j",
    async (component, relativeDiff, dirty) => {
      const directory = await repositories.create(
        "patch-relative-renamed-source-",
      );
      const scanned = component ? join(directory, "component") : directory;
      await mkdir(scanned, { recursive: true });
      const git = initializePatchGit(directory);
      git("config", "diff.relative", String(relativeDiff));
      const source = join(scanned, "old.ts");
      await writeFile(source, "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      if (dirty) {
        await writeFile(source, "staged local edit\n");
        git("add", ".");
        await writeFile(source, "original\n");
      }
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      await addPublicationOrigin(repositories, git);
      let modelCalls = 0;
      const outcome = await runPublicationWorkflow("issue", {
        currentDirectory: scanned,
        onRepositoryCommand: runPublicationCommand,
        onCodex: async (_args, output) => {
          modelCalls++;
          await rename(source, join(scanned, "new.ts"));
          output?.stdout.write("Synthetic rename complete.");
          return 0;
        },
      });
      expect(modelCalls).toBe(1);
      expect(outcome.exitCode, outcome.stderr).toBe(dirty ? 2 : 0);
      if (dirty) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("ls-remote", "origin")).toBe("");
      } else {
        const file = component ? "component/new.ts" : "new.ts";
        expect(git("show", `HEAD:${file}`)).toBe("original");
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      }
      expect(await readFile(join(scanned, "new.ts"), "utf8")).toBe(
        "original\n",
      );
      expect(existsSync(source)).toBe(false);
    },
  );

  test.each(["ordinary", "environment", "config"])(
    "snapshots nested patches in the effective %s Git worktree",
    async (kind) => {
      const root = await repositories.create("patch-effective-worktree-");
      const invocation = join(root, "invocation");
      const nested = join(invocation, "nested");
      const selected =
        kind === "ordinary" ? invocation : join(root, "selected");
      await mkdir(nested, { recursive: true });
      const git = initializePatchGit(invocation);
      const inner = initializePatchGit(nested);
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(invocation, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      if (selected !== invocation) {
        await mkdir(selected);
        await copyFile(join(invocation, "app.ts"), join(selected, "app.ts"));
        inner("config", "core.worktree", join(selected, "nested"));
        await cp(nested, join(selected, "nested"), { recursive: true });
        if (kind === "config") git("config", "core.worktree", selected);
      }
      const gitEnvironment =
        kind === "environment" ? { GIT_WORK_TREE: selected } : {};
      const parentIndex = await readFile(join(invocation, ".git", "index"));
      const nestedIndex = await readFile(join(nested, ".git", "index"));
      const outcome = await runIssuePatch(invocation, {
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output) => {
          await writeFile(join(selected, "app.ts"), "fixed\n");
          await writeFile(join(selected, "nested", "app.ts"), "fixed\n");
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["app.ts", "nested/app.ts"],
      });
      expect(await readFile(join(invocation, ".git", "index"))).toEqual(
        parentIndex,
      );
      expect(await readFile(join(nested, ".git", "index"))).toEqual(
        nestedIndex,
      );
      if (selected !== invocation) {
        expect(await readFile(join(invocation, "app.ts"), "utf8")).toBe(
          "original\n",
        );
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe(
          "original\n",
        );
      }
    },
  );

  test.each([false, true])(
    "snapshots each canonical worktree once; enclosing gitlink alias=%p",
    async (alias) => {
      const repository = await repositories.create("patch-enclosing-alias-");
      const nested = join(repository, "dependency");
      await mkdir(nested);
      const git = initializePatchGit(repository);
      const inner = initializePatchGit(nested);
      await writeFile(join(nested, "app.ts"), "nested original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      if (alias) {
        git("config", "core.sparseCheckout", "true");
        await writeFile(
          join(repository, ".git", "info", "sparse-checkout"),
          "/*\n!/dependency\n",
        );
        git("update-index", "--skip-worktree", "dependency");
        await rm(nested, { recursive: true });
        await symlink(
          repository,
          nested,
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      const outcome = await runIssuePatch(repository, {
        onCodex: async (_args, output) => {
          await writeFile(join(repository, "app.ts"), "fixed\n");
          if (!alias) await writeFile(join(nested, "app.ts"), "nested fixed\n");
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(alias ? 2 : 0);
      if (alias) expect(outcome.stderr).toContain("ancestor worktree");
      else
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          applied: true,
          files: ["app.ts", "dependency/app.ts"],
        });
    },
  );
});

test.skipIf(process.platform !== "win32")(
  "assesses direct patches with drive-relative Git metadata",
  async () => {
    const repository = await fixtures.create("patch-drive-relative-");
    const git = initializePatchGit(repository);
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic drive-relative baseline");
    const drive = repository.slice(0, 2);
    expect(drive).toMatch(/^[a-z]:$/iu);
    const gitEnvironment = { GIT_DIR: `${drive}.git` };
    expect(
      gitText(["rev-parse", "--git-dir"], {
        cwd: repository,
        env: { ...process.env, ...gitEnvironment },
      }).trim(),
    ).toBe(gitEnvironment.GIT_DIR);
    let calls = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: repository,
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output) => {
          calls++;
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            output.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(join(repository, "app.ts"), "fixed\n");
            output?.stdout.write("Fixed and checked.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(calls).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["app.ts"],
    });
  },
);

describe("ordinary patch snapshot context", () => {
  test.each(
    ["ordinary", "saved", "inline"].flatMap((route) =>
      [
        "stable",
        "remove",
        "replace",
        "relative-filter",
        ...(route === "ordinary" ? [] : ["gitfile"]),
      ].flatMap((operation) =>
        (route === "inline"
          ? [undefined, "--create-pr"]
          : route === "saved"
            ? [undefined, "--assess-patch-risk", "--create-pr"]
            : [undefined, "--assess-patch-risk", "--create-pr"]
        ).flatMap((flag) =>
          ["ordinary", "relative"].map((settings) => ({
            route,
            operation,
            flag,
            settings,
            mode: flag ?? "no flag",
          })),
        ),
      ),
    ),
  )(
    "keeps $route $operation snapshots in the selected checkout with $settings settings and $mode",
    async ({ route, operation, flag, settings }) => {
      const root = await fixtures.create("patch-captured-snapshot-");
      const directory = join(root, "package");
      await mkdir(directory);
      const git = initializePatchGit(root);
      if (operation === "relative-filter")
        git("config", "diff.relative", "true");
      if (operation === "remove")
        git("config", "filter.unused.clean", "unreachable-clean-filter");
      await writeFile(join(root, "app.ts"), "unsafe\n");
      await writeFile(join(root, "unrelated.ts"), "original unrelated\n");
      await writeFile(join(directory, "keep.ts"), "component\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const stagedUnrelated =
        flag === "--create-pr" &&
        route !== "ordinary" &&
        (operation === "stable" || operation === "relative-filter");
      if (stagedUnrelated) {
        await writeFile(join(root, "unrelated.ts"), "staged unrelated\n");
        git("add", "unrelated.ts");
      }
      const index = await readFile(join(root, ".git/index"));
      const remote = await fixtures.create("patch-captured-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const foreign = await fixtures.create("patch-unselected-checkout-");
      const foreignGit = initializePatchGit(foreign);
      if (operation === "gitfile")
        foreignGit("config", "core.worktree", foreign);
      await writeFile(join(foreign, "keep.ts"), "unrelated baseline\n");
      foreignGit("add", ".");
      foreignGit("commit", "-m", "Synthetic unrelated baseline");
      await writeFile(join(foreign, "keep.ts"), "foreign preexisting edit\n");
      const foreignHead = foreignGit("rev-parse", "HEAD");
      const foreignRemote = await fixtures.create("patch-unselected-remote-");
      foreignGit("init", "--bare", foreignRemote);
      foreignGit("remote", "add", "origin", foreignRemote);
      await writeFile(
        join(foreign, "untracked.ts"),
        "unrelated local content\n",
      );
      const foreignObjects = foreignGit("count-objects", "-v");
      const foreignIndex = await readFile(join(foreign, ".git/index"));
      const providerConfig = join(remote, "provider-config");
      const environment = {
        ...(settings === "relative"
          ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
          : {}),
        GH_CONFIG_DIR: relative(directory, providerConfig),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.quotePath",
        GIT_CONFIG_VALUE_0: "false",
      };
      const scan = resultWithFindings(
        operation === "gitfile" ? ["high", "high"] : ["high"],
      );
      for (const finding of scan.findings.findings)
        finding.locations[0]!.path = "keep.ts";
      const argv =
        route === "ordinary"
          ? ["patch", "Synthetic issue"]
          : route === "saved"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", directory, "--patch"];
      const selectedDirectoryRemoved =
        route !== "ordinary" && operation === "remove";
      let modelCalls = 0;
      let assessmentCalls = 0;
      let redirectedSnapshotCommands = 0;
      const gitfileBookkeeping: string[][] = [];
      const gitfilePublication: string[][] = [];
      const foreignCommands: string[][] = [];
      let selectedBeforeTurn: string | undefined;
      const outcome = await runWorkflow(
        [...argv, ...(flag ? [flag] : []), "--json"],
        {
          currentDirectory: directory,
          environment,
          result: scan,
          onWorkbench: () => savedScan(scan, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (
                operation === "gitfile" &&
                (cwd === foreign ||
                  options?.directory === foreign ||
                  args.includes(foreign) ||
                  args.includes(join(foreign, ".git")) ||
                  options?.environment?.["GIT_DIR"] === join(foreign, ".git"))
              )
                foreignCommands.push([...args]);
              if (
                operation === "gitfile" &&
                modelCalls > 0 &&
                args.some((argument) =>
                  [
                    "add",
                    "read-tree",
                    "update-index",
                    "write-tree",
                    "commit",
                    "push",
                    "update-ref",
                  ].includes(argument),
                )
              )
                gitfileBookkeeping.push([...args]);
              if (
                operation === "replace" &&
                modelCalls > 0 &&
                (args.includes("read-tree") || args.includes("add"))
              )
                redirectedSnapshotCommands++;
              return runGitRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
            }
            if (operation === "gitfile" && modelCalls > 0)
              gitfilePublication.push([...args]);
            if (args[1] === "list") return "[]";
            expect(options?.environment?.["GH_CONFIG_DIR"]).toBe(
              providerConfig,
            );
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (args, output, childEnvironment) => {
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              assessmentCalls++;
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              await promisify(execFile)(
                "git",
                ["cat-file", "-e", artifact.base],
                {
                  cwd: output.appServer.directory,
                  env: childEnvironment,
                },
              );
              expect(artifact.changedFiles).toEqual(["package/keep.ts"]);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            modelCalls++;
            expect(output?.appServer?.directory).toBe(directory);
            if (operation === "gitfile" && modelCalls === 1)
              selectedBeforeTurn = git("rev-parse", "HEAD");
            await writeFile(join(root, "app.ts"), "fixed\n");
            if (
              route !== "ordinary" &&
              operation !== "remove" &&
              operation !== "replace"
            )
              await writeFile(
                join(directory, "keep.ts"),
                operation === "gitfile"
                  ? `fixed component ${modelCalls}\n`
                  : "fixed component\n",
              );
            if (operation === "gitfile" && modelCalls === 1)
              await writeFile(
                join(directory, ".git"),
                `gitdir: ${join(foreign, ".git")}\n`,
              );
            if (operation === "remove" || operation === "replace")
              await rm(directory, { recursive: true });
            if (operation === "replace")
              await symlink(
                foreign,
                directory,
                process.platform === "win32" ? "junction" : "dir",
              );
            if (route === "ordinary")
              output?.stdout.write("Fixed and checked.");
            else completePatches(args, output);
            return 0;
          },
        },
        {
          configure: (current) => {
            if (route !== "ordinary") return;
            current.assessPatchRisk = async (request) => {
              assessmentCalls++;
              expect(request.repository).toBe(root);
              expect(request.files).toBeUndefined();
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(modelCalls).toBe(operation === "gitfile" ? 2 : 1);
      expect(assessmentCalls).toBe(
        flag === "--assess-patch-risk" &&
          operation !== "replace" &&
          !selectedDirectoryRemoved
          ? 1
          : 0,
      );
      expect(foreignGit("count-objects", "-v")).toBe(foreignObjects);
      expect(foreignGit("rev-parse", "HEAD")).toBe(foreignHead);
      expect(foreignGit("ls-remote", "origin")).toBe("");
      expect(await readFile(join(foreign, "keep.ts"), "utf8")).toBe(
        "foreign preexisting edit\n",
      );
      expect(await readFile(join(foreign, ".git/index"))).toEqual(foreignIndex);
      expect(await readFile(join(foreign, "untracked.ts"), "utf8")).toBe(
        "unrelated local content\n",
      );
      if (operation === "gitfile") {
        expect(foreignCommands).toEqual([]);
        expect(gitfileBookkeeping.length).toBeGreaterThan(0);
        if (flag === "--create-pr") {
          expect(gitfilePublication.length).toBeGreaterThan(0);
          expect(git("rev-parse", "HEAD^")).toBe(selectedBeforeTurn!);
          expect(git("show", "HEAD:package/keep.ts")).toBe("fixed component 2");
          expect(git("ls-remote", "origin")).toContain(
            git("rev-parse", "HEAD"),
          );
        } else {
          expect(gitfilePublication).toEqual([]);
          expect(git("rev-parse", "HEAD")).toBe(selectedBeforeTurn!);
          expect(git("ls-remote", "origin")).toBe("");
        }
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("fixed\n");
        expect(await readFile(join(directory, "keep.ts"), "utf8")).toBe(
          "fixed component 2\n",
        );
        expect(await readFile(join(directory, ".git"), "utf8")).toBe(
          `gitdir: ${join(foreign, ".git")}\n`,
        );
      }
      if (operation === "replace") {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Patch directory now resolves outside the selected repository",
        );
        expect(redirectedSnapshotCommands).toBe(0);
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "main"));
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("fixed\n");
        return;
      }
      if (selectedDirectoryRemoved) {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Patch directory changed during patching",
        );
        expect(JSON.parse(outcome.stdout).patches).toMatchObject(
          scan.findings.findings.map(() => ({
            status: "verified",
            files: ["keep.ts"],
          })),
        );
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "main"));
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("fixed\n");
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      const result = JSON.parse(outcome.stdout);
      if (route === "inline") {
        expect(result.patches).toMatchObject(
          scan.findings.findings.map(() => ({
            status: "verified",
            files: ["keep.ts"],
          })),
        );
      } else {
        expect(result.applied).toBe(true);
        expect(result.files).toContain(
          route === "ordinary" && flag ? "../app.ts" : "app.ts",
        );
        expect(result.files).not.toContain("untracked.ts");
      }
      if (flag !== "--create-pr")
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
      else
        expect(git("show", "HEAD:app.ts")).toBe(
          route === "ordinary" ? "fixed" : "unsafe",
        );
      expect(git("show", "HEAD:unrelated.ts")).toBe("original unrelated");
      expect(git("diff", "--cached", "--name-only")).toBe(
        stagedUnrelated ? "unrelated.ts" : "",
      );
    },
  );
});

test.each(
  ["ordinary", "environment", "config"].flatMap((binding) =>
    [false, true].flatMap((remove) =>
      [false, true].map((redirect) => ({ binding, remove, redirect })),
    ),
  ),
)(
  "binds assessment Git discovery and rejects configuration redirects: $binding remove=$remove redirect=$redirect",
  async ({ binding, remove, redirect }) => {
    const root = await fixtures.create("patch-assessment-discovery-");
    const metadata = join(root, "metadata");
    const worktree = binding === "ordinary" ? metadata : join(root, "worktree");
    const invocation = join(metadata, "component");
    const replacement = join(root, "replacement");
    const gitEnvironment =
      binding === "environment" ? { GIT_WORK_TREE: worktree } : {};
    await mkdir(invocation, { recursive: true });
    await mkdir(worktree, { recursive: true });
    await mkdir(replacement);
    await writeFile(join(replacement, "app.ts"), "unrelated checkout\n");
    const rawGit = initializePatchGit(metadata);
    if (binding === "config") rawGit("config", "core.worktree", worktree);
    const git = (...args: string[]) =>
      gitText(args, {
        cwd: metadata,
        env: { ...process.env, ...gitEnvironment },
      }).trim();
    await writeFile(join(worktree, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic assessment baseline");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(metadata, ".git", "index"));
    let assessmentCalls = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: invocation,
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output, environment) => {
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            assessmentCalls++;
            expect(
              resolve(
                gitText(["rev-parse", "--show-toplevel"], {
                  cwd: output.appServer.directory,
                  env: environment,
                }).trim(),
              ),
            ).toBe(worktree);
            const result = await promisify(execFile)(
              "git",
              ["rev-parse", "HEAD"],
              {
                cwd: output.appServer.directory,
                env: environment,
              },
            );
            expect(result.stdout.trim()).toBe(head);
            const artifact = patchArtifactFromPrompt(output.appServer.prompt);
            await promisify(execFile)(
              "git",
              ["cat-file", "-e", artifact.base],
              {
                cwd: output.appServer.directory,
                env: environment,
              },
            );
            expect(artifact.changedFiles).toEqual(["app.ts"]);
            output.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(join(worktree, "app.ts"), "fixed\n");
            if (redirect) rawGit("config", "core.worktree", replacement);
            if (remove) await rm(invocation, { recursive: true });
            output?.stdout.write("Patch complete.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(redirect ? 2 : 0);
    expect(assessmentCalls).toBe(redirect ? 0 : 1);
    if (redirect)
      expect(outcome.stderr).toContain(
        "Git configuration changed during the patch",
      );
    expect(await readFile(join(worktree, "app.ts"), "utf8")).toBe("fixed\n");
    expect(await readFile(join(metadata, ".git", "index"))).toEqual(index);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(replacement, "app.ts"), "utf8")).toBe(
      "unrelated checkout\n",
    );
  },
);

describe("patch worktree root identity", () => {
  test.each([
    ...["ordinary", "saved", "inline"].flatMap((route) =>
      ["replace", "stable", "alias"].map((operation) => ({
        route,
        operation,
        layout: "external metadata",
      })),
    ),
    { route: "ordinary", operation: "replace", layout: "nested invocation" },
    ...["stable", "replace"].map((operation) => ({
      route: "ordinary",
      operation,
      layout: "external invocation",
    })),
  ])(
    "preserves checkout identity for $route $operation with $layout",
    async ({ route, operation, layout }) => {
      const root = await fixtures.create("patch-root-identity-");
      const foreignRoot = await fixtures.create("patch-root-unselected-");
      const external = layout !== "nested invocation";
      for (const parent of [root, foreignRoot]) {
        const worktree = join(parent, "worktree");
        await mkdir(join(worktree, "component"), { recursive: true });
        const git = initializePatchGit(worktree);
        await writeFile(join(worktree, "keep.ts"), "original\n");
        await writeFile(
          join(worktree, "component", "anchor.ts"),
          "component\n",
        );
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const remote = join(parent, "remote.git");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        if (external)
          await rename(join(worktree, ".git"), join(parent, ".git"));
      }
      const worktree = join(root, "worktree");
      const foreign = join(foreignRoot, "worktree");
      const foreignMetadata = join(external ? foreignRoot : foreign, ".git");
      const foreignGit = (...args: string[]) =>
        repositoryGit(foreignRoot)(
          "--git-dir",
          foreignMetadata,
          "--work-tree",
          foreign,
          ...args,
        );
      await writeFile(join(foreign, "keep.ts"), "foreign preexisting edit\n");
      const foreignObjects = foreignGit("count-objects", "-v");
      const foreignHead = foreignGit("rev-parse", "HEAD");
      const foreignIndex = await readFile(join(foreignMetadata, "index"));
      const foreignStatus = foreignGit("status", "--porcelain=v1");
      const directory =
        layout === "external invocation"
          ? root
          : operation === "alias"
            ? join(root, "worktree-alias")
            : external
              ? worktree
              : join(worktree, "component");
      if (operation === "alias")
        await symlink(
          worktree,
          directory,
          process.platform === "win32" ? "junction" : "dir",
        );
      const environment =
        layout === "external invocation"
          ? { GIT_WORK_TREE: worktree }
          : external
            ? { GIT_DIR: join("..", ".git") }
            : {};
      const foreignBlob = foreignGit("hash-object", join(foreign, "keep.ts"));
      const originalObjects = () =>
        repositoryGit(root)(
          "--git-dir",
          join(root, ".git"),
          "cat-file",
          "--batch-all-objects",
          "--batch-check=%(objectname)",
        ).split("\n");
      if (layout === "external invocation")
        expect(originalObjects()).not.toContain(foreignBlob);
      const scan = resultWithFindings(["high"]);
      scan.findings.findings[0]!.locations[0]!.path = "keep.ts";
      const argv =
        route === "ordinary"
          ? ["patch", "Synthetic issue"]
          : route === "saved"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", directory, "--patch"];
      let modelCalls = 0;
      const outcome = await runWorkflow([...argv, "--create-pr", "--json"], {
        currentDirectory: directory,
        environment,
        result: scan,
        onWorkbench: () => savedScan(scan, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (args, output) => {
          modelCalls++;
          if (operation === "replace") {
            await rename(worktree, join(root, "original-worktree"));
            await symlink(
              foreign,
              worktree,
              process.platform === "win32" ? "junction" : "dir",
            );
          } else await writeFile(join(worktree, "keep.ts"), "fixed\n");
          if (route === "ordinary") output?.stdout.write("Fixed and checked.");
          else completePatches(args, output);
          return 0;
        },
      });
      expect(modelCalls).toBe(1);
      if (layout === "external invocation")
        expect(originalObjects()).not.toContain(foreignBlob);
      expect(foreignGit("count-objects", "-v")).toBe(foreignObjects);
      expect(foreignGit("rev-parse", "HEAD")).toBe(foreignHead);
      expect(await readFile(join(foreignMetadata, "index"))).toEqual(
        foreignIndex,
      );
      expect(foreignGit("status", "--porcelain=v1")).toBe(foreignStatus);
      expect(foreignGit("ls-remote", "origin")).toBe("");
      expect(await readFile(join(foreign, "keep.ts"), "utf8")).toBe(
        "foreign preexisting edit\n",
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        operation === "replace" ? 2 : 0,
      );
      const published = repositoryGit(root)(
        "ls-remote",
        join(root, "remote.git"),
      );
      if (operation === "replace") expect(published).toBe("");
      else expect(published).toContain("refs/heads/codex-security/patch-");
    },
  );
});

describe("verified patch caller identity", () => {
  test.each(
    ["saved", "inline"].flatMap((route) =>
      [
        "move",
        "move-without-alias",
        "directory-to-file",
        "source-edit",
        "destination-overwrite",
        "source-replacement",
        "stable-alias",
        "removed-caller",
      ].map((operation) => ({ route, operation })),
    ),
  )("$route operation=$operation", async ({ route, operation }) => {
    const root = await fixtures.create("patch-caller-identity-");
    const repository = join(root, "repository");
    const component = join(repository, "component");
    const destination = join(repository, "destination");
    const alias = join(repository, "alias");
    const requested =
      operation === "move" ||
      operation === "move-without-alias" ||
      operation === "directory-to-file" ||
      operation === "removed-caller"
        ? component
        : alias;
    const remote = join(root, "remote.git");
    const redirected =
      operation !== "stable-alias" &&
      operation !== "removed-caller" &&
      operation !== "directory-to-file";
    const blocked = operation !== "stable-alias";
    await mkdir(component, { recursive: true });
    await writeFile(join(component, "app.ts"), "unsafe\n");
    await writeFile(join(component, "sibling.ts"), "original sibling\n");
    await writeFile(join(repository, "unrelated.ts"), "unrelated original\n");
    if (requested === alias)
      await symlink(
        component,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    if (operation === "destination-overwrite") {
      await mkdir(destination);
      await writeFile(
        join(destination, "sibling.ts"),
        "distinct destination sibling\n",
      );
    }
    const git = initializePatchGit(repository);
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(repository, ".git/index"));
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    // A configured clean filter triggers input inventory even without matching attributes.
    git("config", "filter.unused.clean", "unreachable-clean-filter");
    const scan = resultWithFindings(["high"]);
    scan.findings.findings[0]!.locations[0]!.path = "app.ts";
    let modelCalls = 0,
      assessments = 0,
      requestsCreated = 0;
    const outcome = await runWorkflow(
      [
        ...(route === "saved"
          ? ["patch", "--scan", "scan-1", "--assess-patch-risk"]
          : ["scan", requested, "--patch"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: requested,
        result: scan,
        onWorkbench: () => savedScan(scan, "scan-1", requested),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, options);
          if (args[1] === "create") requestsCreated++;
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (args, output) => {
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            const artifact = patchArtifactFromPrompt(output.appServer.prompt);
            expect(artifact.changedFiles).toEqual(["component/app.ts"]);
            assessments++;
            output.stdout.write(patchRiskAssessment().report);
          } else {
            modelCalls++;
            if (redirected) {
              if (operation === "move" || operation === "move-without-alias")
                await rename(component, destination);
              else {
                await (
                  await import("node:fs/promises")
                ).cp(component, destination, { recursive: true });
                await rm(alias, { recursive: true });
              }
              if (operation !== "move-without-alias")
                await symlink(
                  destination,
                  requested,
                  process.platform === "win32" ? "junction" : "dir",
                );
              await writeFile(join(destination, "app.ts"), "fixed\n");
              if (operation === "source-edit")
                await writeFile(
                  join(component, "sibling.ts"),
                  "unreported source edit\n",
                );
              if (operation === "source-replacement") {
                await rm(component, { recursive: true });
                await writeFile(component, "unreported source replacement\n");
              }
            } else if (operation === "directory-to-file") {
              await rm(component, { recursive: true });
              await writeFile(component, "replacement fix\n");
            } else if (operation === "removed-caller")
              await rm(component, { recursive: true });
            else await writeFile(join(component, "app.ts"), "fixed\n");
            await writeFile(
              join(repository, "unrelated.ts"),
              "unreported root edit\n",
            );
            completePatches(args, output);
          }
          return 0;
        },
      },
    );
    expect(modelCalls).toBe(1);
    expect(JSON.parse(outcome.stdout).patches).toMatchObject([
      { occurrenceId: "occ_1", status: "verified", files: ["app.ts"] },
    ]);
    expect(await readFile(join(repository, "unrelated.ts"), "utf8")).toBe(
      "unreported root edit\n",
    );
    expect(assessments).toBe(route === "saved" && !blocked ? 1 : 0);
    if (blocked) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Patch directory changed during patching",
      );
      if (operation === "directory-to-file")
        expect(await readFile(component, "utf8")).toBe("replacement fix\n");
      else if (operation === "removed-caller")
        await expect(readFile(join(component, "app.ts"))).rejects.toMatchObject(
          {
            code: "ENOENT",
          },
        );
      else {
        expect(await readFile(join(destination, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
        expect(await readFile(join(destination, "sibling.ts"), "utf8")).toBe(
          "original sibling\n",
        );
      }
      if (operation === "source-edit")
        expect(await readFile(join(component, "sibling.ts"), "utf8")).toBe(
          "unreported source edit\n",
        );
      if (operation === "source-replacement")
        expect(await readFile(component, "utf8")).toBe(
          "unreported source replacement\n",
        );
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("branch", "--show-current")).toBe("main");
      expect(await readFile(join(repository, ".git/index"))).toEqual(index);
      expect(git("ls-remote", "origin")).toBe("");
      expect(requestsCreated).toBe(0);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      expect(requestsCreated).toBe(1);
      expect(git("show", "HEAD:component/app.ts")).toBe("fixed");
      expect(git("show", "HEAD:component/sibling.ts")).toBe("original sibling");
      expect(git("show", "HEAD:unrelated.ts")).toBe("unrelated original");
    }
  });
});

test.each([
  ["absolute", "from"],
  ["relative", "from"],
  ["parent primary pool", "from"],
  ["absolute", "after removing"],
  ["relative", "after removing"],
  ["quoted relative", "after removing"],
])(
  "preserves %s nested alternates %s an outside invocation",
  async (kind, context) => {
    const removeInvocation = context === "after removing";
    const root = await fixtures.create("patch-outside-alternate-");
    const repository = join(root, "repository");
    const invocation = removeInvocation
      ? join(root, "temporary", "invocation")
      : join(root, "invocation");
    const nested = join(repository, "nested");
    const pool =
      kind === "parent primary pool"
        ? join(repository, ".git", "objects")
        : removeInvocation
          ? join(root, "pool with space", "objects")
          : join(invocation, "pool", "objects");
    await mkdir(repository);
    await mkdir(invocation, { recursive: true });
    const git = initializePatchGit(repository);
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    await mkdir(nested);
    const inner = initializePatchGit(nested);
    inner("config", "maintenance.auto", "false");
    await writeFile(join(nested, "app.ts"), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    if (kind === "parent primary pool") {
      await cp(join(nested, ".git", "objects"), pool, {
        recursive: true,
        force: false,
      });
      await rm(join(nested, ".git", "objects"), { recursive: true });
    } else {
      await mkdir(dirname(pool));
      await rename(join(nested, ".git", "objects"), pool);
    }
    await mkdir(join(nested, ".git", "objects"));
    expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
    const gitEnvironment = {
      GIT_DIR: join(repository, ".git"),
      GIT_WORK_TREE: repository,
      GIT_ALTERNATE_OBJECT_DIRECTORIES:
        kind === "quoted relative"
          ? JSON.stringify(relative(invocation, pool))
          : kind === "relative"
            ? relative(invocation, pool)
            : pool,
    };
    expect(
      gitText(
        [
          "--git-dir",
          join(nested, ".git"),
          "--work-tree",
          nested,
          "rev-parse",
          "HEAD^{tree}",
        ],
        { cwd: invocation, env: { ...process.env, ...gitEnvironment } },
      ).trim(),
    ).toMatch(/^[0-9a-f]+$/);
    let calls = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: invocation,
        environment: { ...process.env, ...gitEnvironment },
        onRepositoryCommand: gitWithEnvironment(gitEnvironment),
        onCodex: async (_args, output) => {
          calls++;
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            output.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(join(repository, "app.ts"), "fixed\n");
            await writeFile(join(nested, "app.ts"), "fixed\n");
            if (removeInvocation) await rm(invocation, { recursive: true });
            output?.stdout.write("Fixed and checked.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(calls).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["app.ts", "nested/app.ts"].map((file) =>
        relative(invocation, join(repository, file)).split(sep).join("/"),
      ),
    });
  },
);

describe("patch Git metadata identity", () => {
  test.each(["stable", "retargeted", "deleted", "relocated"])(
    "preserves foreign objects for a %s caller alias",
    async (kind) => {
      const root = await fixtures.create("patch-metadata-binding-");
      const repository = join(root, "repository");
      const foreign = join(root, "foreign");
      const destination = join(repository, "ignored");
      const alias = join(repository, "alias");
      for (const checkout of [repository, foreign]) {
        await mkdir(checkout, { recursive: true });
        const git = initializePatchGit(checkout);
        await writeFile(join(checkout, "app.ts"), "original\n");
        await writeFile(join(checkout, ".gitignore"), "alias\nignored/\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
      }
      await symlink(
        repository,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      const outside = repositoryGit(foreign);
      const foreignHead = outside("rev-parse", "HEAD");
      const foreignIndex = await readFile(join(foreign, ".git", "index"));
      const foreignObjects = outside(
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname)",
      );
      let modelCalls = 0;
      const outcome = await runIssuePatch(alias, {
        onRepositoryCommand: (command, args, cwd, options) => {
          if (args[0] === "-C" && args.includes("--absolute-git-dir")) {
            expect(args[1]).toBe(destination);
            expect(Object.hasOwn(options!.environment!, "GIT_DIR")).toBe(true);
            expect(options!.environment!["GIT_DIR"]).toBeUndefined();
            expect(options!.environment!["GIT_WORK_TREE"]).toBe(repository);
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: {
                GIT_DIR: join(foreign, ".git"),
                ...options?.environment,
              },
            });
          }
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          modelCalls++;
          await writeFile(join(repository, "app.ts"), "fixed\n");
          if (kind !== "stable") {
            if (kind !== "deleted") {
              await mkdir(destination);
              if (kind === "retargeted")
                await writeFile(
                  join(destination, ".git"),
                  `gitdir: ${join(foreign, ".git")}\n`,
                );
            }
            await rm(alias, { recursive: true });
            if (kind !== "deleted")
              await symlink(
                destination,
                alias,
                process.platform === "win32" ? "junction" : "dir",
              );
          }
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      });
      expect(modelCalls, outcome.stderr).toBe(1);
      expect(outcome.exitCode, outcome.stderr).toBe(
        kind === "retargeted" ? 2 : 0,
      );
      if (kind === "retargeted")
        expect(outcome.stderr).toContain(
          "The patch Git directory changed during patching",
        );
      else
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          applied: true,
          files: ["app.ts"],
        });
      expect(
        outside(
          "cat-file",
          "--batch-all-objects",
          "--batch-check=%(objectname)",
        ),
      ).toBe(foreignObjects);
      expect(outside("rev-parse", "HEAD")).toBe(foreignHead);
      expect(await readFile(join(foreign, ".git", "index"))).toEqual(
        foreignIndex,
      );
      expect(await readFile(join(foreign, "app.ts"), "utf8")).toBe(
        "original\n",
      );
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "fixed\n",
      );
    },
  );
});
