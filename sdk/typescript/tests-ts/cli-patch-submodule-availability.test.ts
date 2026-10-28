import { afterEach, describe, expect, test } from "bun:test";
import { appendFile, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  publicationRepository,
  readAppliedText,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

describe("deinitialized patch submodule availability", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  async function fixture(published = false, initialized = false) {
    const outer = await publicationRepository(fixtures);
    const { directory, git } = outer;
    const hooks = await fixtures.create("patch-submodule-hooks-");
    git("config", "core.hooksPath", hooks);
    const nested = join(directory, "nested");
    await mkdir(nested);
    const inner = repositoryGit(nested);
    inner("init", "--initial-branch=main");
    inner("config", "user.name", "Synthetic User");
    inner("config", "user.email", "synthetic@example.test");
    inner("config", "core.hooksPath", hooks);
    await writeFile(join(nested, "app.ts"), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    const childRemote = await fixtures.create("patch-submodule-origin-");
    git("clone", "--bare", nested, childRemote);
    inner("remote", "add", "origin", childRemote);
    inner("fetch", "origin");
    git("config", "-f", ".gitmodules", "submodule.nested.path", "nested");
    git("config", "-f", ".gitmodules", "submodule.nested.url", childRemote);
    git("add", ".gitmodules", "nested");
    git("commit", "-m", "Synthetic registered submodule");
    git("submodule", "init");
    git("submodule", "absorbgitdirs", "--", "nested");
    const retained = inner("rev-parse", "--absolute-git-dir");
    const pushes: string[][] = [];
    const nativePushes: { exitCode: number; stderr: string }[] = [];
    let interruptPush = false;
    let creations = 0;
    let modelRuns = 0;
    const run = (
      args: string[],
      onCodex?: NonNullable<Parameters<typeof runWorkflow>[1]>["onCodex"],
    ) =>
      runWorkflow(args, {
        currentDirectory: directory,
        onRepositoryCommand: (command, arguments_, cwd, options) => {
          if (command === "git") {
            if (arguments_[0] === "push") {
              pushes.push([...arguments_]);
              if (interruptPush) {
                interruptPush = false;
                throw new Error("Synthetic publication interruption");
              }
              if (initialized) {
                // Native recursive push uses the parent's branch refspec for the child.
                const branch = arguments_.at(-1)!;
                if (
                  !inner(
                    "for-each-ref",
                    "--format=%(refname)",
                    `refs/heads/${branch}`,
                  )
                )
                  inner("branch", branch);
              }
              try {
                const result = runGitRepositoryCommand(
                  command,
                  arguments_,
                  cwd,
                  options,
                );
                nativePushes.push({ exitCode: 0, stderr: "" });
                return result;
              } catch (error) {
                const failure = error as { status: number; stderr: Buffer };
                nativePushes.push({
                  exitCode: failure.status,
                  stderr: failure.stderr.toString().trim(),
                });
                throw error;
              }
            }
            return runGitRepositoryCommand(command, arguments_, cwd, options);
          }
          if (arguments_[1] === "list") return "[]";
          if (arguments_[1] === "create") creations += 1;
          return "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (arguments_, output) => {
          modelRuns += 1;
          if (onCodex === undefined)
            throw new Error("Resume must not rerun the patch model.");
          return onCodex(arguments_, output);
        },
      });
    const commitUpdate = async () => {
      await writeFile(join(nested, "app.ts"), "fixed\n");
      inner("commit", "-am", "Synthetic nested update");
      return inner("rev-parse", "HEAD");
    };
    let preparedCommit = "";
    if (initialized) {
      inner("branch", "--set-upstream-to", "origin/main", "main");
    } else {
      // Configuration setup precedes capture; the patch changes only the gitlink.
      preparedCommit = await commitUpdate();
      if (published) inner("push", "origin", "HEAD:main");
      git("submodule", "deinit", "--force", "--", "nested");
    }
    const update = async () => {
      const commit = initialized ? await commitUpdate() : preparedCommit;
      if (initialized) git("add", "nested");
      else git("update-index", "--cacheinfo", `160000,${commit},nested`);
      return commit;
    };
    return {
      ...outer,
      childRemote,
      retained,
      run,
      update,
      pushes,
      nativePushes,
      interruptPublication: () => {
        interruptPush = true;
      },
      counts: () => ({ creations, modelRuns }),
      branch: () =>
        git(
          "for-each-ref",
          "--format=%(refname:short)",
          "refs/heads/codex-security",
        ),
    };
  }

  const unavailable = [
    "missing object",
    "no remote refs",
    "deleted registration file",
    "unregistered gitlink",
  ] as const;
  test.each(unavailable)(
    "refuses %s on initial publication and resume",
    async (kind) => {
      const current = await fixture();
      const { directory, git, retained } = current;
      const initial = await current.run(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        async (_args, output) => {
          let commit = await current.update();
          if (kind === "missing object") {
            commit = "1".repeat(commit.length);
            expect(() =>
              git("--git-dir", retained, "cat-file", "-t", commit),
            ).toThrow();
            git("update-index", "--cacheinfo", `160000,${commit},nested`);
          } else if (kind === "no remote refs") {
            for (const ref of git(
              "--git-dir",
              retained,
              "for-each-ref",
              "--format=%(refname)",
              "refs/remotes",
            )
              .split("\n")
              .filter(Boolean))
              git("--git-dir", retained, "update-ref", "-d", ref);
          } else if (kind === "deleted registration file") {
            await rm(join(directory, ".gitmodules"));
          } else {
            git("update-index", "--force-remove", "nested");
            await mkdir(join(directory, "unregistered"));
            git(
              "update-index",
              "--add",
              "--cacheinfo",
              `160000,${commit},unregistered`,
            );
          }
          output?.stdout.write("Synthetic patch complete.");
          return 0;
        },
      );
      expect(initial.exitCode).toBe(2);
      expect(initial.stderr).toContain(
        "not available in its remote-tracking refs",
      );
      const branch = current.branch();
      expect(branch).not.toBe("");
      const saved = git("rev-parse", `refs/heads/${branch}`);
      const resumed = await current.run([
        "patch",
        "--resume-pr",
        branch,
        "--json",
      ]);
      expect(resumed.exitCode).toBe(2);
      expect(resumed.stderr).toContain(
        "not available in its remote-tracking refs",
      );
      expect(git("rev-parse", `refs/heads/${branch}`)).toBe(saved);
      expect(git("ls-remote", "origin")).toBe("");
      expect(current.pushes).toEqual([]);
      expect(current.counts()).toEqual({ creations: 0, modelRuns: 1 });
    },
  );

  test.each([false, true])(
    "publishes an available commit with deleted current registration: %p",
    async (deleteRegistration) => {
      const current = await fixture(true);
      let commit = "";
      const result = await current.run(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        async (_args, output) => {
          commit = await current.update();
          if (deleteRegistration)
            await rm(join(current.directory, ".gitmodules"));
          output?.stdout.write("Synthetic patch complete.");
          return 0;
        },
      );
      expect(result.exitCode).toBe(0);
      expect(current.counts()).toEqual({ creations: 1, modelRuns: 1 });
      const branch = current.branch();
      expect(
        repositoryGit(current.remote)("ls-tree", branch, "nested"),
      ).toContain(`160000 commit ${commit}\tnested`);
      if (deleteRegistration) {
        expect(
          repositoryGit(current.remote)("ls-tree", branch, ".gitmodules"),
        ).toBe("");
      } else {
        const clone = await fixtures.create("patch-submodule-published-");
        current.git("clone", "--branch", branch, current.remote, clone);
        repositoryGit(clone)(
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "update",
          "--init",
        );
        expect(await readAppliedText(join(clone, "nested", "app.ts"))).toBe(
          "fixed\n",
        );
      }
    },
  );

  type Setting = readonly [string, string | undefined];
  type ConfigurationCase = {
    name: string;
    settings: readonly Setting[];
    expected: "blocked" | "success" | "opt-out" | "native";
    published?: boolean;
    initialized?: boolean;
  };
  const configurations: ConfigurationCase[] = [
    ...["check", "on-demand", "only"].map((value): ConfigurationCase => ({
      name: `unpublished child with push recursion ${value}`,
      settings: [["push.recurseSubmodules", value]],
      expected: "blocked",
    })),
    {
      name: "unpublished child with submodule recursion true",
      settings: [["submodule.recurse", "true"]],
      expected: "blocked",
    },
    {
      name: "unpublished child with valueless submodule recursion",
      settings: [["submodule.recurse", undefined]],
      expected: "blocked",
    },
    {
      name: "published child with push recursion check",
      settings: [["push.recurseSubmodules", "check"]],
      expected: "success",
      published: true,
    },
    {
      name: "published child with submodule recursion true",
      settings: [["submodule.recurse", "true"]],
      expected: "success",
      published: true,
    },
    {
      name: "initialized child with push recursion on-demand",
      settings: [["push.recurseSubmodules", "on-demand"]],
      expected: "success",
      initialized: true,
    },
    {
      name: "initialized child with submodule recursion true",
      settings: [["submodule.recurse", "true"]],
      expected: "success",
      initialized: true,
    },
    ...[
      ["push.recurseSubmodules", "no"],
      ["push.recurseSubmodules", "off"],
      ["push.recurseSubmodules", ""],
      ["submodule.recurse", "false"],
      ["submodule.recurse", ""],
    ].map(([key, value]): ConfigurationCase => ({
      name: `explicit opt-out ${key}=${JSON.stringify(value)}`,
      settings: [[key!, value!]],
      expected: "opt-out",
    })),
    {
      name: "later submodule false overrides push check",
      settings: [
        ["push.recurseSubmodules", "check"],
        ["submodule.recurse", "false"],
      ],
      expected: "opt-out",
    },
    {
      name: "later push check overrides submodule false",
      settings: [
        ["submodule.recurse", "false"],
        ["push.recurseSubmodules", "check"],
      ],
      expected: "blocked",
    },
    {
      name: "last repeated push value disables recursion",
      settings: [
        ["push.recurseSubmodules", "on-demand"],
        ["push.recurseSubmodules", "false"],
      ],
      expected: "opt-out",
    },
    ...["invalid-mode", "true", undefined].map((value): ConfigurationCase => ({
      name: `native invalid push recursion ${value ?? "valueless"}`,
      settings: [["push.recurseSubmodules", value]],
      expected: "native",
    })),
    {
      name: "native handling of invalid push recursion followed by check",
      settings: [
        ["push.recurseSubmodules", "invalid-mode"],
        ["push.recurseSubmodules", "check"],
      ],
      expected: "native",
    },
  ];

  test.each(configurations.map((value) => [value.name, value] as const))(
    "%s on initial publication and resume",
    async (_name, configuration) => {
      for (const phase of ["initial", "resume"]) {
        const current = await fixture(
          configuration.published,
          configuration.initialized,
        );
        for (const [key, value] of configuration.settings) {
          if (value === undefined) {
            const [section, name] = key.split(".");
            await appendFile(
              join(current.git("rev-parse", "--absolute-git-dir"), "config"),
              `\n[${section}]\n\t${name}\n`,
            );
          } else current.git("config", "--add", key, value);
        }
        const configured = () =>
          current.git(
            "config",
            "--null",
            "--get-regexp",
            "^(push\\.recursesubmodules|submodule\\.recurse)$",
          );
        const originalConfiguration = configured();
        const interrupted =
          phase === "resume" && configuration.expected !== "blocked";
        if (interrupted) current.interruptPublication();
        let commit = "";
        const initial = await current.run(
          ["patch", "Synthetic issue", "--create-pr", "--json"],
          async (_args, output) => {
            commit = await current.update();
            output?.stdout.write("Synthetic patch complete.");
            return 0;
          },
        );
        const branch = current.branch();
        expect(branch).not.toBe("");
        const saved = current.git("rev-parse", `refs/heads/${branch}`);
        if (interrupted) {
          expect(initial.exitCode).toBe(2);
          expect(initial.stderr).toContain(
            "Synthetic publication interruption",
          );
          expect(current.nativePushes).toEqual([]);
        }
        const result =
          phase === "resume"
            ? await current.run(["patch", "--resume-pr", branch, "--json"])
            : initial;
        expect(current.git("rev-parse", `refs/heads/${branch}`)).toBe(saved);
        expect(configured()).toBe(originalConfiguration);
        expect(current.counts().modelRuns).toBe(1);

        if (configuration.expected === "blocked") {
          expect(initial.exitCode).toBe(2);
          expect(result.exitCode).toBe(2);
          expect(result.stderr).toContain(
            "not available in its remote-tracking refs",
          );
          expect(current.git("ls-remote", "origin")).toBe("");
          expect(repositoryGit(current.childRemote)("show-ref")).not.toContain(
            commit,
          );
          expect(current.pushes).toEqual([]);
          expect(current.nativePushes).toEqual([]);
          expect(current.counts().creations).toBe(0);
          continue;
        }

        expect(current.pushes).toEqual(
          Array.from({ length: interrupted ? 2 : 1 }, () => [
            "push",
            "--set-upstream",
            `--force-with-lease=refs/heads/${branch}:`,
            "origin",
            branch,
          ]),
        );
        expect(current.nativePushes).toHaveLength(1);
        const native = current.nativePushes[0]!;
        if (configuration.expected === "native") {
          // Git versions differ on an invalid value overwritten by a later valid one.
          // Preserve the native push result and diagnostic in either case.
          expect(result.exitCode).toBe(native.exitCode === 0 ? 0 : 2);
          if (native.exitCode !== 0) {
            expect(native.stderr).not.toBe("");
            expect(result.stderr).toContain(native.stderr);
            expect(current.git("ls-remote", "origin")).toBe("");
          }
          expect(current.counts().creations).toBe(
            native.exitCode === 0 ? 1 : 0,
          );
          continue;
        }

        expect(native.exitCode).toBe(0);
        expect(result.exitCode).toBe(0);
        expect(current.counts().creations).toBe(1);
        expect(
          repositoryGit(current.remote)("ls-tree", branch, "nested"),
        ).toContain(`160000 commit ${commit}\tnested`);
        if (configuration.expected === "opt-out") {
          expect(repositoryGit(current.childRemote)("show-ref")).not.toContain(
            commit,
          );
          continue;
        }
        expect(repositoryGit(current.childRemote)("show-ref")).toContain(
          commit,
        );
        const clone = await fixtures.create("patch-submodule-configured-");
        current.git("clone", "--branch", branch, current.remote, clone);
        repositoryGit(clone)(
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "update",
          "--init",
        );
        expect(await readAppliedText(join(clone, "nested", "app.ts"))).toBe(
          "fixed\n",
        );
      }
    },
  );
});
