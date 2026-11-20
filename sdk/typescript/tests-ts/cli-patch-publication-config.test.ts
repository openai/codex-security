import { expect, test } from "bun:test";
import { execFileSync, execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  patchRiskAssessment,
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
  resultWithFindings,
  savedScan,
  patchDirectories,
} from "./cli-patch-fixtures.js";
import { promisify } from "node:util";

const fixtures = patchDirectories();

for (const callerKind of ["outside", "scoped"] as const) {
  for (const source of ["global", "system", "included"] as const) {
    test(`publication keeps relative ${source} configuration from the ${callerKind} caller`, async () => {
      const { directory, git, remote } = await publicationRepository(fixtures);
      const support = await fixtures.create("patch-publication-config-");
      const caller =
        callerKind === "outside" ? support : join(directory, "src");
      const setup = callerKind === "outside" ? caller : directory;
      const shadow = callerKind === "outside" ? directory : caller;
      const trustedHooks = join(support, "trusted-hooks");
      const otherHooks = join(support, "other-hooks");
      const trustedEffect = join(support, "trusted-effect");
      const otherEffect = join(support, "other-effect");
      for (const [hooks, effect] of [
        [trustedHooks, trustedEffect],
        [otherHooks, otherEffect],
      ]) {
        await mkdir(hooks!);
        await writeFile(
          join(hooks!, "post-index-change"),
          `#!/bin/sh\nprintf effect >> '${effect!.replaceAll("\\", "/").replaceAll("'", "'\\''")}'\n`,
          { mode: 0o755 },
        );
      }
      const configuration = (hooks: string) =>
        `[core]\n hooksPath = ${JSON.stringify(hooks.replaceAll("\\", "/"))}\n[alias]\n synthetic-check = status --porcelain\n`;
      const active = join(
        setup,
        source === "included" ? "included-settings" : "settings",
      );
      await writeFile(active, configuration(trustedHooks));
      if (source === "included")
        await writeFile(
          join(setup, "settings"),
          "[include]\npath = included-settings\n",
        );
      await writeFile(
        join(shadow, "settings"),
        "[synthetic]\nvalue = source data\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic configuration fixture");
      const environment: NodeJS.ProcessEnv = {
        GIT_DIR: join(directory, ".git"),
        GIT_WORK_TREE: directory,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: join(support, "empty-global"),
        ...(source === "global" || source === "included"
          ? { GIT_CONFIG_GLOBAL: "settings" }
          : {}),
        ...(source === "system"
          ? { GIT_CONFIG_NOSYSTEM: undefined, GIT_CONFIG_SYSTEM: "settings" }
          : {}),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "user.name",
        GIT_CONFIG_VALUE_0: "Configured Fixture",
        GIT_CONFIG_PARAMETERS: "'user.email=fixture@example.invalid'",
      };
      let trustedBefore = "";
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: caller,
          environment,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command !== "git")
              return args[1] === "create"
                ? "https://example.test/repository/pull/1"
                : "[]";
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
          onCodex: async (_args, output) => {
            const controls =
              output?.appServer?.permissions?.readOnlyPaths ?? [];
            expect(controls).toContain(active);
            expect(controls).not.toContain(join(shadow, "settings"));
            trustedBefore = await readFile(trustedEffect, "utf8").catch(
              () => "",
            );
            await writeFile(
              join(shadow, "settings"),
              configuration(otherHooks),
            );
            await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
            output?.stdout.write("Synthetic patch complete.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(await readFile(otherEffect, "utf8").catch(() => "")).toBe("");
      expect((await readFile(trustedEffect, "utf8")).length).toBeGreaterThan(
        trustedBefore.length,
      );
      expect(await readFile(active, "utf8")).toBe(configuration(trustedHooks));
      expect(git("log", "-1", "--format=%an <%ae>")).toBe(
        "Configured Fixture <fixture@example.invalid>",
      );
      expect(git("ls-remote", remote)).toContain(
        "refs/heads/codex-security/patch-",
      );
      expect(
        execFileSync("git", ["synthetic-check"], {
          cwd: caller,
          env: { ...process.env, ...environment },
          encoding: "utf8",
        }),
      ).toBe("");
    });
  }
}

test("publication preserves empty global and system configuration paths", async () => {
  const { directory } = await publicationRepository(fixtures);
  const home = await fixtures.create("patch-empty-configuration-");
  const hooks = join(home, "hooks");
  const effect = join(home, "effect");
  await mkdir(hooks);
  await writeFile(
    join(hooks, "post-index-change"),
    `#!/bin/sh\nprintf effect >> '${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'\n`,
    { mode: 0o755 },
  );
  await writeFile(
    join(home, ".gitconfig"),
    `[synthetic]\nvalue = home-config\n[core]\nhooksPath = ${JSON.stringify(hooks.replaceAll("\\", "/"))}\n`,
  );
  const environment = {
    HOME: home,
    USERPROFILE: home,
    GIT_CONFIG_GLOBAL: "",
    GIT_CONFIG_SYSTEM: "",
    GIT_CONFIG_NOSYSTEM: undefined,
  };
  expect(
    execFileSync("git", ["config", "--get", "synthetic.value"], {
      cwd: directory,
      env: { ...process.env, ...environment, GIT_CONFIG_GLOBAL: undefined },
      encoding: "utf8",
    }).trim(),
  ).toBe("home-config");
  const outcome = await runWorkflow(
    ["patch", "Synthetic issue", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      environment,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command !== "git")
          return args[1] === "create"
            ? "https://example.test/repository/pull/1"
            : "[]";
        const selected = { ...environment, ...options?.environment };
        expect(selected.GIT_CONFIG_GLOBAL).toBe("");
        expect(selected.GIT_CONFIG_SYSTEM).toBe("");
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: selected,
        });
      },
      onCodex: async (_args, output) => {
        await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
        output?.stdout.write("Synthetic patch complete.");
        return 0;
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(await readFile(effect, "utf8").catch(() => "")).toBe("");
});

test.each(["HOME", "XDG_CONFIG_HOME"])(
  "publication keeps Git's relative %s anchored after the outside caller is removed",
  async (selector) => {
    const { directory, git } = await publicationRepository(fixtures);
    const caller = await fixtures.create("patch-config-caller-");
    const support = await fixtures.create("patch-config-home-");
    const shadow = join(
      directory,
      "settings",
      selector === "HOME" ? ".gitconfig" : "git/config",
    );
    await mkdir(dirname(shadow), { recursive: true });
    await writeFile(shadow, "[i18n]\ncommitEncoding = ISO-8859-1\n");
    git("add", ".");
    git("commit", "-m", "Track harmless worktree configuration");
    const environment = {
      GIT_DIR: join(directory, ".git"),
      GIT_WORK_TREE: directory,
      GIT_CONFIG_GLOBAL: undefined,
      GIT_CONFIG_NOSYSTEM: "1",
      HOME: support,
      XDG_CONFIG_HOME: support,
      [selector]: "settings",
    };
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: (tool, args, cwd, options) =>
          tool === "git"
            ? runGitRepositoryCommand(tool, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              })
            : args[1] === "create"
              ? "https://example.test/repository/pull/1"
              : "[]",
        onCodex: async (_args, output) => {
          await rm(caller, { recursive: true });
          await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
          output?.stdout.write("Synthetic patch complete.");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(git("cat-file", "-p", "HEAD")).not.toContain("encoding ISO-8859-1");
  },
);

test("assessment and publication protect the outside caller after rebinding Git", async () => {
  const { directory } = await publicationRepository(fixtures);
  const caller = await fixtures.create("patch-rebinding-caller-");
  const environment = {
    GIT_DIR: join(directory, ".git"),
    GIT_WORK_TREE: directory,
  };
  let patched = false;
  const operations = [
    "--absolute-git-dir",
    "--show-toplevel",
    "push",
    "create",
  ];
  const calls: { operation: string; roots: string[] }[] = [];
  const outcome = await runWorkflow(
    [
      "patch",
      "Synthetic issue",
      "--assess-patch-risk",
      "--create-pr",
      "--json",
    ],
    {
      currentDirectory: caller,
      environment,
      onCodex: async (_args, output) => {
        if (output?.appServer?.prompt.includes("immutable patch artifact")) {
          output.stdout.write(patchRiskAssessment().report);
        } else {
          await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
          patched = true;
          output?.stdout.write("Synthetic patch complete.");
        }
        return 0;
      },
      onRepositoryCommand: (command, args, cwd, options) => {
        if (patched) {
          const operation = operations.find((name) => args.includes(name));
          if (operation)
            calls.push({
              operation,
              roots: [cwd, ...(options?.protectedRoots ?? [])],
            });
        }
        if (command !== "git")
          return args[1] === "create"
            ? "https://example.test/repository/pull/1"
            : "[]";
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(new Set(calls.map(({ operation }) => operation))).toEqual(
    new Set(operations),
  );
  for (const { operation, roots } of calls)
    expect(roots, operation).toEqual(
      expect.arrayContaining([caller, directory]),
    );
});

const gh = Bun.which("gh");

for (const mode of ["resume", "prepare"]) {
  for (const selector of mode === "resume"
    ? ["unset"]
    : ["unset", "unrelated", "missing", "source alias"]) {
    test.skipIf(gh === null)(
      `${mode} reuses the existing publication with ${selector} GIT_CONFIG`,
      async () => {
        const { directory, git } = await publicationRepository(fixtures);
        const support = await fixtures.create("patch-publication-selector-");
        const config = join(support, "selector");
        const globalConfig = join(support, "global");
        await writeFile(globalConfig, "");
        await writeFile(config, "[synthetic]\n selector = original\n");
        const source = "https://github.com/example/source.git";
        if (selector === "source alias") {
          git(
            "config",
            "url.https://github.com/example/.insteadOf",
            "synthetic:",
          );
          git("remote", "set-url", "origin", "synthetic:source.git");
        } else git("remote", "set-url", "origin", source);
        const branch = "codex-security/patch-scan-1";
        const commit = git("rev-parse", "HEAD");
        if (mode === "resume") {
          git("branch", branch);
          git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
        }
        const environment: NodeJS.ProcessEnv = {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          HOME: support,
          USERPROFILE: support,
          GH_CONFIG_DIR: support,
          GH_NO_UPDATE_NOTIFIER: "1",
          GH_PROMPT_DISABLED: "1",
          GH_TOKEN: "synthetic-gh-test-token",
          GH_REPO: "github.com/example/upstream",
          GH_HOST: "github.com",
          GIT_CONFIG_GLOBAL: globalConfig,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_PARAMETERS: "'synthetic.inherited=kept'",
          GIT_CONFIG:
            selector === "unset"
              ? undefined
              : selector === "missing"
                ? join(support, "missing")
                : config,
        };
        const originalEnvironment = { ...environment };
        const originalConfig = await readFile(join(directory, ".git/config"));
        const originalIndex = await readFile(join(directory, ".git/index"));
        const originalRefs = git(
          "for-each-ref",
          "--format=%(refname):%(objectname)",
        );
        const originalSource = await readFile(
          join(directory, "src/finding-1.ts"),
        );
        const url = "https://github.com/example/upstream/pull/1";
        const identities: NodeJS.ProcessEnv[] = [];
        let models = 0;
        let pushes = 0;
        let creates = 0;
        const result = resultWithFindings(["high"]);
        const outcome = await runWorkflow(
          mode === "resume"
            ? ["patch", "--resume-pr", branch, "--json"]
            : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            environment,
            result,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onCodex: () => {
              models++;
              throw new Error("Existing publication must prevent a model turn");
            },
            onRepositoryCommand: async (command, args, cwd, options) => {
              const effectiveEnvironment = {
                ...environment,
                ...options?.environment,
              };
              if (command === "git") {
                if (args.includes("push")) {
                  pushes++;
                  throw new Error("Existing publication must prevent a push");
                }
                if (args.includes("ls-remote")) return "";
                return runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: effectiveEnvironment,
                });
              }
              expect(command).toBe("gh");
              if (args[0] === "pr" && args[1] === "list") {
                expect(args).toContain(branch);
                expect(effectiveEnvironment["GH_REPO"]).toBe(
                  environment["GH_REPO"],
                );
                expect(effectiveEnvironment["GIT_CONFIG"]).toBe(
                  environment["GIT_CONFIG"],
                );
                return JSON.stringify([
                  {
                    url,
                    head: commit,
                    state: "OPEN",
                    repositoryId: "R_source",
                    crossRepository: true,
                  },
                ]);
              }
              if (args[0] === "pr" && args[1] === "create") {
                creates++;
                throw new Error(
                  "Existing publication must prevent duplicate creation",
                );
              }
              expect(args[0]).toBe("repo");
              identities.push(effectiveEnvironment);
              if (args[1] === "set-default") {
                expect(args).toEqual(["repo", "set-default", "--view"]);
                const { stdout } = await promisify(execFile)(gh!, [...args], {
                  cwd: options?.directory ?? cwd,
                  env: effectiveEnvironment,
                  encoding: "utf8",
                });
                const selected = stdout.trim();
                if (selected)
                  expect(selected.replace(/^github\.com\//u, "")).toBe(
                    "example/source",
                  );
                return selected;
              }
              expect(args).toEqual([
                "repo",
                "view",
                "--json",
                "id,url",
                "--jq",
                "tojson",
              ]);
              expect(
                runGitRepositoryCommand(
                  "git",
                  ["config", "--get", "synthetic.inherited"],
                  cwd,
                  {
                    ...options,
                    environment: effectiveEnvironment,
                  },
                ),
              ).toBe("kept");
              return JSON.stringify({
                id: "R_source",
                url: "https://github.com/example/source",
              });
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(
          mode === "resume" ? 0 : 2,
        );
        if (mode === "resume")
          expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
        else expect(outcome.stderr).toContain("already exists");
        expect(identities).toHaveLength(2);
        for (const identity of identities) {
          expect(identity["GIT_CONFIG"]).toBeUndefined();
          expect(identity["GIT_CONFIG_GLOBAL"]).toBe(globalConfig);
          expect(identity["GIT_CONFIG_NOSYSTEM"]).toBe("1");
          expect(identity["GIT_CONFIG_PARAMETERS"]).toContain(
            environment["GIT_CONFIG_PARAMETERS"]!,
          );
          expect(identity["GH_REPO"]).toBe("");
          expect(identity["GH_TOKEN"]).toBe(environment["GH_TOKEN"]);
        }
        expect({ models, pushes, creates }).toEqual({
          models: 0,
          pushes: 0,
          creates: 0,
        });
        expect(environment).toEqual(originalEnvironment);
        expect(await readFile(config, "utf8")).toBe(
          "[synthetic]\n selector = original\n",
        );
        expect(await readFile(join(directory, ".git/config"))).toEqual(
          originalConfig,
        );
        expect(await readFile(join(directory, ".git/index"))).toEqual(
          originalIndex,
        );
        expect(git("for-each-ref", "--format=%(refname):%(objectname)")).toBe(
          originalRefs,
        );
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(await readFile(join(directory, "src/finding-1.ts"))).toEqual(
          originalSource,
        );
      },
    );
  }
}
