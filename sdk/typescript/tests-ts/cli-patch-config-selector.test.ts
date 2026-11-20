import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
  stat,
} from "node:fs/promises";
import { join, dirname, sep } from "node:path";
import {
  runGitRepositoryCommand,
  runWorkflow,
  repositoryGit,
  patchDirectories,
  runIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

test.each([
  "missing selector",
  "existing selector",
  "replace effective config",
] as const)(
  "patch inventories effective configuration with GIT_CONFIG: %s",
  async (mode) => {
    const root = await fixtures.create("patch-config-selector-");
    const support = await fixtures.create("patch-config-selector-support-");
    const globalConfig = join(support, "empty-global");
    await writeFile(globalConfig, "");
    const baseEnvironment = {
      GIT_CONFIG_GLOBAL: globalConfig,
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: root,
        env: { ...process.env, ...baseEnvironment },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const source = join(root, "app.ts");
    const selector = join(root, "selector-settings");
    const effectiveConfig = join(root, "effective-settings");
    const hooks = join(root, "operator-hooks");
    const hook = join(hooks, "post-index-change");
    const effect = join(support, "effect");
    await mkdir(hooks);
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const script = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
    await writeFile(hook, script, { mode: 0o755 });
    const configuration = `[core]\n hooksPath = ${JSON.stringify(hooks.replaceAll("\\", "/"))}\n`;
    await writeFile(effectiveConfig, configuration);
    await writeFile(source, "before\n");
    const selectorText = "[synthetic]\n value = ordinary selector data\n";
    if (mode !== "missing selector") await writeFile(selector, selectorText);
    git("add", ".");
    git("commit", "-m", "Synthetic selector baseline");
    git("config", "include.path", "../effective-settings");
    git("update-index", "--assume-unchanged", "app.ts");
    git("update-index", "--no-assume-unchanged", "app.ts");
    expect(await readFile(effect, "utf8")).toContain("effect");
    await unlink(effect);
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const localConfig = await readFile(join(root, ".git", "config"));
    const environment = {
      ...baseEnvironment,
      GIT_CONFIG: selector,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.quotePath",
      GIT_CONFIG_VALUE_0: "false",
    };
    const calls: {
      args: string[];
      environment: NodeJS.ProcessEnv;
      afterTurn: boolean;
    }[] = [];
    let launches = 0;
    let controls: readonly string[] = [];
    let effectsBefore = "";
    const outcome = await runIssuePatch(root, {
      environment,
      onRepositoryCommand: (command, args, cwd, options) => {
        const effectiveEnvironment = {
          ...environment,
          ...options?.environment,
        };
        calls.push({
          args: [...args],
          environment: effectiveEnvironment,
          afterTurn: launches > 0,
        });
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: effectiveEnvironment,
        });
      },
      onCodex: async (_args, output, childEnvironment) => {
        launches++;
        controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
        expect(childEnvironment?.["GIT_CONFIG"]).toBe(selector);
        expect(childEnvironment?.["GIT_CONFIG_COUNT"]).toBe("1");
        expect(childEnvironment?.["GIT_CONFIG_KEY_0"]).toBe("core.quotePath");
        expect(childEnvironment?.["GIT_CONFIG_VALUE_0"]).toBe("false");
        effectsBefore = await readFile(effect, "utf8").catch(() => "");
        await writeFile(source, "after\n");
        if (mode === "existing selector") {
          await writeFile(
            `${selector}.replacement`,
            "[synthetic]\n value = edited ordinary data\n",
          );
          await rename(`${selector}.replacement`, selector);
        } else if (mode === "replace effective config") {
          await writeFile(
            `${effectiveConfig}.replacement`,
            `${configuration}[synthetic]\n value = changed configuration\n`,
          );
          await rename(`${effectiveConfig}.replacement`, effectiveConfig);
        }
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches, outcome.stderr).toBe(1);
    expect(controls).toContain(join(root, ".git"));
    expect(controls).toContain(effectiveConfig);
    expect(controls).toContain(hook);
    expect(controls).not.toContain(selector);
    const inventory = calls.filter(
      ({ args }) => args.includes("config") && !args.includes("--git-path"),
    );
    const origins = inventory.filter(
      ({ args }) => args.includes("--list") && !args.includes("--file"),
    );
    expect(origins.length).toBeGreaterThan(0);
    for (const { args } of origins) {
      expect(args).toContain("--includes");
      expect(args).toContain("--show-origin");
      expect(args).toContain("--show-scope");
    }
    const lfsLookups = inventory.filter(
      ({ args }) => args.at(-1) === "lfs.storage",
    );
    expect(lfsLookups.length).toBeGreaterThan(0);
    for (const { args } of lfsLookups) expect(args).toContain("--includes");
    for (const call of calls) {
      expect(call.environment["GIT_CONFIG"]).toBe(
        inventory.includes(call) && call.args.at(-1) !== "lfs.storage"
          ? undefined
          : selector,
      );
      expect(call.environment["GIT_CONFIG_GLOBAL"]).toBe(globalConfig);
      expect(call.environment["GIT_CONFIG_NOSYSTEM"]).toBe("1");
      expect(call.environment["GIT_CONFIG_COUNT"]).toBe("2");
      expect(call.environment["GIT_CONFIG_KEY_1"]).toBe("core.fsmonitor");
      expect(call.environment["GIT_CONFIG_VALUE_1"]).toBe("false");
      expect(call.environment["GIT_CONFIG_KEY_0"]).toBe("core.quotePath");
      expect(call.environment["GIT_CONFIG_VALUE_0"]).toBe("false");
    }
    const effectsAfter = await readFile(effect, "utf8").catch(() => "");
    if (mode === "replace effective config") {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Git configuration or hooks changed location during the patch",
      );
      expect(calls.filter(({ afterTurn }) => afterTurn)).toEqual([]);
      expect(effectsAfter).toBe(effectsBefore);
      expect(await readFile(effectiveConfig, "utf8")).toContain(
        "changed configuration",
      );
      expect(await readFile(selector, "utf8")).toBe(selectorText);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual([
        "app.ts",
        ...(mode === "existing selector" ? ["selector-settings"] : []),
      ]);
      expect(effectsAfter.length).toBeGreaterThan(effectsBefore.length);
      expect(await readFile(effectiveConfig, "utf8")).toBe(configuration);
      if (mode === "missing selector")
        await expect(readFile(selector)).rejects.toHaveProperty(
          "code",
          "ENOENT",
        );
      else
        expect(await readFile(selector, "utf8")).toBe(
          "[synthetic]\n value = edited ordinary data\n",
        );
    }
    expect(environment.GIT_CONFIG).toBe(selector);
    expect(await readFile(source, "utf8")).toBe("after\n");
    expect(await readFile(hook, "utf8")).toBe(script);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(localConfig);
  },
);

test.each(["unset", "missing", "unrelated", "decoy remote"] as const)(
  "publication preflight reads effective Git configuration with selector: %s",
  async (mode) => {
    const { publicationRepository } = await import("./cli-patch-fixtures.js");
    const { directory, git } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-publication-selector-");
    const selector = join(support, "selected-config");
    if (mode === "unrelated")
      await writeFile(selector, "[synthetic]\n value = fixture\n");
    if (mode === "decoy remote") {
      const decoy = join(support, "decoy.git");
      git("init", "--bare", decoy);
      git("push", decoy, "HEAD:refs/heads/codex-security/patch-scan-1");
      await writeFile(
        selector,
        `[remote "origin"]\nurl = ${JSON.stringify(decoy.replaceAll("\\", "/"))}\n`,
      );
    }
    const environment = { GIT_CONFIG: mode === "unset" ? undefined : selector };
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    let launches = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              })
            : "[]",
        onCodex: (_args, output, childEnvironment) => {
          launches++;
          expect(childEnvironment?.["GIT_CONFIG"]).toBe(environment.GIT_CONFIG);
          output?.stdout.write("Synthetic no-op turn.\n");
          return 0;
        },
      },
    );
    expect(launches, outcome.stderr).toBe(1);
    expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(2);
    expect(JSON.parse(outcome.stdout).error.code).toBe("NO_PATCH_APPLIED");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
    expect(environment.GIT_CONFIG).toBe(
      mode === "unset" ? undefined : selector,
    );
  },
);

for (const selected of [
  "global",
  "relative global",
  "administration global",
  "home",
  "xdg",
  "system",
  "disabled global",
  "disabled system",
  "empty global",
  "device",
  "lfs root",
  "lfs objects",
]) {
  const states: Array<boolean | "directory"> =
    selected.startsWith("disabled") || selected === "empty global"
      ? [true]
      : selected === "device" || selected.startsWith("lfs ")
        ? [false]
        : [false, true];
  if (selected === "global" || selected === "administration global")
    states.push("directory");
  for (const create of states) {
    test.skipIf(process.platform === "win32" && selected === "device")(
      `patch binds selected ${selected} configuration absence, created: ${create}`,
      async () => {
        const root = await fixtures.create("patch-missing-config-");
        const remote = await fixtures.create("patch-missing-config-remote-");
        const home = join(root, "synthetic-config", "home");
        await mkdir(home, { recursive: true });
        const environment: NodeJS.ProcessEnv = {
          ...process.env,
          HOME: home,
          USERPROFILE: home,
          XDG_CONFIG_HOME: undefined,
          GIT_CONFIG_GLOBAL: "",
          GIT_CONFIG_SYSTEM: "",
          GIT_CONFIG_NOSYSTEM: "1",
        };
        let control = join(root, "synthetic-config", "selected-config");
        if (selected.startsWith("lfs ")) {
          control = join(
            root,
            "synthetic-config",
            "lfs",
            ...(selected === "lfs objects" ? ["objects"] : []),
          );
          environment["GIT_CONFIG_GLOBAL"] = control;
        } else if (selected === "administration global") {
          control = join(root, ".git", "selected-config");
          environment["GIT_CONFIG_GLOBAL"] = control;
        } else if (selected === "home") {
          environment["GIT_CONFIG_GLOBAL"] = undefined;
          control = join(home, ".gitconfig");
        } else if (selected === "xdg") {
          environment["GIT_CONFIG_GLOBAL"] = undefined;
          environment["XDG_CONFIG_HOME"] = join(
            root,
            "synthetic-config",
            "xdg",
          );
          control = join(environment["XDG_CONFIG_HOME"], "git", "config");
        } else if (selected.includes("system")) {
          environment["GIT_CONFIG_SYSTEM"] = control;
          if (selected === "system") environment["GIT_CONFIG_NOSYSTEM"] = "0";
        } else if (selected === "device") {
          environment["GIT_CONFIG_GLOBAL"] = "/dev/null";
        } else if (selected !== "disabled global") {
          environment["GIT_CONFIG_GLOBAL"] =
            selected === "relative global"
              ? "synthetic-config/selected-config"
              : control;
        }
        if (selected === "empty global") await writeFile(control, "");
        const git = (...args: string[]) =>
          execFileSync("git", args, {
            cwd: root,
            env: environment,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
          }).trim();
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        if (selected.startsWith("lfs "))
          git("config", "lfs.storage", join(root, "synthetic-config", "lfs"));
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        await writeFile(
          join(root, ".gitignore"),
          "synthetic-config/\nsynthetic-hooks/\n",
        );
        await writeFile(join(root, "app.ts"), "before\n");
        git("add", ".");
        git("commit", "-m", "Synthetic missing configuration baseline");
        const head = git("rev-parse", "HEAD");
        const index = await readFile(join(root, ".git", "index"));
        const hooks = join(root, "synthetic-hooks");
        const effect = join(root, ".git", "configuration-hook-effect");
        let modelFinished = false;
        let pushes = 0;
        let creations = 0;
        const postModelGit: string[][] = [];
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--create-pr", "--json"],
          {
            currentDirectory: root,
            environment,
            onRepositoryCommand: (command, args, cwd, options) => {
              if (command !== "git") {
                if (args[1] === "list") return "[]";
                if (args[1] === "create") creations++;
                return "https://github.example.test/example/repository/pull/1";
              }
              if (args[0] === "push") pushes++;
              if (modelFinished) postModelGit.push([...args]);
              return runGitRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
            },
            onCodex: async (_args, output) => {
              if (selected.startsWith("lfs "))
                expect((await stat(control)).isDirectory()).toBe(true);
              await writeFile(join(root, "app.ts"), "after\n");
              if (create === "directory") {
                await mkdir(control, { recursive: true });
              } else if (create) {
                await mkdir(hooks);
                await writeFile(
                  join(hooks, "post-checkout"),
                  `#!/bin/sh\nprintf effect > '${effect.split(sep).join("/").replaceAll("'", "'\\''")}'\n`,
                  { mode: 0o755 },
                );
                await mkdir(dirname(control), { recursive: true });
                await writeFile(
                  control,
                  `[core]\n hooksPath = ${JSON.stringify(hooks.split(sep).join("/"))}\n`,
                );
              }
              modelFinished = true;
              output?.stdout.write("Synthetic patch complete.\n");
              return 0;
            },
          },
        );
        let directoryError: string | undefined;
        if (create === "directory" || selected.startsWith("lfs ")) {
          expect((await stat(control)).isDirectory()).toBe(true);
          try {
            // Probe native config loading without changing the index or worktree.
            git("rev-parse", "--verify", "--quiet", "HEAD");
          } catch (error) {
            const failure = error as {
              status: number;
              stderr: Buffer | string;
            };
            expect(failure.status).toBe(128);
            directoryError = failure.stderr.toString();
            expect(directoryError).toContain(control);
          }
        }
        const activated = create === true && !selected.startsWith("disabled");
        const rejected = activated || directoryError !== undefined;
        expect(
          {
            exit: outcome.exitCode,
            pushes,
            creations,
            hook: await readFile(effect, "utf8").catch(() => null),
          },
          outcome.stderr,
        ).toEqual({
          exit: rejected ? 2 : 0,
          pushes: rejected ? 0 : 1,
          creations: rejected ? 0 : 1,
          hook: null,
        });
        if (activated) {
          expect(outcome.stderr).toMatch(
            /Git configuration (?:or hooks changed location|changed) during the patch/,
          );
          expect(postModelGit).toEqual([]);
        }
        if (directoryError !== undefined)
          for (const line of directoryError.trim().split(/\r?\n/u))
            expect(outcome.stderr).toContain(line);
        if (rejected) {
          // Inspect preserved state without selecting the rejected directory.
          expect(repositoryGit(root)("rev-parse", "HEAD")).toBe(head);
          expect(await readFile(join(root, ".git", "index"))).toEqual(index);
          expect(repositoryGit(remote)("for-each-ref")).toBe("");
        }
        const preparationRejected =
          directoryError !== undefined && selected.startsWith("lfs ");
        expect(modelFinished).toBe(!preparationRejected);
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe(
          preparationRejected ? "before\n" : "after\n",
        );
      },
    );
  }
}
