import { expect, test, afterAll, beforeAll } from "bun:test";
import { execFileSync, execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
  stat,
  cp,
  symlink,
  appendFile,
  chmod,
  link,
  mkdtemp,
  rm,
} from "node:fs/promises";
import { join, dirname, sep, relative, resolve } from "node:path";
import {
  runGitRepositoryCommand,
  runWorkflow,
  repositoryGit,
  publicationRepository,
  patchRiskAssessment,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
  runSavedPublication,
  gitWithEnvironment,
  runPublicationWorkflow,
  resultWithFindings,
  savedScan,
} from "./cli-patch-fixtures.js";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

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

test("publication preflight uses the native remote with an unrelated GIT_CONFIG selector", async () => {
  const { directory, git, remote } = await publicationRepository(fixtures);
  const support = await fixtures.create("patch-selector-remote-");
  const decoy = join(support, "decoy.git");
  git("init", "--bare", decoy);
  git("push", "origin", "HEAD:refs/heads/codex-security/patch-scan-1");
  const selector = join(support, "selector");
  await writeFile(
    selector,
    `[remote "origin"]\nurl = ${JSON.stringify(decoy.replaceAll("\\", "/"))}\n`,
  );
  const environment = { GIT_CONFIG: selector };
  expect(
    execFileSync("git", ["remote", "get-url", "origin"], {
      cwd: directory,
      env: { ...process.env, ...environment },
      encoding: "utf8",
    }).trim(),
  ).toBe(remote);
  let launches = 0;
  const outcome = await runSavedPublication(directory, {
    environment,

    onRepositoryCommand: (command, args, cwd, options) =>
      command === "git"
        ? runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          })
        : "[]",
    onCodex: () => {
      launches++;
      return 0;
    },
  });
  expect(outcome.exitCode).toBe(2);
  expect(outcome.stderr).toContain("already exists");
  expect(launches).toBe(0);
});

test.each([false, true])(
  "nested snapshot ignores the config-only selector (linked worktree: %p)",
  async (linked) => {
    const { directory, git } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-selector-nested-");
    const nested = join(directory, "nested");
    const origin = linked ? join(support, "origin") : nested;
    await mkdir(origin);
    const nestedGit = repositoryGit(origin);
    nestedGit("init", "--initial-branch=main");
    nestedGit("config", "user.name", "Synthetic User");
    nestedGit("config", "user.email", "synthetic@example.test");
    await writeFile(join(origin, "app.ts"), "nested source\n");
    nestedGit("add", ".");
    nestedGit("commit", "-m", "Synthetic nested baseline");
    if (linked) nestedGit("worktree", "add", "-b", "nested", nested);
    git("add", "nested");
    git("commit", "-m", "Synthetic gitlink");
    const selector = join(support, "selector");
    await writeFile(
      selector,
      `[core]\nworktree = ${JSON.stringify(support.replaceAll("\\", "/"))}\n[extensions]\nworktreeConfig = true\n`,
    );
    const environment = {
      GIT_CONFIG: selector,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.quotePath",
      GIT_CONFIG_VALUE_0: "false",
    };
    let launches = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: directory,
        environment,
        onRepositoryCommand: gitWithEnvironment(environment),
        onCodex: async (_args, output) => {
          launches++;
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          )
            output.stdout.write(patchRiskAssessment().report);
          else {
            await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
            output?.stdout.write("Synthetic patch complete.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(2);
  },
);

test.each(["unset", "missing", "unrelated", "decoy remote"] as const)(
  "publication preflight reads effective Git configuration with selector: %s",
  async (mode) => {
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
    const outcome = await runPublicationWorkflow("issue", {
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
    });
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
        const outcome = await runPublicationWorkflow("issue", {
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
        });
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

for (const included of [false, true]) {
  for (const mode of [
    "outside unchanged",
    "outside replaced",
    "inside shadow",
  ] as const) {
    test(`binds relative config origins to Git's setup directory (${mode}, included: ${included})`, async () => {
      const root = await fixtures.create("patch-config-origin-selected-");
      const support = await fixtures.create("patch-config-origin-support-");
      const outside = mode !== "inside shadow";
      const caller = outside
        ? await fixtures.create("patch-config-origin-caller-")
        : join(root, "runner");
      await mkdir(caller, { recursive: true });
      const setup = outside ? caller : root;
      const shadowDirectory = outside ? root : caller;
      const globalConfig = join(setup, "settings");
      const activeConfig = join(
        setup,
        included ? "included-settings" : "settings",
      );
      const shadowConfig = join(
        shadowDirectory,
        included ? "included-settings" : "settings",
      );
      const operatorHooks = join(support, "operator-hooks");
      const replacementHooks = join(caller, "replacement-hooks");
      const operatorEffect = join(support, "operator-effect");
      const replacementEffect = join(support, "replacement-effect");
      const scripts = [];
      for (const [directory, effect] of [
        [operatorHooks, operatorEffect],
        [replacementHooks, replacementEffect],
      ]) {
        await mkdir(directory!, { recursive: true });
        const path = join(directory!, "post-index-change");
        const shellPath = `'${effect!.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
        const contents = `#!/bin/sh\nprintf effect >> ${shellPath}\n`;
        await writeFile(path, contents, { mode: 0o755 });
        scripts.push({ path, contents });
      }
      const config = (hooks: string) =>
        `[core]\n hooksPath = ${JSON.stringify(hooks.replaceAll("\\", "/"))}\n`;
      const originalConfig = config(operatorHooks);
      if (included)
        await writeFile(globalConfig, "[include]\n path = included-settings\n");
      await writeFile(activeConfig, originalConfig);
      await writeFile(
        join(shadowDirectory, "settings"),
        "[synthetic]\n value = shadow\n",
      );
      if (included)
        await writeFile(shadowConfig, "[synthetic]\n value = shadow\n");
      await writeFile(join(root, "app.ts"), "selected source\n");
      await writeFile(join(caller, "note.txt"), "caller source\n");
      const initialize = (directory: string) => {
        const git = initializePatchGit(directory);
        git("add", ".");
        git("commit", "-m", "Synthetic config-origin baseline");
        return git;
      };
      const git = initialize(root);
      const callerGit = outside ? initialize(caller) : undefined;
      const environment = {
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "settings",
        GIT_DIR: join(root, ".git"),
        GIT_WORK_TREE: root,
      };
      const selectedGit = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: caller,
          env: { ...process.env, ...environment },
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      expect(
        selectedGit("config", "--show-origin", "--get", "core.hooksPath"),
      ).toBe(
        `file:${included ? "included-settings" : "settings"}\t${operatorHooks.replaceAll("\\", "/")}`,
      );
      for (const hooks of [operatorHooks, replacementHooks]) {
        selectedGit(
          "-c",
          `core.hooksPath=${hooks}`,
          "update-index",
          "--assume-unchanged",
          join(root, "app.ts"),
        );
        selectedGit(
          "-c",
          `core.hooksPath=${hooks}`,
          "update-index",
          "--no-assume-unchanged",
          join(root, "app.ts"),
        );
      }
      expect(await readFile(operatorEffect, "utf8")).toContain("effect");
      expect(await readFile(replacementEffect, "utf8")).toContain("effect");
      await unlink(operatorEffect);
      await unlink(replacementEffect);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const callerHead = callerGit?.("rev-parse", "HEAD");
      const callerIndex = outside
        ? await readFile(join(caller, ".git", "index"))
        : undefined;
      let launches = 0;
      let controls: readonly string[] = [];
      let modelDirectory: string | undefined;
      let operatorBefore = "";
      const bookkeeping: string[][] = [];
      const outcome = await runIssuePatch(caller, {
        environment,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (
            launches > 0 &&
            args.some((arg) =>
              ["add", "read-tree", "update-index", "write-tree"].includes(arg),
            )
          )
            bookkeeping.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
        onCodex: async (_args, output) => {
          launches++;
          controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
          modelDirectory = output?.appServer?.directory;
          operatorBefore = await readFile(operatorEffect, "utf8").catch(
            () => "",
          );
          if (mode !== "outside unchanged") {
            const target =
              mode === "outside replaced" ? activeConfig : shadowConfig;
            await writeFile(`${target}.replacement`, config(replacementHooks));
            await rename(`${target}.replacement`, target);
          }
          if (!outside)
            await writeFile(
              join(caller, "note.txt"),
              "updated caller source\n",
            );
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(launches).toBe(1);
      expect(modelDirectory).toBe(caller);
      expect(controls).toContain(globalConfig);
      expect(controls).toContain(activeConfig);
      expect(controls).not.toContain(shadowConfig);
      const operatorAfter = await readFile(operatorEffect, "utf8").catch(
        () => "",
      );
      if (mode === "outside replaced") {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(outcome.stderr.replaceAll("\\", "/")).toContain(
          activeConfig.replaceAll("\\", "/"),
        );
        expect(bookkeeping).toEqual([]);
        expect(operatorAfter).toBe(operatorBefore);
        expect(await readFile(activeConfig, "utf8")).toBe(
          config(replacementHooks),
        );
      } else {
        if (outside) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "No patch was applied; 0 files changed",
          );
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files.sort()).toEqual(
            [
              relative(root, shadowConfig).replaceAll("\\", "/"),
              "runner/note.txt",
            ].sort(),
          );
        }
        expect(bookkeeping.length).toBeGreaterThan(0);
        expect(operatorAfter.length).toBeGreaterThan(operatorBefore.length);
        expect(await readFile(activeConfig, "utf8")).toBe(originalConfig);
      }
      expect(await readFile(replacementEffect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe(
        "selected source\n",
      );
      for (const { path, contents } of scripts)
        expect(await readFile(path, "utf8")).toBe(contents);
      if (outside) {
        expect(callerGit!("rev-parse", "HEAD")).toBe(callerHead!);
        expect(callerIndex!).toEqual(
          await readFile(join(caller, ".git", "index")),
        );
        expect(await readFile(join(caller, "note.txt"), "utf8")).toBe(
          "caller source\n",
        );
      }
    });
  }
}

for (const [selector, action] of [
  ["relative", "source"],
  ["absolute", "source"],
  ["common", "source"],
  ["alias", "source"],
  ["relative", "metadata"],
  ["alias", "retarget"],
] as const) {
  test(`protects outside-caller ${selector} Git selectors during ${action} replacement`, async () => {
    const root = await fixtures.create("patch-selector-worktree-");
    const caller = await fixtures.create("patch-selector-caller-");
    const metadata = join(caller, selector === "alias" ? "metadata" : "admin");
    const alias = join(caller, "admin");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main", "--separate-git-dir", metadata);
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(root, "admin"), "ordinary source\n");
    git("add", ".");
    git("commit", "-m", "Synthetic selector baseline");
    if (selector === "alias")
      await symlink(
        metadata,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    const emptyConfig = join(caller, "empty-config");
    await writeFile(emptyConfig, "");
    const environment = {
      GIT_DIR:
        selector === "absolute" || selector === "common" ? metadata : "admin",
      GIT_WORK_TREE: root,
      ...(selector === "common" ? { GIT_COMMON_DIR: "admin" } : {}),
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_CONFIG_SYSTEM: emptyConfig,
    };
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(metadata, "index"));
    const config = await readFile(join(metadata, "config"));
    const replacement = join(caller, "replacement");
    if (action !== "source")
      await cp(metadata, replacement, { recursive: true });
    let launches = 0;
    let controls: readonly string[] = [];
    const outcome = await runIssuePatch(caller, {
      environment,
      onRepositoryCommand: gitWithEnvironment(environment),
      onCodex: async (_args, output, childEnvironment) => {
        launches++;
        controls = output!.appServer!.permissions!.readOnlyPaths;
        expect(output!.appServer!.directory).toBe(caller);
        expect(childEnvironment?.["GIT_DIR"]).toBe(environment.GIT_DIR);
        expect(childEnvironment?.["GIT_WORK_TREE"]).toBe(root);
        await writeFile(join(root, "admin.new"), "updated source\n");
        await rename(join(root, "admin.new"), join(root, "admin"));
        if (action === "metadata") {
          await rename(metadata, join(caller, "original-metadata"));
          await rename(replacement, metadata);
        } else if (action === "retarget") {
          await unlink(alias);
          await symlink(
            replacement,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
        }
        output!.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches).toBe(1);
    expect(controls).toContain(metadata);
    expect(controls).toContain(join(metadata, "config"));
    expect(await readFile(join(root, "admin"), "utf8")).toBe(
      "updated source\n",
    );
    expect(await readFile(join(metadata, "index"))).toEqual(index);
    expect(await readFile(join(metadata, "config"))).toEqual(config);
    expect(git("rev-parse", "HEAD")).toBe(head);
    if (action === "source") {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(controls).not.toContain(join(root, "admin"));
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["admin"],
      });
    } else {
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        action === "metadata"
          ? "Selected Git administration changed during the patch"
          : "Git configuration or hooks changed location during the patch",
      );
    }
  });
}

const configurations = [
  "local",
  "include",
  "empty include",
  "empty worktree",
  "empty global",
  "relative global",
  "newline global",
  "empty system",
  "empty home",
  "empty xdg",
  "explicit xdg",
  "disabled global",
  "disabled system",
  "disabled worktree",
] as const;

for (const configuration of configurations) {
  for (const changed of [false, true]) {
    test.skipIf(
      process.platform === "win32" && configuration === "newline global",
    )(
      `patch binds ${configuration} configuration contents, changed: ${changed}`,
      async () => {
        const root = await fixtures.create("patch-config-contents-");
        const home = await fixtures.create("patch-config-home-");
        const remote = await fixtures.create("patch-config-remote-");
        const environment: NodeJS.ProcessEnv = {
          ...process.env,
          HOME: home,
          USERPROFILE: home,
          XDG_CONFIG_HOME: undefined,
          GIT_CONFIG_GLOBAL: "",
          GIT_CONFIG_SYSTEM: "",
          GIT_CONFIG_NOSYSTEM: "1",
        };
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
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        let control = join(root, ".git", "config");
        if (configuration.includes("include")) {
          control = join(root, ".git", "included-config");
          git("config", "include.path", "included-config");
        } else if (configuration.includes("worktree")) {
          control = join(root, ".git", "config.worktree");
          if (configuration !== "disabled worktree")
            git("config", "extensions.worktreeConfig", "true");
        } else if (configuration.includes("global")) {
          control =
            configuration === "relative global"
              ? join(root, ".git", "selected-global")
              : join(
                  home,
                  configuration === "newline global"
                    ? "selected\nconfig"
                    : ".gitconfig",
                );
          if (configuration !== "disabled global")
            environment["GIT_CONFIG_GLOBAL"] =
              configuration === "relative global"
                ? ".git/selected-global"
                : control;
        } else if (configuration.includes("system")) {
          control = join(home, "selected-system-config");
          environment["GIT_CONFIG_SYSTEM"] = control;
          if (configuration !== "disabled system")
            environment["GIT_CONFIG_NOSYSTEM"] = "0";
        } else if (configuration === "empty home") {
          control = join(home, ".gitconfig");
          environment["GIT_CONFIG_GLOBAL"] = undefined;
        } else if (configuration.includes("xdg")) {
          environment["GIT_CONFIG_GLOBAL"] = undefined;
          const xdg =
            configuration === "explicit xdg"
              ? join(home, "xdg")
              : join(home, ".config");
          if (configuration === "explicit xdg")
            environment["XDG_CONFIG_HOME"] = xdg;
          control = join(xdg, "git", "config");
        }
        if (configuration !== "local") {
          await mkdir(dirname(control), { recursive: true });
          await writeFile(
            control,
            configuration === "include"
              ? "[synthetic]\n value = original\n"
              : "",
          );
        }
        const original = await readFile(control);
        const alias = join(root, "config-alias.txt");
        await link(control, alias);
        await writeFile(join(root, "app.ts"), "before\n");
        git("add", ".");
        git("commit", "-m", "Synthetic configuration baseline");
        const head = git("rev-parse", "HEAD");
        const index = await readFile(join(root, ".git", "index"));
        const effect = join(root, ".git", "configuration-hook-effect");
        const hooks = join(root, "synthetic-hooks");
        const postModelGit: string[][] = [];
        let modelFinished = false;
        let creations = 0;
        const active = !configuration.startsWith("disabled");
        const outcome = await runPublicationWorkflow("issue", {
          currentDirectory: root,
          environment,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command !== "git") {
              if (args[1] === "list") return "[]";
              if (args[1] === "create") creations++;
              return "https://github.example.test/example/repository/pull/1";
            }
            if (modelFinished) postModelGit.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
          onCodex: async (_args, output) => {
            expect((await stat(alias)).ino).toBe((await stat(control)).ino);
            if (active)
              expect(output?.appServer?.permissions?.readOnlyPaths).toContain(
                control,
              );
            await writeFile(join(root, "app.ts"), "after\n");
            if (changed) {
              await mkdir(hooks);
              const shellEffect = `'${effect.split(sep).join("/").replaceAll("'", "'\\''")}'`;
              await writeFile(
                join(hooks, "post-checkout"),
                `#!/bin/sh\nprintf effect > ${shellEffect}\n`,
                { mode: 0o755 },
              );
              await appendFile(
                alias,
                `\n[core]\n hooksPath = ${JSON.stringify(hooks.split(sep).join("/"))}\n`,
              );
            }
            modelFinished = true;
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        });
        if (changed && active) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "Git configuration changed during the patch",
          );
          expect(postModelGit).toEqual([]);
          expect(creations).toBe(0);
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(await readFile(join(root, ".git", "index"))).toEqual(index);
          expect(await readFile(control)).not.toEqual(original);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(creations).toBe(1);
          if (!changed) expect(await readFile(alias)).toEqual(original);
        }
        expect(await readFile(effect).catch(() => null)).toBeNull();
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
      },
    );
  }
}

let unreadableBundle: string | undefined;
let unreadableFixture: string;
beforeAll(async () => {
  if (process.platform === "win32") return;
  // Use the supported Node filesystem semantics; Bun's macOS realpath opens
  // the target for reading and cannot resolve these mode-000 inputs.
  unreadableBundle = await mkdtemp(
    join(import.meta.dirname, "..", ".patch-config-node-"),
  );
  const built = await Bun.build({
    entrypoints: [
      join(
        import.meta.dirname,
        "fixtures",
        "patch-unreadable-configuration-node.ts",
      ),
    ],
    outdir: unreadableBundle,
    target: "node",
    packages: "external",
  });
  expect(built.success).toBe(true);
  unreadableFixture = built.outputs[0]!.path;
});
afterAll(async () => {
  if (unreadableBundle)
    await rm(unreadableBundle, { recursive: true, force: true });
});

for (const configuration of [
  "global",
  "global activation",
  "inactive include",
  "disabled worktree",
]) {
  test.skipIf(process.platform === "win32")(
    `patch preserves unreadable optional ${configuration} configuration`,
    async () => {
      const root = await fixtures.create("patch-unreadable-config-");
      const home = await fixtures.create("patch-unreadable-config-home-");
      const environment: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        GIT_CONFIG_GLOBAL: "",
        GIT_CONFIG_SYSTEM: "",
        GIT_CONFIG_NOSYSTEM: "1",
      };
      const git = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: root,
          env: environment,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(root, "app.ts"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic optional configuration baseline");
      const control = configuration.startsWith("global")
        ? join(home, ".gitconfig")
        : join(
            root,
            ".git",
            configuration === "disabled worktree"
              ? "config.worktree"
              : "included-config",
          );
      if (configuration.startsWith("global"))
        environment["GIT_CONFIG_GLOBAL"] = control;
      if (configuration === "inactive include")
        git(
          "config",
          "includeIf.onbranch:other-branch.path",
          "included-config",
        );
      await writeFile(control, "");
      const activate = configuration === "global activation";
      const alias = join(root, "config-alias.txt");
      if (activate) {
        await link(control, alias);
        await writeFile(join(root, ".gitignore"), "config-alias.txt\n");
        git("add", ".gitignore");
        git("commit", "-m", "Synthetic ignored configuration alias");
      }
      await chmod(control, 0o000);
      try {
        await expect(readFile(control)).rejects.toMatchObject({
          code: "EACCES",
        });
        expect(() => git("config", "--includes", "--list")).not.toThrow();
        const outcome = JSON.parse(
          execFileSync(
            "node",
            [
              "--input-type=module",
              "--eval",
              `await import(${JSON.stringify(pathToFileURL(unreadableFixture).href)})`,
            ],
            {
              input: JSON.stringify({
                root,
                control,
                alias,
                activate,
                environment,
              }),
              encoding: "utf8",
            },
          ),
        ) as Awaited<ReturnType<typeof runWorkflow>> & {
          launches: number;
          postModelGit: string[][];
        };
        expect(outcome.launches).toBe(1);
        if (activate) {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "Git configuration became readable during the patch",
          );
          expect(outcome.postModelGit).toEqual([]);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
          await expect(readFile(control)).rejects.toMatchObject({
            code: "EACCES",
          });
        }
      } finally {
        await chmod(control, 0o600);
      }
    },
  );
}

function configuredPublicationCommand(
  environment: NodeJS.ProcessEnv,
  observe?: (...args: Parameters<typeof runGitRepositoryCommand>) => void,
): typeof runGitRepositoryCommand {
  return (command, args, cwd, options) => {
    const selected = {
      ...options,
      environment: { ...environment, ...options?.environment },
    };
    observe?.(command, args, cwd, selected);
    if (command === "git")
      return runGitRepositoryCommand(command, args, cwd, selected);
    return args[1] === "create"
      ? "https://example.test/repository/pull/1"
      : "[]";
  };
}

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
      const outcome = await runPublicationWorkflow("issue", {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: configuredPublicationCommand(environment),
        onCodex: async (_args, output) => {
          const controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
          expect(controls).toContain(active);
          expect(controls).not.toContain(join(shadow, "settings"));
          trustedBefore = await readFile(trustedEffect, "utf8").catch(() => "");
          await writeFile(join(shadow, "settings"), configuration(otherHooks));
          await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
          output?.stdout.write("Synthetic patch complete.");
          return 0;
        },
      });
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
  const outcome = await runPublicationWorkflow("issue", {
    currentDirectory: directory,
    environment,
    onRepositoryCommand: configuredPublicationCommand(
      environment,
      (command, _args, _cwd, options) => {
        if (command === "git") {
          expect(options?.environment?.["GIT_CONFIG_GLOBAL"]).toBe("");
          expect(options?.environment?.["GIT_CONFIG_SYSTEM"]).toBe("");
        }
      },
    ),
    onCodex: async (_args, output) => {
      await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
      output?.stdout.write("Synthetic patch complete.");
      return 0;
    },
  });
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
    const outcome = await runPublicationWorkflow("issue", {
      currentDirectory: caller,
      environment,
      onRepositoryCommand: configuredPublicationCommand(environment),
      onCodex: async (_args, output) => {
        await rm(caller, { recursive: true });
        await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
        output?.stdout.write("Synthetic patch complete.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(git("cat-file", "-p", "HEAD")).not.toContain("encoding ISO-8859-1");
  },
);

test("publication keeps GIT_CONFIG bound to a removed component", async () => {
  const { directory } = await publicationRepository(fixtures);
  const caller = join(directory, "src");
  const selector = "selector-settings";
  const environment = { GIT_CONFIG: selector };
  const selections: string[] = [];
  const outcome = await runPublicationWorkflow("issue", {
    currentDirectory: caller,
    environment,
    onRepositoryCommand: configuredPublicationCommand(
      environment,
      (command, args, cwd, options) => {
        if (command === "gh" && args[1] === "create") {
          const path = options?.environment?.["GIT_CONFIG"];
          selections.push(resolve(options?.directory ?? cwd, path!));
        }
      },
    ),
    onCodex: async (_args, output) => {
      await rm(caller, { recursive: true });
      await writeFile(
        join(directory, selector),
        '[remote "origin"]\n gh-resolved = decoy/repository\n',
      );
      output?.stdout.write("Synthetic patch complete.");
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(selections).toEqual([join(caller, selector)]);
});

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
      onRepositoryCommand: configuredPublicationCommand(
        environment,
        (_command, args, cwd, options) => {
          if (patched) {
            const operation = operations.find((name) => args.includes(name));
            if (operation)
              calls.push({
                operation,
                roots: [cwd, ...(options?.protectedRoots ?? [])],
              });
          }
        },
      ),
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
