import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
