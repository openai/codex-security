import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  appendFile,
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runGitRepositoryCommand, runWorkflow } from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
          },
        );
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
