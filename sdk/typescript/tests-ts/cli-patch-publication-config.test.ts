import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
