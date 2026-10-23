import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  "home",
  "xdg",
  "explicit",
  "empty explicit",
  ...(process.platform === "win32"
    ? ["appdata", "mixed case"]
    : ["lowercase decoy"]),
])("preserves gh configuration after caller removal: %s", async (kind) => {
  const { directory, git } = await publicationRepository(fixtures);
  const caller = join(directory, "component");
  await mkdir(caller);
  await writeFile(join(caller, "app.ts"), "before\n");
  git("add", ".");
  git("commit", "-m", "Synthetic caller baseline");
  const support = await fixtures.create("patch-gh-configuration-");
  const home = join(support, "home");
  const config =
    kind === "home" || kind === "lowercase decoy"
      ? join(home, ".config", "gh")
      : kind === "appdata"
        ? join(support, "GitHub CLI")
        : kind === "explicit"
          ? join(support, "explicit")
          : join(support, "gh");
  await mkdir(config, { recursive: true });
  await writeFile(join(config, "config.yml"), "prompt: disabled\n");
  const environment: NodeJS.ProcessEnv = {
    GH_CONFIG_DIR: kind === "empty explicit" ? "" : undefined,
    GLAB_CONFIG_DIR: undefined,
    XDG_CONFIG_HOME: undefined,
    AppData: undefined,
    HOME: relative(caller, home),
    USERPROFILE: relative(caller, home),
    GIT_CONFIG_GLOBAL: join(support, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
  };
  if (kind === "appdata") environment["AppData"] = relative(caller, support);
  else if (kind === "lowercase decoy") {
    environment["gh_config_dir"] = join(support, "decoy");
  } else if (kind !== "home") {
    environment["XDG_CONFIG_HOME"] = relative(caller, support);
    if (kind === "explicit")
      environment["GH_CONFIG_DIR"] = relative(caller, config);
    if (kind === "mixed case") {
      delete environment["XDG_CONFIG_HOME"];
      environment["xdg_config_home"] = relative(caller, support);
    }
  }
  let removed = false;
  let readsAfterRemoval = 0;
  const outcome = await runWorkflow(
    ["patch", "Synthetic issue", "--create-pr", "--json"],
    {
      currentDirectory: caller,
      environment,
      onRepositoryCommand: async (command, args, cwd, options) => {
        if (command === "git")
          return runGitRepositoryCommand(command, args, cwd, options);
        if (removed) {
          readsAfterRemoval++;
          expect(options?.environment?.["GH_CONFIG_DIR"]).toBe(config);
          expect(
            await readFile(
              join(options!.environment!["GH_CONFIG_DIR"]!, "config.yml"),
              "utf8",
            ),
          ).toBe("prompt: disabled\n");
        }
        return args[1] === "create"
          ? "https://github.example.test/example/repository/pull/1"
          : "[]";
      },
      onCodex: async (_args, output) => {
        await rm(caller, { recursive: true });
        removed = true;
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(readsAfterRemoval).toBeGreaterThan(0);
});

test.each([
  { resolver: "legacy", kind: "home" },
  { resolver: "legacy", kind: "xdg" },
  { resolver: "legacy", kind: "empty explicit" },
  { resolver: "legacy", kind: "explicit" },
  { resolver: "xdg", kind: "home" },
  { resolver: "xdg", kind: "legacy precedence" },
  { resolver: "xdg", kind: "ignored relative xdg" },
  { resolver: "xdg", kind: "empty explicit" },
  { resolver: "xdg", kind: "explicit" },
  ...(process.platform === "win32"
    ? ["expanded profile", "drive-relative xdg"]
    : ["expanded tilde", "expanded home"]
  ).map((kind) => ({ resolver: "xdg", kind })),
])(
  "preserves glab configuration after caller removal: $resolver, $kind",
  async ({ resolver, kind }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const caller = join(directory, "component");
    await mkdir(caller);
    await writeFile(join(caller, "app.ts"), "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic caller baseline");
    git(
      "remote",
      "set-url",
      "origin",
      "https://gitlab.com/example/repository.git",
    );
    const support = await fixtures.create("patch-glab-configuration-");
    const home = join(support, "home");
    const expanded = kind.startsWith("expanded");
    const independent =
      expanded ||
      kind === "ignored relative xdg" ||
      kind === "drive-relative xdg";
    const xdg = join(expanded ? home : support, "xdg");
    const system = join(support, "system");
    const explicit = join(support, "explicit");
    const configuration =
      kind === "explicit"
        ? explicit
        : expanded ||
            kind === "xdg" ||
            (kind === "empty explicit" && resolver === "legacy")
          ? join(xdg, "glab-cli")
          : kind === "ignored relative xdg" || kind === "drive-relative xdg"
            ? join(system, "glab-cli")
            : join(home, ".config", "glab-cli");
    for (const path of [configuration, join(xdg, "glab-cli"), explicit]) {
      await mkdir(path, { recursive: true });
      await writeFile(
        join(path, "config.yml"),
        path === configuration
          ? "synthetic-selected-host\n"
          : "synthetic-other-host\n",
      );
    }
    const environment: NodeJS.ProcessEnv = {
      GLAB_CONFIG_DIR:
        kind === "explicit"
          ? relative(caller, explicit)
          : kind === "empty explicit"
            ? ""
            : undefined,
      HOME: independent ? home : relative(caller, home),
      USERPROFILE: independent ? home : relative(caller, home),
      XDG_CONFIG_HOME:
        kind === "expanded tilde"
          ? "~/xdg"
          : kind === "expanded home"
            ? "$HOME/xdg"
            : kind === "expanded profile"
              ? "%USERPROFILE%/xdg"
              : kind === "drive-relative xdg"
                ? `${directory[0]?.toUpperCase() === "D" ? "E" : "D"}:xdg`
                : kind === "home"
                  ? undefined
                  : relative(caller, xdg),
      XDG_CONFIG_DIRS: system,
      GIT_CONFIG_GLOBAL: join(support, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const inherited = { ...environment };
    const hosting = join(support, "glab.cjs");
    const calls = join(support, "calls.jsonl");
    // Exercise both glab's older XDG/HOME fallback and its newer legacy-first
    // resolver, which ignores relative XDG_CONFIG_HOME values.
    await writeFile(
      hosting,
      `
      const fs = require("node:fs");
      const path = require("node:path");
      const env = process.env;
      const home = ${JSON.stringify(resolver)} === "legacy" ? env.HOME : process.platform === "win32" ? env.USERPROFILE : env.HOME;
      const legacy = path.join(home, ".config", "glab-cli");
      const exists = (directory) => fs.existsSync(path.join(directory, "config.yml"));
      let xdg = env.XDG_CONFIG_HOME;
      if (process.platform === "win32") {
        if (xdg?.startsWith("%USERPROFILE%")) xdg = path.join(home, xdg.slice(13));
      } else {
        if (xdg?.startsWith("~")) xdg = path.join(home, xdg.slice(1));
        else if (xdg?.startsWith("$HOME")) xdg = path.join(home, xdg.slice(5));
      }
      const config = env.GLAB_CONFIG_DIR || (${JSON.stringify(resolver)} === "legacy"
        ? path.join(env.XDG_CONFIG_HOME || path.join(home, ".config"), "glab-cli")
        : exists(legacy) ? legacy
        : xdg && path.isAbsolute(xdg) && exists(path.join(xdg, "glab-cli"))
          ? path.join(xdg, "glab-cli") : path.join(env.XDG_CONFIG_DIRS, "glab-cli"));
      const selected = fs.readFileSync(path.join(config, "config.yml"), "utf8");
      if (selected !== "synthetic-selected-host\\n") throw new Error("Selected a different synthetic hosting configuration");
      fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify({ directory: process.cwd(), config }) + "\\n");
      if (process.argv[3] === "create") process.stdout.write("https://gitlab.com/example/repository/-/merge_requests/1");
    `,
    );
    let removed = false;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: async (command, args, cwd, options) => {
          const effective = { ...environment, ...options?.environment };
          if (command === "git") {
            expect(effective["HOME"]).toBe(environment["HOME"]);
            for (const key of Object.keys(effective)) {
              if (
                key.startsWith("GIT_CONFIG_KEY_") &&
                effective[key] ===
                  "url.https://gitlab.com/example/repository.git.insteadOf"
              )
                effective[key] = `url.${remote}.insteadOf`;
            }
            return runGitRepositoryCommand(
              command,
              args[0] === "push"
                ? args.map((argument) =>
                    argument === "origin" ? remote : argument,
                  )
                : args,
              cwd,
              { ...options, environment: effective },
            );
          }
          expect(command).toBe("glab");
          if (expanded || kind === "drive-relative xdg")
            expect(effective["XDG_CONFIG_HOME"]).toBe(
              environment["XDG_CONFIG_HOME"],
            );
          return execFileSync(process.execPath, [hosting, ...args], {
            cwd: options?.directory ?? cwd,
            env: { ...process.env, ...effective },
            encoding: "utf8",
          });
        },
        onCodex: async (_args, output) => {
          expect((await readFile(calls, "utf8")).trim()).not.toBe("");
          await rm(caller, { recursive: true });
          removed = true;
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(removed).toBe(true);
    const directories = (await readFile(calls, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line).directory);
    expect(directories).toContain(caller);
    expect(directories).toContain(directory);
    expect(environment).toEqual(inherited);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
      "https://gitlab.com/example/repository/-/merge_requests/1",
    );
  },
);
