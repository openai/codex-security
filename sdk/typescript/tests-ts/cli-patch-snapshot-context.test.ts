import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  realpath,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, parse, resolve } from "node:path";
import { stringify as stringifyToml } from "smol-toml";
import { runCodexSkillCommand, runRepositoryCommand } from "../src/cli.js";
import { resolveCodexCommand } from "../src/runtime.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
// Native Windows snapshots repeat account and file ACL setup per Git command.
const nativeSnapshotTimeout = process.platform === "win32" ? 180_000 : 30_000;
const windows = patchSnapshotWindowsConfig();
const provider =
  'model_provider = "synthetic"\n[model_providers.synthetic]\nname = "Synthetic"\nbase_url = "http://127.0.0.1:9/v1"\nwire_api = "responses"\n';

test
  .skipIf(process.platform === "win32")
  .each([
    "configured",
    "git-dir",
    "inaccessible",
    ...(spawnSync("git", ["lfs", "version"]).status === 0 ? ["used"] : []),
  ])(
  "patches non-LFS files without requiring unused writable LFS storage: %s",
  async (mode) => {
    const root = await fixtures.create("patch-unused-lfs-");
    const repository = join(root, "repository");
    await mkdir(repository);
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(repository, "app.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic unused LFS baseline");
    if (mode === "used") {
      git("lfs", "install", "--local", "--skip-repo");
      await writeFile(
        join(repository, ".gitattributes"),
        "*.bin filter=lfs diff=lfs merge=lfs -text\n",
      );
      git("add", ".gitattributes");
      git("commit", "-m", "Synthetic LFS attributes");
    }
    const readOnly =
      mode === "git-dir" ? join(repository, ".git") : join(root, "cache");
    if (mode !== "git-dir") {
      await mkdir(readOnly);
      git("config", "lfs.storage", readOnly);
    }
    const index = await readFile(join(repository, ".git", "index"));
    const head = git("rev-parse", "HEAD");
    let patched = false;
    await chmod(readOnly, mode === "inaccessible" ? 0 : 0o555);
    try {
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: repository,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            patched = true;
            if (mode === "used")
              await writeFile(
                join(repository, "payload.bin"),
                "Synthetic LFS payload\n",
              );
            await writeFile(join(repository, "app.ts"), "fixed\n");
            output!.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(patched).toBe(true);
      expect(outcome.exitCode, outcome.stderr).toBe(mode === "used" ? 2 : 0);
      if (mode === "used")
        expect(outcome.stderr).toContain("clean filter 'lfs' failed");
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
    } finally {
      await chmod(readOnly, 0o755);
    }
  },
);

test.each(["unused", "abort", "unexpected failure"])(
  "preserves optional LFS configuration behavior: %s",
  async (mode) => {
    const root = await fixtures.create("patch-optional-lfs-config-");
    const repository = join(root, "repository");
    await mkdir(repository);
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(repository, "app.ts"), "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic optional LFS baseline");
    const index = await readFile(join(repository, ".git", "index"));
    const head = git("rev-parse", "HEAD");
    const selector = join(root, "selected.gitconfig");
    const contents = "Synthetic ordinary file\n";
    await writeFile(selector, contents);
    const environment = { ...process.env, GIT_CONFIG: selector };
    const canceled = new AbortController();
    canceled.abort();
    const failure: Error | undefined =
      mode === "abort"
        ? canceled.signal.reason
        : mode === "unexpected failure"
          ? Object.assign(new Error("Synthetic Git invocation failure"), {
              code: 1,
            })
          : undefined;
    let started = false;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      environment,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (failure !== undefined && args.includes("lfs.storage"))
          throw failure;
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
      onCodex: async (_args, output) => {
        started = true;
        const storage = await realpath(join(repository, ".git", "lfs"));
        expect(output!.appServer!.snapshotStoragePaths).toEqual([storage]);
        expect(output!.appServer!.permissions!.modelOnlyReadOnlyPaths).toEqual([
          join(storage, "objects"),
          join(storage, "tmp"),
        ]);
        await writeFile(join(repository, "app.ts"), "after\n");
        output!.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(started).toBe(failure === undefined);
    expect(outcome.exitCode, outcome.stderr).toBe(failure ? 2 : 0);
    if (failure !== undefined)
      expect(outcome.stderr).toContain(failure.message);
    expect(await readFile(selector, "utf8")).toBe(contents);
    expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
    expect(git("rev-parse", "HEAD")).toBe(head);
  },
);

test(
  "native snapshots retain Windows Git home fallbacks when HOME is unset",
  async () => {
    const root = await fixtures.create("patch-home-fallbacks-");
    const repository = join(root, "repository"),
      home = join(root, "home");
    await Promise.all([mkdir(repository), mkdir(home)]);
    const emptyConfig = join(root, "empty.gitconfig");
    await writeFile(emptyConfig, "");
    const fallback = {
      USERPROFILE: home,
      HOMEDRIVE: parse(home).root.slice(0, -1),
      HOMEPATH: home.slice(parse(home).root.length - 1),
    };
    const environment = patchSnapshotEnvironment(
      await fixtures.create("patch-home-fallback-temp-"),
      {
        ...process.env,
        ...fallback,
        HOME: undefined,
        CODEX_HOME: home,
        GIT_CONFIG_GLOBAL:
          process.platform === "win32" ? undefined : join(home, ".gitconfig"),
        GIT_CONFIG_SYSTEM: emptyConfig,
        GIT_CONFIG_NOSYSTEM: "1",
      },
    );
    const cleanSource = `const fs=require("node:fs"); const expected=${JSON.stringify(fallback)}; const input=fs.readFileSync(0,"utf8"); process.stdout.write(Object.entries(expected).every(([key,value])=>process.env[key]===value) ? input.toUpperCase() : input);`;
    const cleanCommand = `node -e '${cleanSource.replaceAll("'", "'\\''")}'`;
    await writeFile(
      join(home, ".gitconfig"),
      `[filter "home-fallback"]\n clean = ${JSON.stringify(cleanCommand)}\n required = true\n`,
    );
    await writeFile(
      join(home, "config.toml"),
      windows +
        stringifyToml({
          shell_environment_policy: {
            inherit: "all",
            exclude: ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"],
            set: {
              USERPROFILE: join(root, "policy-home"),
              HOMEDRIVE: "Z:",
              HOMEPATH: "\\policy-home",
            },
          },
        }),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        env: environment,
        encoding: "utf8",
      }).trim();
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(
      join(repository, ".gitattributes"),
      "data filter=home-fallback\n",
    );
    await writeFile(join(repository, "data"), "lowercase source\n");
    git("add", ".");
    git("commit", "-m", "Synthetic home fallback baseline");
    expect(git("show", "HEAD:data")).toBe("LOWERCASE SOURCE");
    const trees: string[] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      environment,
      manualCodexPreparation: true,
      onCodex: async (_args, output) => {
        output!.appServer!.onPermissions!({
          directory: repository,
          environment,
          snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
          profile: {
            extends: ":workspace",
            network: { enabled: false },
            workspace_roots: {},
            filesystem: Object.fromEntries(
              output!.appServer!.permissions!.readOnlyPaths.map((path) => [
                path,
                { ".": "read" },
              ]),
            ),
          },
        });
        await output!.appServer!.onBeforeTurn?.();
        output!.stdout.write("Synthetic no-op turn.\n");
        return 0;
      },
      onRepositoryCommand: async (command, args, cwd, options) => {
        const result = await runRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
        if (args.includes("write-tree")) trees.push(result.trim());
        return result;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(trees, outcome.stdout + outcome.stderr).toEqual([
      git("rev-parse", "HEAD^{tree}"),
      git("rev-parse", "HEAD^{tree}"),
    ]);
    expect(await readFile(join(repository, "data"), "utf8")).toBe(
      "lowercase source\n",
    );
  },
  nativeSnapshotTimeout,
);

test
  .skipIf(spawnSync("git", ["lfs", "version"]).status !== 0)
  .each([
    "missing",
    "symlink",
    "configured-symlink",
    "selector",
    "selector-include",
    "malformed-selector",
  ] as const)(
  "prepares canonical LFS storage for the first filtered file: %s",
  async (mode) => {
    const root = await fixtures.create("patch-first-lfs-");
    const repository = join(root, "repository"),
      home = join(root, "home");
    await Promise.all([mkdir(repository), mkdir(home)]);
    await writeFile(join(home, "config.toml"), windows);
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    git("lfs", "install", "--local", "--skip-repo");
    await writeFile(
      join(repository, ".gitattributes"),
      "*.bin filter=lfs diff=lfs merge=lfs -text\n",
    );
    await writeFile(join(repository, "app.ts"), "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic LFS baseline");
    let storage = join(repository, ".git", "lfs");
    const environment = patchSnapshotEnvironment(
      await fixtures.create("patch-first-lfs-temp-"),
      { ...process.env, CODEX_HOME: home },
    );
    if (
      mode === "selector" ||
      mode === "selector-include" ||
      mode === "malformed-selector"
    ) {
      if (mode !== "malformed-selector")
        storage = join(root, "selected-storage");
      const selector = join(root, "lfs.gitconfig");
      const settings = `[lfs]\n storage = ${JSON.stringify(storage.replaceAll("\\", "/"))}\n`;
      if (mode === "selector-include") {
        const included = join(root, "included.gitconfig");
        await writeFile(included, settings);
        await writeFile(
          selector,
          `[include]\n path = ${JSON.stringify(included.replaceAll("\\", "/"))}\n`,
        );
      } else if (mode === "malformed-selector") {
        await writeFile(
          selector,
          `[lfs]\n storage = ${JSON.stringify(join(root, "discarded-storage").replaceAll("\\", "/"))}\n[invalid\n`,
        );
      } else await writeFile(selector, settings);
      environment["GIT_CONFIG"] = selector;
    } else if (mode !== "missing") {
      const target = join(root, "storage-target");
      await mkdir(target);
      const alias = mode === "symlink" ? storage : join(root, "storage-alias");
      await symlink(
        target,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      if (mode === "configured-symlink") {
        storage = join(alias, "storage");
        git("config", "lfs.storage", storage);
      }
    }
    await expect(lstat(join(storage, "objects"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    if (
      mode === "selector" ||
      mode === "selector-include" ||
      mode === "malformed-selector"
    ) {
      const lfsEnvironment = spawnSync("git", ["lfs", "env"], {
        cwd: repository,
        env: environment,
        encoding: "utf8",
      });
      expect(lfsEnvironment.status, lfsEnvironment.stderr).toBe(0);
      if (mode === "malformed-selector")
        expect(lfsEnvironment.stderr).toContain("bad config line");
      const media = lfsEnvironment.stdout
        .split(/\r?\n/u)
        .find((line) => line.startsWith("LocalMediaDir="));
      expect(media).toBeDefined();
      expect(resolve(media!.slice("LocalMediaDir=".length))).toBe(
        resolve(join(storage, "objects")),
      );
    }
    const originalConfig = await readFile(join(repository, ".git", "config"));
    const originalIndex = await readFile(join(repository, ".git", "index"));
    const payload = "Synthetic first LFS payload\n";
    let storagePaths: readonly string[] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      environment,
      manualCodexPreparation: true,
      onCodex: async (_args, output) => {
        storagePaths = output!.appServer!.snapshotStoragePaths ?? [];
        output!.appServer!.onPermissions!({
          directory: repository,
          environment,
          snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
          profile: {
            extends: ":workspace",
            network: { enabled: false },
            workspace_roots: {},
            filesystem: {
              ...Object.fromEntries(
                output!.appServer!.permissions!.readOnlyPaths.map((path) => [
                  path,
                  { ".": "read" },
                ]),
              ),
              // An external cache needs explicit snapshot data-directory grants.
              ...(mode === "selector" || mode === "selector-include"
                ? { [storage]: { ".": "read" } }
                : {}),
            },
          },
        });
        await output!.appServer!.onBeforeTurn?.();
        await writeFile(join(repository, "payload.bin"), payload);
        output!.stdout.write("Synthetic LFS patch complete.\n");
        return 0;
      },
      onRepositoryCommand: (command, args, cwd, options) =>
        runRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        }),
    });
    expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(0);
    expect(storagePaths).toContain(await realpath(storage));
    if (mode === "malformed-selector") {
      expect(storagePaths).toEqual([await realpath(storage)]);
      await expect(
        lstat(join(root, "discarded-storage")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    }
    const digest = createHash("sha256").update(payload).digest("hex");
    expect(
      await readFile(
        join(
          await realpath(storage),
          "objects",
          digest.slice(0, 2),
          digest.slice(2, 4),
          digest,
        ),
        "utf8",
      ),
    ).toBe(payload);
    expect(await readFile(join(repository, ".git", "config"))).toEqual(
      originalConfig,
    );
    expect(await readFile(join(repository, ".git", "index"))).toEqual(
      originalIndex,
    );
  },
  nativeSnapshotTimeout,
);

test.each([
  ...[
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "HOME",
    "XDG_CONFIG_HOME",
  ].flatMap((selector) =>
    ["set", "unset", "empty"].map((state) => ({
      selector,
      state,
      filtered: true,
    })),
  ),
  { selector: "GIT_CONFIG_COUNT", state: "unset", filtered: true },
  { selector: "GIT_CONFIG_PARAMETERS", state: "unset", filtered: true },
  ...["GIT_CONFIG_GLOBAL", "HOME", "XDG_CONFIG_HOME"].map((selector) => ({
    selector,
    state: "set",
    filtered: false,
  })),
  ...["set", "unset"].flatMap((state) =>
    [false, true].map((filtered) => ({
      selector: "GIT_ATTR_SOURCE",
      state,
      filtered,
    })),
  ),
  ...["set", "unset", "empty"].flatMap((state) =>
    [false, true].map((filtered) => ({
      selector: "GIT_ATTR_NOSYSTEM",
      state,
      filtered,
    })),
  ),
  ...[false, true].map((filtered) => ({
    selector: "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    state: "set",
    filtered,
  })),
])(
  "native no-op snapshots preserve coordinator Git configuration: %j",
  async ({ selector, state, filtered }) => {
    const root = await fixtures.create("patch-native-config-");
    const repository = join(root, "repository"),
      home = join(root, "home");
    await Promise.all([mkdir(repository), mkdir(home, { mode: 0o700 })]);
    const emptyConfig = join(root, "empty.gitconfig"),
      filterConfig = join(root, "filter.gitconfig");
    await writeFile(emptyConfig, "");
    const attributeValue =
      state === "set" ? "1" : state === "empty" ? "" : undefined;
    const cleanSource =
      'const fs=require("node:fs");const input=fs.readFileSync(0,"utf8");' +
      `process.stdout.write(${selector === "GIT_ATTR_NOSYSTEM" ? `process.env.GIT_ATTR_NOSYSTEM===${JSON.stringify(attributeValue)}?input.toUpperCase():input` : "input.toUpperCase()"});`;
    const cleanCommand = `node -e '${cleanSource.replaceAll("'", "'\\''")}'`;
    const filterSettings = `[filter "synthetic-selector"]\n clean = ${JSON.stringify(cleanCommand)}\n`;
    await writeFile(filterConfig, filterSettings);
    const environment = patchSnapshotEnvironment(
      await fixtures.create("patch-native-config-temp-"),
      {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: home,
        CODEX_HOME: home,
      },
    );
    for (const name of Object.keys(environment))
      if (/^GIT_CONFIG(?:_|$)/iu.test(name)) delete environment[name];
    Object.assign(environment, {
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_CONFIG_SYSTEM: emptyConfig,
      GIT_CONFIG_NOSYSTEM: "1",
    });
    const policySet: Record<string, string> = {};
    if (selector === "HOME" || selector === "XDG_CONFIG_HOME") {
      environment["GIT_CONFIG_GLOBAL"] = undefined;
      environment[selector] =
        state === "set" ? home : state === "empty" ? "" : undefined;
      const policyHome = join(root, "policy-home");
      await mkdir(policyHome, { mode: 0o700 });
      const configHome = state === "set" ? home : policyHome;
      const configPath =
        selector === "HOME"
          ? join(configHome, ".gitconfig")
          : join(configHome, "git", "config");
      if (selector === "XDG_CONFIG_HOME") await mkdir(join(configHome, "git"));
      await writeFile(configPath, filterSettings);
      policySet[selector] = policyHome;
    } else if (selector === "GIT_CONFIG_NOSYSTEM") {
      environment["GIT_CONFIG_SYSTEM"] = filterConfig;
      environment[selector] =
        state === "set" ? "1" : state === "empty" ? "" : undefined;
      Object.assign(policySet, {
        GIT_CONFIG_SYSTEM: filterConfig,
        GIT_CONFIG_NOSYSTEM: state === "set" ? "0" : "1",
      });
    } else if (selector === "GIT_CONFIG_COUNT") {
      Object.assign(policySet, {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "filter.synthetic-selector.clean",
        GIT_CONFIG_VALUE_0: cleanCommand,
      });
    } else if (selector === "GIT_CONFIG_PARAMETERS") {
      policySet["GIT_CONFIG_PARAMETERS"] =
        `'filter.synthetic-selector.clean=${cleanCommand.replaceAll("'", "'\\''")}'`;
    } else if (selector === "GIT_ATTR_SOURCE") {
      environment[selector] = undefined;
      policySet[selector] = state === "set" ? "HEAD" : "synthetic-attributes";
    } else if (selector === "GIT_ATTR_NOSYSTEM") {
      environment[selector] =
        state === "set" ? "1" : state === "empty" ? "" : undefined;
      policySet[selector] = state === "set" ? "0" : "1";
    } else if (selector !== "GIT_ALTERNATE_OBJECT_DIRECTORIES") {
      environment[selector] =
        state === "set" ? filterConfig : state === "empty" ? "" : undefined;
      policySet[selector] = state === "set" ? emptyConfig : filterConfig;
      if (selector === "GIT_CONFIG_SYSTEM") {
        environment["GIT_CONFIG_NOSYSTEM"] = "0";
        policySet["GIT_CONFIG_NOSYSTEM"] = "0";
      }
      if (selector === "GIT_CONFIG_GLOBAL" && state === "empty")
        await writeFile(join(home, ".gitconfig"), filterSettings);
    }
    await writeFile(
      join(home, "config.toml"),
      windows +
        stringifyToml({
          shell_environment_policy: {
            inherit: "all",
            exclude: filtered ? ["GIT_*", "HOME", "XDG_CONFIG_HOME"] : [],
            set: filtered ? policySet : {},
          },
        }),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        env: environment,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    if (selector === "GIT_ATTR_SOURCE" || selector === "GIT_ATTR_NOSYSTEM")
      git("config", "filter.synthetic-selector.clean", cleanCommand);
    await writeFile(
      join(repository, ".gitattributes"),
      "data filter=synthetic-selector\n",
    );
    await writeFile(join(repository, "data"), "original lowercase data\n");
    git("add", ".");
    git("commit", "-m", "Synthetic configuration baseline");
    if (selector === "GIT_ATTR_SOURCE") {
      git("tag", "synthetic-attributes");
      git("rm", ".gitattributes");
      environment[selector] =
        state === "set" ? "synthetic-attributes" : undefined;
      git("add", "--renormalize", "data");
      git("commit", "-m", "Synthetic worktree without attributes");
    }
    const pool = join(root, "object-pool");
    if (selector === "GIT_ALTERNATE_OBJECT_DIRECTORIES") {
      const objects = join(repository, ".git", "objects");
      await rename(objects, pool);
      await mkdir(objects);
      environment[selector] = pool;
    }
    const index = await readFile(join(repository, ".git", "index"));
    let snapshots = 0;
    const bindings: NodeJS.ProcessEnv[] = [];
    const trees: string[] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      environment,
      manualCodexPreparation: true,
      onCodex: async (_args, output) => {
        expect(trees).toEqual([]);
        if (selector === "GIT_ALTERNATE_OBJECT_DIRECTORIES")
          expect(
            output!.appServer!.permissions!.readOnlyPaths.map((path) =>
              path.replaceAll("\\", "/"),
            ),
          ).toContain((await realpath(pool)).replaceAll("\\", "/"));
        output!.appServer!.onPermissions!({
          directory: repository,
          environment,
          snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
          profile: {
            extends: ":workspace",
            network: { enabled: false },
            workspace_roots: {},
            filesystem: Object.fromEntries(
              output!.appServer!.permissions!.readOnlyPaths.map((path) => [
                path,
                { ".": "read" },
              ]),
            ),
          },
        });
        await output!.appServer!.onBeforeTurn?.();
        expect(trees).toEqual([git("rev-parse", "HEAD^{tree}")]);
        output!.stdout.write("Synthetic no-op model turn.\n");
        return 0;
      },
      async onRepositoryCommand(command, args, cwd, options) {
        if (options?.sandbox) {
          snapshots++;
          bindings.push(options.sandbox.gitEnvironment!);
          if (selector === "GIT_ALTERNATE_OBJECT_DIRECTORIES")
            expect(
              Object.entries(
                options.sandbox.profile["filesystem"] as Record<
                  string,
                  unknown
                >,
              ).find(
                ([path]) =>
                  path.replaceAll("\\", "/") === pool.replaceAll("\\", "/"),
              )?.[1],
            ).toEqual({ ".": "read" });
        }
        const result = await runRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
        if (args.includes("write-tree")) trees.push(result.trim());
        return result;
      },
    });
    expect(await readFile(join(repository, "data"), "utf8")).toBe(
      "original lowercase data\n",
    );
    expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
    expect(git("diff", "--exit-code")).toBe("");
    expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(2);
    expect(
      JSON.parse(outcome.stdout).error.code,
      outcome.stdout + outcome.stderr,
    ).toBe("NO_PATCH_APPLIED");
    expect(snapshots).toBeGreaterThan(0);
    expect(trees).toHaveLength(2);
    expect(trees[1]).toBe(trees[0]);
    if (filtered) {
      const alternates = (value: string | undefined) =>
        execFileSync("git", ["count-objects", "-v"], {
          cwd: repository,
          env: { ...environment, GIT_ALTERNATE_OBJECT_DIRECTORIES: value },
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        })
          .split("\n")
          .filter((line) => line.startsWith("alternate: "));
      const expectedAlternates =
        selector === "GIT_ALTERNATE_OBJECT_DIRECTORIES"
          ? alternates(environment[selector])
          : undefined;
      if (expectedAlternates !== undefined)
        expect(expectedAlternates.length).toBeGreaterThan(0);
      for (const binding of bindings) {
        if (expectedAlternates === undefined)
          expect(binding).toHaveProperty(selector, environment[selector]);
        else {
          expect(binding).toHaveProperty(selector);
          expect(alternates(binding[selector])).toEqual(expectedAlternates);
        }
      }
    }
  },
  nativeSnapshotTimeout,
);

test.each([
  "stored credentials",
  "provider override",
  "Git exclusions",
  "Git config tuple",
] as const)(
  "snapshots inherit the prepared native context: %s",
  async (mode) => {
    const root = await fixtures.create("patch-snapshot-context-");
    const repository = join(root, "repository"),
      home = join(root, "home"),
      state = join(root, "state"),
      prepared = join(state, "codex-home");
    await Promise.all([mkdir(repository), mkdir(home)]);
    const global = join(root, "empty-gitconfig");
    await writeFile(global, "");
    const environment = patchSnapshotEnvironment(
      await fixtures.create("patch-prepared-context-temp-"),
      {
        PATH: process.env["PATH"],
        ...(process.env["SystemRoot"] === undefined
          ? {}
          : { SystemRoot: process.env["SystemRoot"] }),
        CODEX_HOME:
          mode === "stored credentials" ? join(root, "absent-home") : home,
        CODEX_SECURITY_STATE_DIR: state,
        GIT_CONFIG_GLOBAL: global,
        GIT_CONFIG_NOSYSTEM: "1",
        ...(mode === "Git config tuple"
          ? {
              GIT_CONFIG_COUNT: "1",
              GIT_CONFIG_KEY_0: "core.quotePath",
              GIT_CONFIG_VALUE_0: "false",
            }
          : {}),
      },
    );
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const source = join(repository, "app.ts");
    await writeFile(source, "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const index = await readFile(join(repository, ".git", "index"));
    if (mode === "stored credentials") {
      await mkdir(prepared, { recursive: true, mode: 0o700 });
      await writeFile(
        join(prepared, "auth.json"),
        '{"auth_mode":"apikey","OPENAI_API_KEY":"sk-synthetic-local-only"}\n',
        { mode: 0o600 },
      );
      await writeFile(join(prepared, "config.toml"), windows);
    } else
      await writeFile(
        join(home, "config.toml"),
        windows +
          (mode === "provider override"
            ? 'model_provider = "synthetic"\n'
            : provider +
              '[shell_environment_policy]\ninherit = "all"\n' +
              (mode === "Git config tuple"
                ? "ignore_default_excludes = false\n"
                : 'exclude = ["GIT_*"]\n')),
      );
    // Use real native configuration and preflight; substitute only the model turn.
    const proxy = join(root, "native-turn.cjs"),
      record = join(root, "runtime.json");
    await writeFile(
      proxy,
      `const fs=require("node:fs"),{spawn}=require("node:child_process"),{createInterface}=require("node:readline");
fs.writeFileSync(${JSON.stringify(record)},JSON.stringify({home:process.env.CODEX_HOME}));
const child=spawn(process.argv[2],process.argv.slice(3),{stdio:["pipe","pipe","inherit"]});
let thread;
createInterface({input:child.stdout}).on("line",line=>{const reply=JSON.parse(line);if(reply.id===2)thread=reply.result?.thread.id;process.stdout.write(line+"\\n");});
const send=reply=>process.stdout.write(JSON.stringify(reply)+"\\n");
createInterface({input:process.stdin}).on("line",line=>{const request=JSON.parse(line);if(request.method!=="turn/start"){child.stdin.write(line+"\\n");return;}
fs.writeFileSync(${JSON.stringify(source)},"after\\n");
send({id:request.id,result:{turn:{id:"synthetic-turn"}}});
send({method:"item/completed",params:{threadId:thread,turnId:"synthetic-turn",item:{type:"agentMessage",text:"Synthetic patch complete"}}});
send({method:"turn/completed",params:{threadId:thread,turn:{id:"synthetic-turn",status:"completed"}}});
}).on("close",()=>child.stdin.end());child.on("exit",code=>process.exitCode=code??1);
`,
    );
    const homes = new Set<string>();
    const result = await runWorkflow(
      [
        "patch",
        "Synthetic issue",
        ...(mode === "stored credentials" ? ["--auth", "chatgpt"] : []),
        ...(mode === "provider override"
          ? [
              "--codex",
              'model_providers.synthetic={name="Synthetic",base_url="http://127.0.0.1:9/v1",wire_api="responses"}',
              "--codex",
              "analytics.enabled=false",
            ]
          : []),
        "--json",
      ],
      {
        currentDirectory: repository,
        environment,
        manualCodexPreparation: true,
        onCodex: (args, output, selected) =>
          runCodexSkillCommand(
            [proxy, resolveCodexCommand(selected).command, ...args],
            output,
            { command: process.execPath },
            selected,
          ),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (options?.sandbox !== undefined) {
            homes.add(options.sandbox.environment["CODEX_HOME"]!);
            if (mode === "provider override") {
              expect(
                options.sandbox.configuration?.["model_providers"],
              ).toHaveProperty("synthetic");
              expect(options.sandbox.configuration?.["analytics"]).toEqual({
                enabled: false,
              });
            }
          }
          return runRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
      },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).files).toEqual(["app.ts"]);
    expect(homes).toEqual(
      new Set([mode === "stored credentials" ? prepared : home]),
    );
    expect(JSON.parse(await readFile(record, "utf8")).home).toBe([...homes][0]);
    expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
  },
  nativeSnapshotTimeout,
);

test("snapshot binding frames retain raw stdin and unset semantics while native environment filters remain active", async () => {
  const root = await fixtures.create("patch-snapshot-bindings-");
  const repository = join(root, "repository"),
    home = join(root, "home");
  await Promise.all([mkdir(repository), mkdir(home)]);
  repositoryGit(repository)("init", "--initial-branch=main");
  await writeFile(
    join(home, "config.toml"),
    windows +
      '[shell_environment_policy]\ninherit="all"\nexclude=["GIT_*","SNAPSHOT_USER_FILTERED"]\n[shell_environment_policy.set]\nGIT_DIR="incorrect-repository"\nSNAPSHOT_USER_SET="preserved"\n',
  );
  const script = join(root, "inspect.cjs");
  await writeFile(
    script,
    `const fs=require("node:fs");
fs.writeSync(1, JSON.stringify({index:process.env.GIT_INDEX_FILE,dir:process.env.GIT_DIR??null,filtered:process.env.SNAPSHOT_USER_FILTERED??null,set:process.env.SNAPSHOT_USER_SET})+"\\n");
fs.writeSync(1, fs.readFileSync(0));
if(process.argv.includes("fail")){fs.writeSync(2, "Synthetic Git failure detail.\\n");process.exitCode=17;}
`,
  );
  const index = join(root, "snapshot-index");
  const gitEnvironment = {
    GIT_INDEX_FILE: index,
    GIT_DIR: undefined,
    ...Object.fromEntries(
      Array.from({ length: 1024 }, (_, i) => [
        `GIT_UNSET_${i}_${"x".repeat(128)}`,
        undefined,
      ]),
    ),
  };
  expect(
    Buffer.byteLength(
      JSON.stringify(
        Object.entries(gitEnvironment).map(([name, value]) => [
          name,
          value ?? null,
        ]),
      ),
    ),
  ).toBeGreaterThan(128 * 1024);
  const sandbox = {
    directory: repository,
    environment: patchSnapshotEnvironment(
      await fixtures.create("patch-binding-temp-"),
      {
        ...process.env,
        CODEX_HOME: home,
        SNAPSHOT_USER_FILTERED: "excluded",
      },
    ),
    gitEnvironment,
    profile: {
      extends: ":workspace",
      network: { enabled: false },
      workspace_roots: {},
      filesystem: {},
    },
  };
  const input = Buffer.alloc(256 * 1024);
  for (let i = 0; i < input.length; i++) input[i] = i % 256;
  const args = [
    "-c",
    `alias.inspect=!node ${JSON.stringify(script.replaceAll("\\", "/"))}`,
    "inspect",
  ];
  let capturedStderr = "";
  const bytes = Buffer.from(
    await runRepositoryCommand("git", args, repository, {
      sandbox,
      input,
      encoding: "base64",
      trim: false,
      maxBuffer: Infinity,
      onStderr(chunk) {
        capturedStderr += chunk.toString();
      },
    }),
    "base64",
  );
  const end = bytes.indexOf(10);
  expect(bytes.subarray(0, end).toString(), capturedStderr).not.toBe("");
  expect(JSON.parse(bytes.subarray(0, end).toString())).toEqual({
    index,
    dir: null,
    filtered: null,
    set: "preserved",
  });
  expect(bytes.subarray(end + 1)).toEqual(input);
  await expect(
    runRepositoryCommand("git", [...args, "fail"], repository, { sandbox }),
  ).rejects.toMatchObject({
    code: 17,
    stderr: expect.stringContaining("Synthetic Git failure detail."),
  });
  await expect(
    runRepositoryCommand("git", args, repository, {
      sandbox,
      input,
      maxBuffer: 32,
    }),
  ).rejects.toHaveProperty("code", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER");
  await expect(
    runRepositoryCommand(
      "git",
      ["cat-file", "--invalid-synthetic-option"],
      repository,
      { sandbox, input },
    ),
  ).rejects.toHaveProperty("code", 129);
  await expect(
    runRepositoryCommand("git", args, repository, {
      sandbox: {
        ...sandbox,
        configuration: { model_provider: "missing-synthetic-provider" },
      },
      input,
    }),
  ).rejects.toThrow("Model provider `missing-synthetic-provider` not found");
}, 30_000);

test.each([
  "standard",
  "nested",
  "worktree",
  "configured",
  "absent",
  "symlink",
  "directory-symlink",
  "missing-include",
  "include-symlink",
  "include-loop",
] as const)(
  "snapshot filters can write LFS data while overlapping hooks stay protected: %s",
  async (mode) => {
    const root = await fixtures.create("patch-snapshot-storage-");
    const parent = join(root, "repository"),
      home = join(root, "home");
    await Promise.all([mkdir(parent), mkdir(home)]);
    await writeFile(join(home, "config.toml"), windows);
    const initialize = (directory: string) => {
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      return git;
    };
    const parentGit = initialize(parent);
    let repository = parent;
    let checkout = parent;
    if (mode === "nested") {
      checkout = join(parent, "child");
      await mkdir(checkout);
      initialize(checkout);
    }
    const initial = repositoryGit(checkout);
    const storage =
      mode === "configured"
        ? join(root, "data-cache")
        : join(checkout, ".git", "lfs");
    if (mode === "configured") initial("config", "lfs.storage", storage);
    const temporary =
        mode === "absent" || mode === "symlink"
          ? storage
          : join(
              storage,
              mode === "directory-symlink" ? "selected-hooks" : "tmp",
            ),
      objects = join(storage, "objects");
    if (mode === "directory-symlink") {
      const original = join(root, "selected-hooks");
      await Promise.all([mkdir(original), mkdir(storage, { recursive: true })]);
      await symlink(
        original,
        temporary,
        process.platform === "win32" ? "junction" : "dir",
      );
    }
    await Promise.all([
      mkdir(temporary, { recursive: true }),
      mkdir(objects, { recursive: true }),
    ]);
    const hook = join(temporary, "post-index-change");
    const selectedConfig = join(storage, "snapshot.gitconfig");
    const configContents = "# Synthetic selected configuration.\n";
    if (mode === "include-symlink") {
      const original = join(root, "selected-config");
      await writeFile(original, configContents);
      await symlink(original, selectedConfig);
    }
    if (mode === "include-loop") {
      await symlink(selectedConfig, selectedConfig);
      initial(
        "config",
        "includeIf.onbranch:future-branch.path",
        selectedConfig,
      );
    }
    if (mode === "missing-include" || mode === "include-symlink")
      initial("config", "include.path", selectedConfig);
    const protectedPath =
      mode === "missing-include" ||
      mode === "include-symlink" ||
      mode === "include-loop"
        ? selectedConfig
        : hook;
    const hookContents = "#!/bin/sh\nexit 0\n";
    if (mode === "symlink") {
      const original = join(root, "original-hook");
      await writeFile(original, hookContents, { mode: 0o755 });
      await symlink(original, hook);
    } else if (mode !== "absent")
      await writeFile(hook, hookContents, { mode: 0o755 });
    initial("config", "core.hooksPath", temporary);
    const clean = join(root, "clean.cjs");
    await writeFile(
      clean,
      `const fs=require("node:fs"),path=require("node:path");const input=fs.readFileSync(0);
fs.writeFileSync(${JSON.stringify(join(temporary, "payload"))},input);
fs.writeFileSync(${JSON.stringify(join(objects, "payload"))},input);
if(fs.readFileSync("app.ts","utf8").startsWith("after")){try{${mode === "symlink" || mode === "include-symlink" || mode === "include-loop" ? `fs.unlinkSync(${JSON.stringify(protectedPath)});` : mode === "directory-symlink" ? `fs.rmSync(${JSON.stringify(temporary)},{recursive:true,force:true});fs.mkdirSync(${JSON.stringify(temporary)});` : ""}fs.writeFileSync(${JSON.stringify(protectedPath)},${JSON.stringify(mode === "missing-include" || mode === "include-symlink" || mode === "include-loop" ? "[core]\n fsmonitor = false\n" : mode === "absent" || mode === "symlink" || mode === "directory-symlink" ? "#!/bin/sh\nprintf activated > HOOK_ACTIVATED\n" : "changed")});fs.chmodSync(${JSON.stringify(protectedPath)},0o755);}catch(error){if(!["EACCES","EPERM","EROFS"].includes(error.code))throw error;}}
process.stdout.write(input);
`,
    );
    initial(
      "config",
      "filter.storage.clean",
      `node ${JSON.stringify(clean.replaceAll("\\", "/"))}`,
    );
    initial("config", "filter.storage.required", "true");
    initial("config", "filter.storage.smudge", "cat");
    await writeFile(
      join(checkout, ".gitattributes"),
      "data filter=storage -text\n",
    );
    await writeFile(join(checkout, "app.ts"), "before\n");
    await writeFile(join(checkout, "data"), "Synthetic LFS payload\n");
    initial("add", ".");
    initial("commit", "-m", "Synthetic filtered baseline");
    if (mode === "nested") {
      parentGit("add", ".");
      parentGit("commit", "-m", "Synthetic parent baseline");
    }
    if (mode === "worktree") {
      repository = join(root, "linked");
      initial("worktree", "add", "-b", "linked", repository);
      checkout = repository;
    }
    const originalContents = await readFile(join(checkout, "app.ts"));
    const index = repositoryGit(checkout)(
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    );
    const originalIndex = await readFile(index);
    const environment = patchSnapshotEnvironment(
      await fixtures.create("patch-storage-temp-"),
      { ...process.env, CODEX_HOME: home },
    );
    const result = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      environment,
      manualCodexPreparation: true,
      onCodex: async (_args, output) => {
        output!.appServer!.onPermissions!({
          directory: repository,
          environment,
          snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
          profile: {
            extends: ":workspace",
            network: { enabled: false },
            workspace_roots: {},
            filesystem: Object.fromEntries(
              output!.appServer!.permissions!.readOnlyPaths.map((path) => [
                path,
                { ".": "read" },
              ]),
            ),
          },
        });
        await output!.appServer!.onBeforeTurn?.();
        await writeFile(join(checkout, "app.ts"), "after\n");
        output!.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
      onRepositoryCommand: (command, args, cwd, options) =>
        runRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        }),
    });
    if (mode === "include-loop")
      expect((await lstat(selectedConfig)).isSymbolicLink()).toBe(true);
    if (process.platform === "win32") {
      expect(result.exitCode).toBe(2);
      expect(result.stdout + result.stderr).toContain(
        "Windows sandbox cannot protect Git control",
      );
      expect(await readFile(join(checkout, "app.ts"))).toEqual(
        originalContents,
      );
    } else if (
      (mode === "symlink" ||
        mode === "directory-symlink" ||
        mode === "include-symlink" ||
        mode === "include-loop") &&
      result.exitCode !== 0
    ) {
      expect(result.exitCode).toBe(2);
      if (process.platform === "linux")
        expect(result.stdout + result.stderr).toContain(
          "cannot enforce sandbox read-only path",
        );
      expect(await readFile(join(checkout, "app.ts"))).toEqual(
        originalContents,
      );
    } else {
      expect(result.exitCode, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout).files).toContain(
        mode === "nested" ? "child/app.ts" : "app.ts",
      );
    }
    if (mode === "absent")
      await expect(lstat(hook)).rejects.toMatchObject({ code: "ENOENT" });
    else {
      expect(await readFile(hook, "utf8")).toBe(hookContents);
      if (mode === "symlink")
        expect((await lstat(hook)).isSymbolicLink()).toBe(true);
      if (mode === "directory-symlink")
        expect((await lstat(temporary)).isSymbolicLink()).toBe(true);
    }
    if (mode === "missing-include")
      await expect(lstat(selectedConfig)).rejects.toMatchObject({
        code: "ENOENT",
      });
    if (mode === "include-symlink") {
      expect((await lstat(selectedConfig)).isSymbolicLink()).toBe(true);
      expect(await readFile(selectedConfig, "utf8")).toBe(configContents);
    }
    await expect(lstat(join(checkout, "HOOK_ACTIVATED"))).rejects.toMatchObject(
      { code: "ENOENT" },
    );
    expect(await readFile(join(objects, "payload"), "utf8")).toBe(
      "Synthetic LFS payload\n",
    );
    expect(await readFile(index)).toEqual(originalIndex);
  },
  nativeSnapshotTimeout,
);
