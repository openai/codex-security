import { afterEach, describe, expect, mock, test } from "bun:test";
import { execFileSync } from "node:child_process";
import filesystem, {
  appendFile,
  chmod,
  cp,
  link,
  lstat,
  symlink,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { runCodexSkillCommand } from "../src/cli.js";
import { capturePatchGitControls } from "../src/patch-git-controls.js";
import { capture } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

function patchReadOnlyPaths(args: readonly string[], permissions: unknown) {
  expect(
    args.filter((value) =>
      value.startsWith("permissions.codex_security_patch="),
    ),
  ).toEqual([]);
  expect(permissions).toEqual(
    expect.objectContaining({
      name: "codex_security_patch",
      readOnlyPaths: expect.any(Array),
    }),
  );
  return (permissions as { readOnlyPaths: readonly string[] }).readOnlyPaths;
}

describe("patch Git administration", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  for (const replacement of [false, true]) {
    test(`binds prepared cache directories before the patch turn (replacement: ${replacement})`, async () => {
      const repository = await fixtures.create("patch-prepared-cache-");
      const storage = join(repository, "cache-data");
      await mkdir(storage);
      await symlink(
        storage,
        join(repository, "cache"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const filter = join(repository, "clean.cjs");
      await writeFile(
        filter,
        'const fs=require("node:fs");for(const path of ["cache/objects","cache/tmp"])fs.mkdirSync(path,{recursive:true});fs.writeFileSync("cache/objects/prepared","ready");fs.writeSync(1,fs.readFileSync(0));\n',
      );
      await writeFile(join(repository, ".gitignore"), "cache/\ncache-data/\n");
      await writeFile(
        join(repository, ".gitattributes"),
        "data filter=synthetic -text\n",
      );
      await writeFile(join(repository, "data"), "original\n");
      await writeFile(join(repository, "app.ts"), "before\n");
      git("config", "lfs.storage", "../cache");
      git(
        "config",
        "filter.synthetic.clean",
        `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
      );
      git("config", "filter.synthetic.required", "true");
      git("add", "app.ts", "data", ".gitattributes", "clean.cjs", ".gitignore");
      git("commit", "-m", "Synthetic cache preparation baseline");
      for (const name of ["objects", "tmp"])
        await rm(join(storage, name), { recursive: true });
      await writeFile(join(repository, "data"), "updated\n");
      const index = await readFile(join(repository, ".git", "index"));
      const head = git("rev-parse", "HEAD");
      let patched = false;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--external-sandbox", "--json"],
        {
          currentDirectory: repository,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            patched = true;
            expect(output!.appServer!.externalSandbox).toBe(true);
            expect(
              await readFile(join(storage, "objects", "prepared"), "utf8"),
            ).toBe("ready");
            if (replacement) {
              for (const name of ["objects", "tmp"]) {
                await rename(join(storage, name), join(storage, `${name}-old`));
                await mkdir(join(storage, name));
              }
            }
            await writeFile(join(repository, "app.ts"), "after\n");
            output!.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(patched).toBe(true);
      expect(outcome.exitCode, outcome.stderr).toBe(replacement ? 2 : 0);
      if (replacement)
        expect(JSON.parse(outcome.stdout).error.message).toContain(
          "changed location during the patch",
        );
      else expect(JSON.parse(outcome.stdout).files).toContain("app.ts");
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "after\n",
      );
      expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
      expect(git("rev-parse", "HEAD")).toBe(head);
    });
  }

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "keeps selected administration usable without parent directory listing",
    async () => {
      const repository = await fixtures.create(
        "patch-traversable-administration-",
      );
      const external = await fixtures.create(
        "patch-traversable-administration-target-",
      );
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      const metadata = join(external, "metadata");
      await rename(join(repository, ".git"), metadata);
      const parent = join(external, "selected");
      await mkdir(parent);
      const alias = join(parent, "administration");
      await symlink(metadata, alias, "dir");
      await chmod(parent, 0o111);
      try {
        await expect(readdir(parent)).rejects.toMatchObject({ code: "EACCES" });
        // Exercise traversal in the package's documented Node runtime.
        const result = execFileSync(
          "node",
          [
            "--input-type=module",
            "-e",
            `
import { execFileSync } from "node:child_process";
const { capturePatchGitControls } = await import(process.argv[1]);
const repository = process.argv[2];
const alias = process.argv[3];
const controls = await capturePatchGitControls(repository, async (_root, checkout, args, options) => {
  const result = execFileSync("git", args, {
    cwd: checkout,
    input: options?.input,
    env: {
      ...process.env,
      GIT_DIR: alias,
      GIT_WORK_TREE: repository,
      ...(options?.indexFile === undefined ? {} : { GIT_INDEX_FILE: options.indexFile }),
      ...options?.environment,
    },
  });
  return result.toString(options?.encoding === "base64" ? "base64" : "utf8");
}, false);
await controls.validate();
console.log(JSON.stringify(controls.snapshotStoragePaths));
`,
            await buildPatchGitControlsForNode(external),
            repository,
            alias,
          ],
          { encoding: "utf8" },
        );
        expect(JSON.parse(result)).toEqual([join(metadata, "lfs")]);
      } finally {
        await chmod(parent, 0o700);
      }
    },
  );

  test("distinguishes alternate administration spelling from separate entries", async () => {
    const repository = await fixtures.create("patch-administration-case-");
    const external = await fixtures.create("patch-administration-case-target-");
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    const selected = join(repository, ".git");
    const metadata = join(external, "metadata");
    await rename(selected, metadata);
    const linkType = process.platform === "win32" ? "junction" : "dir";
    await symlink(metadata, selected, linkType);
    const alternate = join(repository, ".GIT");
    const sameEntry = await lstat(alternate).then(
      () => true,
      (error) => {
        if (error.code === "ENOENT") return false;
        throw error;
      },
    );
    if (!sameEntry) {
      if (process.platform !== "linux")
        await symlink(metadata, alternate, linkType);
      else {
        await link(selected, alternate);
        expect((await lstat(alternate, { bigint: true })).ino).toBe(
          (await lstat(selected, { bigint: true })).ino,
        );
      }
    }
    git("config", "lfs.storage", join(alternate, "lfs"));
    const controls = await capturePatchGitControls(
      repository,
      async (_root, checkout, args, options) =>
        runGitRepositoryCommand("git", args, checkout, options),
      true,
    );
    const paths = [join(metadata, "lfs")];
    expect(controls!.snapshotStoragePaths).toEqual(sameEntry ? paths : []);
    expect(controls!.modelOnlyReadOnlyPaths).toEqual([
      join(metadata, "lfs", "objects"),
      join(metadata, "lfs", "tmp"),
    ]);
    await controls!.validate();
  });

  for (const sibling of ["none", "same target", "same identity"] as const) {
    const name = `recognizes a unique alternate administration entry with sibling: ${sibling}`;
    test(name, async () => {
      if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
      const repository = await fixtures.create("patch-alternate-entry-");
      const external = await fixtures.create("patch-alternate-entry-target-");
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      const metadata = join(external, "metadata");
      await rename(join(repository, ".git"), metadata);
      const selected = join(repository, "SelectedAdministration");
      const alternate = join(repository, "SELECT~1");
      const linkType = process.platform === "win32" ? "junction" : "dir";
      await symlink(metadata, selected, linkType);
      const other = join(repository, "OtherAdministration");
      if (sibling !== "none") await symlink(metadata, other, linkType);
      const environment = { GIT_DIR: selected, GIT_WORK_TREE: repository };
      await runGitRepositoryCommand(
        "git",
        ["config", "lfs.storage", join(alternate, "lfs")],
        repository,
        { environment },
      );
      const original = { ...filesystem };
      const translate = (path: unknown) =>
        typeof path === "string" &&
        (path === alternate || path.startsWith(`${alternate}${sep}`))
          ? `${selected}${path.slice(alternate.length)}`
          : path;
      // Model a filesystem lookup alias that is not a separate directory entry.
      const methods = Object.fromEntries(
        (["stat", "lstat", "realpath", "readlink", "mkdir"] as const).map(
          (method) => [
            method,
            (...args: unknown[]) => {
              let path = translate(args[0]);
              // Model equal link identities without platform-specific hard links.
              if (
                method === "lstat" &&
                sibling === "same identity" &&
                path === other
              )
                path = selected;
              return Reflect.apply(original[method], original, [
                path,
                ...args.slice(1),
              ]);
            },
          ],
        ),
      );
      const modeled = { ...original, ...methods };
      mock.module("node:fs/promises", () => ({
        ...modeled,
        default: modeled,
      }));
      try {
        const controls = await capturePatchGitControls(
          repository,
          async (_root, checkout, args, options) =>
            runGitRepositoryCommand("git", args, checkout, {
              ...options,
              environment: { ...environment, ...options?.environment },
            }),
          false,
        );
        const paths = [join(await realpath(metadata), "lfs")];
        expect(controls!.snapshotStoragePaths).toEqual(
          sibling === "same identity" ? [] : paths,
        );
        await controls!.validate();
      } finally {
        mock.module("node:fs/promises", () => ({
          ...original,
          default: original,
        }));
      }
    });
  }

  for (const location of [
    "root",
    "ancestor",
    "objects",
    "tmp",
    "indirect-root",
    "indirect-parent",
    "indirect-separators",
  ] as const) {
    // Windows junction creation normalizes ".." before storing its target.
    test.skipIf(process.platform === "win32" && location === "indirect-parent")(
      `leaves optional storage through checkout links unprepared: ${location}`,
      async () => {
        const repository = await fixtures.create("patch-storage-checkout-");
        const target = await fixtures.create("patch-storage-target-");
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git(
          "config",
          "lfs.storage",
          location === "ancestor" ? "../cache/storage" : "../cache",
        );
        await writeFile(join(repository, "app.txt"), "before\n");
        const cache = join(repository, "cache");
        if (location === "objects" || location === "tmp") await mkdir(cache);
        const link =
          location === "objects" || location === "tmp"
            ? join(cache, location)
            : cache;
        const linkTarget =
          location === "indirect-parent" ? join(target, "nested") : target;
        if (location === "indirect-parent") await mkdir(linkTarget);
        if (location === "indirect-separators")
          await mkdir(join(target, "storage"));
        await symlink(
          linkTarget,
          link,
          process.platform === "win32" ? "junction" : "dir",
        );
        if (
          location === "indirect-root" ||
          location === "indirect-parent" ||
          location === "indirect-separators"
        ) {
          const selection = await fixtures.create("patch-storage-selection-");
          const alias = join(selection, "cache");
          await symlink(
            location === "indirect-parent"
              ? `${cache}${sep}..${sep}storage`
              : location === "indirect-separators"
                ? `${cache}${sep}${sep}storage`
                : cache,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
          git("config", "lfs.storage", alias);
        }
        git("add", ".");
        git("commit", "-m", "Synthetic storage configuration");
        const targetContents = await readdir(target);
        const controls = await capturePatchGitControls(
          repository,
          async (_root, checkout, args, options) =>
            runGitRepositoryCommand("git", args, checkout, options),
          true,
        );
        const canonical = await realpath(target);
        expect(controls).toBeDefined();
        expect(
          controls!.snapshotStoragePaths.every(
            (path) =>
              path !== canonical && !path.startsWith(`${canonical}${sep}`),
          ),
        ).toBe(true);
        expect(
          controls!.readOnlyPaths.every(
            (path) =>
              path !== canonical && !path.startsWith(`${canonical}${sep}`),
          ),
        ).toBe(true);
        expect(await readdir(target)).toEqual(targetContents);
        if (location === "indirect-separators")
          expect(await readdir(join(target, "storage"))).toEqual([]);
        await controls!.validate();
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--json"],
          {
            currentDirectory: repository,
            onRepositoryCommand: runGitRepositoryCommand,
            onCodex: async (_args, output) => {
              await writeFile(join(repository, "app.txt"), "after\n");
              output?.stdout.write("Synthetic patch complete.\n");
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(await readdir(target)).toEqual(targetContents);
        if (location === "indirect-separators")
          expect(await readdir(join(target, "storage"))).toEqual([]);
        const replacement = await fixtures.create("patch-storage-replacement-");
        await rm(link, { recursive: true });
        await symlink(
          replacement,
          link,
          process.platform === "win32" ? "junction" : "dir",
        );
        await expect(controls!.validate()).rejects.toThrow(
          "changed location during the patch",
        );
      },
    );
  }

  for (const location of [
    "external",
    "external-alias",
    "administration-alias",
    "metadata-alias",
    "gitfile-alias",
    "nested-administration",
    "checkout-alias",
    "selected-git-dir",
    "selected-git-dir-trailing",
    "selected-git-dir-separators",
    "selected-common-dir",
  ] as const) {
    test(`preserves selected storage aliases outside checkout data: ${location}`, async () => {
      const repository = await fixtures.create("patch-storage-selected-");
      const external = await fixtures.create("patch-storage-external-");
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic selected storage");
      const linkType = process.platform === "win32" ? "junction" : "dir";
      let directory = repository;
      const environment: NodeJS.ProcessEnv = {};
      let storage = join(repository, ".git", "lfs");
      if (location === "external") {
        storage = external;
        git("config", "lfs.storage", storage);
      } else if (location === "external-alias") {
        const alias = join(external, "alias");
        const target = join(external, "target");
        await mkdir(target);
        await symlink(target, alias, linkType);
        storage = join(alias, "storage");
        git("config", "lfs.storage", storage);
      } else if (location === "administration-alias") {
        await symlink(external, storage, linkType);
      } else if (location === "metadata-alias") {
        const metadata = join(external, "metadata");
        await rename(join(repository, ".git"), metadata);
        await symlink(metadata, join(repository, ".git"), linkType);
      } else if (location === "gitfile-alias") {
        const metadata = join(external, "metadata");
        await rename(join(repository, ".git"), metadata);
        const alias = join(repository, "administration-alias");
        await symlink(metadata, alias, linkType);
        await writeFile(
          join(repository, ".git"),
          "gitdir: administration-alias\n",
        );
        storage = join(alias, "lfs");
        git("config", "lfs.storage", storage);
      } else if (location === "nested-administration") {
        const child = join(repository, "child");
        await mkdir(child);
        const childGit = repositoryGit(child);
        childGit("init", "--initial-branch=main");
        childGit("config", "user.name", "Synthetic User");
        childGit("config", "user.email", "synthetic@example.test");
        await writeFile(join(child, "app.txt"), "child\n");
        childGit("add", ".");
        childGit("commit", "-m", "Synthetic child");
        const metadata = join(repository, ".git", "child-administration");
        await rename(join(child, ".git"), metadata);
        await symlink(metadata, join(child, ".git"), linkType);
        git("add", "child");
        git("commit", "-m", "Synthetic selected child");
        storage = join(child, ".git", "parent-lfs");
        git("config", "lfs.storage", storage);
      } else if (location === "selected-git-dir-separators") {
        const metadata = join(external, "metadata");
        await rename(join(repository, ".git"), metadata);
        const alias = join(repository, "administration-alias");
        await symlink(external, alias, linkType);
        environment["GIT_DIR"] = `${alias}${sep}${sep}metadata`;
        environment["GIT_WORK_TREE"] = repository;
        storage = join(alias, "metadata", "lfs");
        await runGitRepositoryCommand(
          "git",
          ["config", "lfs.storage", storage],
          repository,
          { environment },
        );
      } else if (location === "checkout-alias") {
        directory = join(external, "checkout");
        await symlink(repository, directory, linkType);
      } else {
        const metadata = join(repository, "administration");
        if (location !== "selected-common-dir") {
          await rename(join(repository, ".git"), metadata);
        }
        const alias = join(repository, "administration-alias");
        await symlink(
          location !== "selected-common-dir"
            ? metadata
            : join(repository, ".git"),
          alias,
          linkType,
        );
        environment[
          location !== "selected-common-dir" ? "GIT_DIR" : "GIT_COMMON_DIR"
        ] = location === "selected-git-dir-trailing" ? `${alias}${sep}` : alias;
        environment["GIT_WORK_TREE"] = repository;
        storage = join(alias, "lfs");
      }
      const controls = await capturePatchGitControls(
        directory,
        async (_root, checkout, args, options) =>
          runGitRepositoryCommand("git", args, checkout, {
            ...options,
            environment: { ...environment, ...options?.environment },
          }),
        location !== "selected-git-dir" &&
          location !== "selected-git-dir-trailing" &&
          location !== "selected-git-dir-separators",
        location !== "selected-common-dir",
      );
      expect(controls).toBeDefined();
      const path = await realpath(storage);
      expect(controls!.snapshotStoragePaths).toContain(path);
      expect(controls!.readOnlyPaths).toContain(path);
      for (const name of ["objects", "tmp"])
        expect((await lstat(join(storage, name))).isDirectory()).toBe(true);
      await controls!.validate();
    });
  }

  for (const active of [false, true]) {
    test.skipIf(process.platform === "win32")(
      `requires access to conditional Git includes only when active: ${active}`,
      async () => {
        const root = await fixtures.create("patch-inaccessible-include-");
        const git = repositoryGit(root);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(root, "app.txt"), "before\n");
        git("add", ".");
        git("commit", "-m", "Synthetic inaccessible include baseline");
        const configuration = await fixtures.create("patch-private-config-");
        const blocked = join(configuration, "blocked");
        await mkdir(blocked);
        await writeFile(
          join(blocked, "config"),
          "# Synthetic configuration.\n",
        );
        const global = join(configuration, "global-config");
        const selected = active ? root : join(root, "unrelated-checkout");
        await writeFile(
          global,
          `[includeIf ${JSON.stringify(`gitdir:${selected.split(sep).join("/")}/`)}]\n path = ${JSON.stringify(join(blocked, "config"))}\n`,
        );
        const environment = {
          ...process.env,
          GIT_CONFIG_GLOBAL: global,
          GIT_CONFIG_NOSYSTEM: "1",
          LC_ALL: "C",
        };
        await chmod(blocked, 0o000);
        try {
          const ordinaryGit = () =>
            execFileSync("git", ["status", "--porcelain"], {
              cwd: root,
              env: environment,
              encoding: "utf8",
              stdio: ["ignore", "pipe", "pipe"],
            });
          if (active) expect(ordinaryGit).toThrow("Permission denied");
          else expect(ordinaryGit()).toBe("");
          let launches = 0;
          const outcome = await runWorkflow(
            ["patch", "Synthetic issue", "--json"],
            {
              currentDirectory: root,
              environment,
              onRepositoryCommand: (command, args, cwd, options) =>
                runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: { ...environment, ...options?.environment },
                }),
              onCodex: async (_args, output) => {
                launches++;
                await writeFile(join(root, "app.txt"), "after\n");
                output?.stdout.write("Fixed.\n");
                return 0;
              },
            },
          );
          expect(outcome.exitCode, outcome.stderr).toBe(active ? 2 : 0);
          expect(launches).toBe(active ? 0 : 1);
          if (active) expect(outcome.stderr).toContain("Permission denied");
          expect(await readFile(join(root, "app.txt"), "utf8")).toBe(
            active ? "before\n" : "after\n",
          );
        } finally {
          await chmod(blocked, 0o700);
        }
      },
    );
  }

  test.each([false, true])(
    "expands unknown-user includes only when their Git condition is active: %p",
    async (active) => {
      const root = await fixtures.create("patch-conditional-include-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(root, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic conditional include baseline");
      const selected = active ? root : join(root, "unrelated-checkout");
      await appendFile(
        join(root, ".git/config"),
        `\n[includeIf ${JSON.stringify(`gitdir:${selected.split(sep).join("/")}/`)}]\n path = ~synthetic_missing_patch_user_1251/config\n`,
      );
      if (!active) expect(git("status", "--porcelain")).toBe("");
      let launches = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            launches++;
            await writeFile(join(root, "app.txt"), "after\n");
            output?.stdout.write("Fixed.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(active ? 2 : 0);
      expect(launches).toBe(active ? 0 : 1);
      if (active)
        expect(outcome.stderr).toContain("could not expand include path");
      expect(await readFile(join(root, "app.txt"), "utf8")).toBe(
        active ? "before\n" : "after\n",
      );
    },
  );

  for (const validShadow of [false, true]) {
    test.skipIf(process.platform !== "linux")(
      `does not discover an ignored replacement-character shadow of a raw source path: valid checkout ${validShadow}`,
      async () => {
        const root = await fixtures.create("patch-raw-source-shadow-");
        const git = repositoryGit(root);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(root, "outer.txt"), "before\n");
        const rawDirectory = Buffer.concat([
          Buffer.from(`${root}/source-`),
          Buffer.from([0xff]),
        ]);
        await mkdir(rawDirectory);
        const rawSource = Buffer.concat([rawDirectory, Buffer.from("/app.ts")]);
        await writeFile(rawSource, "raw source\n");
        git("add", ".");
        git("commit", "-m", "Synthetic distinct raw source baseline");
        const shadow = join(root, "source-\ufffd");
        await appendFile(
          join(root, ".git/info/exclude"),
          "\n/source-\ufffd/\n",
        );
        await mkdir(shadow);
        if (validShadow) repositoryGit(shadow)("init", "--initial-branch=main");
        else await writeFile(join(shadow, ".git"), "Synthetic fixture data.\n");
        await writeFile(join(shadow, "app.ts"), "ignored shadow\n");
        const shadowMarker = await realpath(join(shadow, ".git"));
        let launches = 0;
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--json"],
          {
            currentDirectory: root,
            onRepositoryCommand: runGitRepositoryCommand,
            onCodex: async (args, output) => {
              launches++;
              expect(
                patchReadOnlyPaths(args, output?.appServer?.permissions),
              ).not.toContain(shadowMarker);
              await writeFile(join(root, "outer.txt"), "after\n");
              output?.stdout.write("Fixed.\n");
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(launches).toBe(1);
        expect(await readFile(join(root, "outer.txt"), "utf8")).toBe("after\n");
        expect(await readFile(rawSource, "utf8")).toBe("raw source\n");
        expect(await readFile(join(shadow, "app.ts"), "utf8")).toBe(
          "ignored shadow\n",
        );
      },
    );
  }

  test.each([false, true])(
    "preserves workspace settings without activating an unused profile: %p",
    async (configured) => {
      const directory = await fixtures.create("patch-profile-protocol-");
      const protectedPath = join(directory, ".git");
      const previousPath = join(directory, "previous-control");
      const extraRoot = join(directory, "build-cache");
      const inherited = configured
        ? {
            network_access: true,
            writable_roots: [extraRoot],
            exclude_tmpdir_env_var: true,
            exclude_slash_tmp: true,
          }
        : {};
      const policy = {
        type: "workspaceWrite",
        writableRoots: configured ? [extraRoot] : [],
        networkAccess: configured,
        excludeTmpdirEnvVar: configured,
        excludeSlashTmp: configured,
      };
      const source = `
const assert = require("node:assert/strict");
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
let configured = false;
let preflight = false;
let permissionProfile;
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize") {
    assert.equal(request.params.capabilities.experimentalApi, true);
    send({ id: 1, result: {} });
  } else if (request.method === "config/read") {
    assert.equal(request.params.cwd, ${JSON.stringify(directory)});
    assert.equal(request.params.includeLayers, true);
    configured = true;
    send({ id: 4, result: { config: { permissions: { codex_security_patch: { description: null, extends: ":workspace", filesystem: { glob_scan_max_depth: ${configured ? "8" : "null"}, [${JSON.stringify(protectedPath)}]: { ".": "write", "private/**": "deny" }, [${JSON.stringify(previousPath)}]: { ".": "read" } } } }, sandbox_workspace_write: ${JSON.stringify(inherited)} } } });
  } else if (request.method === "thread/start") {
    assert.equal(configured, true);
    const profiles = Object.keys(request.params.config.permissions);
    assert.equal(profiles.length, 1);
    permissionProfile = profiles[0];
    assert.match(permissionProfile, /^codex_security_patch_[a-f0-9-]+$/);
    assert.deepEqual(request.params, { threadSource: "security_remediation", approvalPolicy: "never", sandbox: "workspace-write", config: { default_permissions: permissionProfile, permissions: { [permissionProfile]: { extends: ":workspace", network: { enabled: ${configured} }, workspace_roots: ${JSON.stringify(configured ? { [extraRoot]: true } : {})}, filesystem: { [${JSON.stringify(protectedPath)}]: { ".": "read" }, ...${JSON.stringify(configured ? { ":tmpdir": {}, ":slash_tmp": {} } : {})} } } } } });
    send({ id: 2, result: { thread: { id: "patch-thread" }, sandbox: ${JSON.stringify(policy)} } });
  } else if (request.method === "command/exec") {
    assert.deepEqual(request.params.sandboxPolicy, ${JSON.stringify(policy)});
    assert.equal(Object.hasOwn(request.params, "permissionProfile"), false);
    preflight = true;
    assert.equal(request.params.cwd, ${JSON.stringify(directory)});
    assert.deepEqual(request.params.command, [process.execPath, "-e", ""]);
    send({ id: 5, result: { exitCode: 0, stdout: "", stderr: "" } });
  } else if (request.method === "experimentalFeature/list") {
    send({ id: request.id, result: { data: [{ name: "cli_daybreak", enabled: false }], nextCursor: null } });
  } else if (request.method === "turn/start") {
    assert.equal(preflight, true);
    assert.equal(request.params.threadId, "patch-thread");
    assert.equal(request.params.permissions, permissionProfile);
    assert.equal(Object.hasOwn(request.params, "sandboxPolicy"), false);
    send({ id: 3, result: { turn: { id: "patch-turn" } } });
    send({ method: "item/completed", params: { threadId: "patch-thread", turnId: "patch-turn", item: { type: "agentMessage", text: "Synthetic patch complete." } } });
    send({ method: "turn/completed", params: { threadId: "patch-thread", turn: { id: "patch-turn", status: "completed" } } });
  }
});
`;
      const stdout = capture();
      const stderr = capture();
      expect(
        await runCodexSkillCommand(
          ["-e", source],
          {
            command: "patch",
            stdout: stdout.stream,
            stderr: stderr.stream,
            appServer: {
              directory,
              prompt: "Fix the synthetic issue.",
              threadSource: "security_remediation",
              permissions: {
                name: "codex_security_patch",
                readOnlyPaths: [protectedPath],
              },
            },
          },
          { command: process.execPath },
          { PATH: process.env["PATH"] },
        ),
      ).toBe(0);
      expect(stdout.text()).toBe("Synthetic patch complete.\n");
      expect(stderr.text()).toBe("");
    },
  );

  test.each([
    ["new", 0],
    ["new", 1],
    ["new", 130],
    ["recursive", 0],
    ["untracked", 0],
    ["replacement", 0],
  ] as const)(
    "checks %s Git control state before bookkeeping after turn exit %d",
    async (mode, status) => {
      const root = await fixtures.create("patch-git-administration-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const nestedPath =
        mode === "recursive"
          ? "nested/child"
          : mode === "untracked"
            ? "parent/nested"
            : "nested";
      const nested = join(root, nestedPath);
      await mkdir(nested, { recursive: true });
      const child = repositoryGit(nested);
      child("init", "--initial-branch=main");
      child("config", "user.name", "Synthetic User");
      child("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.txt"), "baseline\n");
      child("add", ".");
      child("commit", "-m", "Synthetic child baseline");
      const revision = child("rev-parse", "HEAD");
      const metadata = join(root, "data", "metadata");
      await mkdir(join(root, "data"));
      await rename(join(nested, ".git"), metadata);
      git(
        "--git-dir",
        metadata,
        "config",
        "core.worktree",
        `../../${nestedPath}`,
      );
      git(
        "--git-dir",
        metadata,
        "config",
        "core.hooksPath",
        `${relative(nested, metadata).split(sep).join("/")}/hooks`,
      );
      await writeFile(
        join(metadata, "hooks", "post-index-change"),
        `#!/bin/sh\nprintf 'synthetic-hook\\n' >> ${relative(nested, root).split(sep).join("/")}/.git/hook-ran\n`,
        { mode: 0o755 },
      );
      await rm(join(nested, "app.txt"));
      await writeFile(join(root, "outer.txt"), "baseline\n");
      git("add", "data", "outer.txt");
      let topRevision = revision;
      if (mode === "recursive") {
        const parent = repositoryGit(join(root, "nested"));
        parent("init", "--initial-branch=main");
        parent("config", "user.name", "Synthetic User");
        parent("config", "user.email", "synthetic@example.test");
        parent(
          "update-index",
          "--add",
          "--cacheinfo",
          `160000,${revision},child`,
        );
        parent("commit", "-m", "Synthetic parent gitlink");
        topRevision = parent("rev-parse", "HEAD");
      }
      if (mode !== "untracked")
        git(
          "update-index",
          "--add",
          "--cacheinfo",
          `160000,${topRevision},nested`,
        );
      git("commit", "-m", "Synthetic metadata as ordinary input files");
      const marker = `${relative(nested, metadata).split(sep).join("/")}`;
      if (mode === "replacement")
        await writeFile(join(nested, ".git"), `gitdir: ${marker}\n`);
      let beforeHooks: Buffer | null = null;
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      let afterTurn = false;
      const bookkeeping: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (args.includes("read-tree") || args.includes("update-index")) {
              if (args.includes("core.hooksPath=/dev/null")) {
                expect(args).toContain("core.fsmonitor=false");
                expect(options?.environment?.["GIT_INDEX_FILE"]).not.toBe(
                  join(root, ".git", "index"),
                );
                expect(options?.environment?.["GIT_INDEX_FILE"]).toBeDefined();
              }
            }
            if (
              afterTurn &&
              !args.includes("core.hooksPath=/dev/null") &&
              args.some((value) =>
                ["add", "read-tree", "update-index", "write-tree"].includes(
                  value,
                ),
              )
            )
              bookkeeping.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (args, output) => {
            expect(
              patchReadOnlyPaths(args, output?.appServer?.permissions),
            ).toContain(await realpath(git("rev-parse", "--absolute-git-dir")));
            beforeHooks = await readFile(join(root, ".git", "hook-ran")).catch(
              () => null,
            );
            if (mode === "replacement") {
              const retired = join(root, "data", "retired");
              await rename(metadata, retired);
              await cp(retired, metadata, { recursive: true });
            }
            await writeFile(join(nested, ".git"), `gitdir: ${marker}\n`);
            await writeFile(join(nested, "app.txt"), "fixed\n");
            await writeFile(join(root, "outer.txt"), "fixed\n");
            if (status !== 0)
              output?.stderr.write(`Synthetic turn exited ${status}.\n`);
            output?.stdout.write("Synthetic patch completed.\n");
            afterTurn = true;
            return status;
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "Git metadata outside the pre-patch administration directories",
      );
      if (status !== 0)
        expect(outcome.stderr).toContain(`Synthetic turn exited ${status}.`);
      expect(bookkeeping).toEqual([]);
      expect(
        await readFile(join(root, ".git", "hook-ran")).catch(() => null),
      ).toEqual(beforeHooks);
      if (mode === "replacement") expect(beforeHooks).not.toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, "outer.txt"), "utf8")).toBe("fixed\n");
    },
  );
  test.each(["hook-files", "scripts", "."])(
    "protects hooks in %s while keeping unrelated source writable",
    async (hookDirectory) => {
      const root = await fixtures.create("patch-referenced-[literal]-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const hooks = join(root, hookDirectory);
      const target = join(root, "hook-target");
      await mkdir(hooks, { recursive: true });
      await writeFile(join(hooks, "source.txt"), "before\n");
      await writeFile(
        target,
        "#!/bin/sh\nprintf 'trusted\\n' >> .git/trusted-hook\n",
        { mode: 0o755 },
      );
      const hook = join(hooks, "post-index-change");
      if (process.platform === "win32") await cp(target, hook);
      else await symlink(relative(hooks, target), hook);
      const configuration = join(root, "patch-config");
      await writeFile(
        configuration,
        `[core]\n hooksPath = ${hookDirectory === "." ? root.split(sep).join("/") : hookDirectory}\n[include]\n path = missing-config\n`,
      );
      git("config", "include.path", "../patch-config");
      await writeFile(join(root, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic trusted hook configuration");
      let before = "";
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (args, output) => {
            const controls = patchReadOnlyPaths(
              args,
              output?.appServer?.permissions,
            );
            for (const path of [
              configuration,
              hook,
              ...(process.platform === "win32" ? [] : [target]),
            ])
              expect(controls).toContain(await realpath(path));
            expect(controls).not.toContain(
              join(await realpath(root), "missing-config"),
            );
            expect(controls).not.toContain(await realpath(root));
            expect(controls).not.toContain(await realpath(hooks));
            expect(controls).not.toContain(
              await realpath(join(hooks, "source.txt")),
            );
            before = await readFile(join(root, ".git", "trusted-hook"), "utf8");
            await writeFile(join(root, "app.txt"), "after\n");
            await writeFile(join(hooks, "source.txt"), "after\n");
            output?.stdout.write("Fixed.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      const after = await readFile(join(root, ".git", "trusted-hook"), "utf8");
      expect(after.startsWith(before)).toBe(true);
      expect(after.length).toBeGreaterThan(before.length);
      expect(await readFile(join(root, "app.txt"), "utf8")).toBe("after\n");
      expect(await readFile(join(hooks, "source.txt"), "utf8")).toBe("after\n");
    },
  );
  test.skipIf(process.platform !== "linux")(
    "checks raw-byte Git markers without rejecting ordinary raw-byte paths",
    async () => {
      for (const marker of [false, true]) {
        const root = await fixtures.create("patch-raw-administration-");
        const git = repositoryGit(root);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(root, "outer.txt"), "before\n");
        const child = join(root, "child");
        await mkdir(child);
        const nested = repositoryGit(child);
        nested("init", "--initial-branch=main");
        nested("config", "user.name", "Synthetic User");
        nested("config", "user.email", "synthetic@example.test");
        await writeFile(join(child, "app.txt"), "before\n");
        nested("add", ".");
        nested("commit", "-m", "Synthetic nested baseline");
        const revision = nested("rev-parse", "HEAD");
        const metadata = join(root, "metadata");
        await rename(join(child, ".git"), metadata);
        git(
          "--git-dir",
          metadata,
          "config",
          "core.hooksPath",
          "../metadata/hooks",
        );
        await writeFile(
          join(metadata, "hooks/post-index-change"),
          "#!/bin/sh\nprintf 'unexpected\\n' >> ../.git/hook-ran\n",
          { mode: 0o755 },
        );
        const name = Buffer.concat([
          Buffer.from("nested-"),
          Buffer.from([0xff]),
        ]);
        const directory = Buffer.concat([Buffer.from(`${root}/`), name]);
        await rename(child, directory);
        git("add", "metadata", "outer.txt");
        if (marker) {
          execFileSync("git", ["update-index", "-z", "--index-info"], {
            cwd: root,
            input: Buffer.concat([
              Buffer.from(`160000 ${revision}\t`),
              name,
              Buffer.from([0]),
            ]),
          });
        } else git("add", "--all");
        git("commit", "-m", "Synthetic raw path baseline");
        let afterTurn = false;
        const bookkeeping: string[][] = [];
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--json"],
          {
            currentDirectory: root,
            onRepositoryCommand: (command, args, cwd, options) => {
              if (args.includes("read-tree") || args.includes("update-index")) {
                if (args.includes("core.hooksPath=/dev/null")) {
                  expect(args).toContain("core.fsmonitor=false");
                  expect(options?.environment?.["GIT_INDEX_FILE"]).not.toBe(
                    join(root, ".git", "index"),
                  );
                  expect(
                    options?.environment?.["GIT_INDEX_FILE"],
                  ).toBeDefined();
                }
              }
              if (
                afterTurn &&
                !args.includes("core.hooksPath=/dev/null") &&
                args.some((value) =>
                  ["add", "read-tree", "update-index", "write-tree"].includes(
                    value,
                  ),
                )
              )
                bookkeeping.push([...args]);
              return runGitRepositoryCommand(command, args, cwd, options);
            },
            onCodex: async (_args, output) => {
              if (marker)
                await writeFile(
                  Buffer.concat([directory, Buffer.from("/.git")]),
                  "gitdir: ../metadata\n",
                );
              await writeFile(
                Buffer.concat([directory, Buffer.from("/app.txt")]),
                "after\n",
              );
              await writeFile(join(root, "outer.txt"), "after\n");
              output?.stdout.write("Fixed.\n");
              afterTurn = true;
              return 0;
            },
          },
        );
        if (marker) {
          expect(outcome.exitCode).toBe(2);
          expect(outcome.stderr).toContain("checkout path is not valid UTF-8");
          expect(bookkeeping).toEqual([]);
        } else expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(
          await readFile(join(root, ".git", "hook-ran")).catch(() => null),
        ).toBeNull();
        expect(
          await readFile(
            Buffer.concat([directory, Buffer.from("/app.txt")]),
            "utf8",
          ),
        ).toBe("after\n");
      }
    },
  );
  test.skipIf(process.platform !== "linux")(
    "keeps unrelated raw-byte Git subsection names available for patching",
    async () => {
      const root = await fixtures.create("patch-raw-remote-name-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(root, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic raw subsection baseline");
      await appendFile(
        join(root, ".git", "config"),
        Buffer.concat([
          Buffer.from('\n[remote "unrelated-'),
          Buffer.from([0xff]),
          Buffer.from('"]\n url = https://example.test/synthetic.git\n'),
        ]),
      );
      let launches = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            launches++;
            await writeFile(join(root, "app.txt"), "after\n");
            output?.stdout.write("Fixed.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(await readFile(join(root, "app.txt"), "utf8")).toBe("after\n");
    },
  );
  for (const reference of [
    "include",
    "hooks",
    "gitfile",
    "commondir",
  ] as const) {
    for (const raw of [false, true]) {
      test.skipIf(raw && process.platform !== "linux")(
        `checks ${raw ? "raw-byte" : "literal replacement-character"} ${reference} control references before patch launch`,
        async () => {
          const root = await fixtures.create("patch-control-reference-");
          const git = repositoryGit(root);
          git("init", "--initial-branch=main");
          git("config", "user.name", "Synthetic User");
          git("config", "user.email", "synthetic@example.test");
          await writeFile(join(root, "app.txt"), "before\n");
          git("add", ".");
          git("commit", "-m", "Synthetic control reference baseline");
          const name = Buffer.concat([
            Buffer.from("control-"),
            raw ? Buffer.from([0xff]) : Buffer.from("\ufffd"),
          ]);
          const path = Buffer.concat([Buffer.from(`${root}${sep}`), name]);
          const metadata = join(root, ".git");
          let expectedControl = path;
          if (reference === "include") {
            await writeFile(path, "# Synthetic included configuration.\n");
            await appendFile(
              join(metadata, "config"),
              Buffer.concat([
                Buffer.from("\n[include]\n path = ../"),
                name,
                Buffer.from("\n"),
              ]),
            );
          } else if (reference === "hooks") {
            await mkdir(path);
            expectedControl = Buffer.concat([
              path,
              Buffer.from(`${sep}post-index-change`),
            ]);
            await writeFile(expectedControl, "#!/bin/sh\nexit 0\n", {
              mode: 0o755,
            });
            await appendFile(
              join(metadata, "config"),
              Buffer.concat([
                Buffer.from("\n[core]\n hooksPath = "),
                name,
                Buffer.from("\n"),
              ]),
            );
          } else {
            const head = await readFile(join(metadata, "HEAD"));
            const index = await readFile(join(metadata, "index"));
            await rename(metadata, path);
            if (reference === "gitfile") {
              await writeFile(
                metadata,
                Buffer.concat([
                  Buffer.from("gitdir: "),
                  name,
                  Buffer.from("\n"),
                ]),
              );
            } else {
              await mkdir(metadata);
              await writeFile(join(metadata, "HEAD"), head);
              await writeFile(join(metadata, "index"), index);
              await writeFile(
                join(metadata, "commondir"),
                Buffer.concat([Buffer.from("../"), name, Buffer.from("\n")]),
              );
            }
          }
          let launches = 0;
          const outcome = await runWorkflow(
            ["patch", "Synthetic issue", "--json"],
            {
              currentDirectory: root,
              onRepositoryCommand: runGitRepositoryCommand,
              onCodex: async (args, output) => {
                launches++;
                if (!raw) {
                  expect(
                    patchReadOnlyPaths(args, output?.appServer?.permissions),
                  ).toContain(await realpath(expectedControl.toString("utf8")));
                }
                await writeFile(join(root, "app.txt"), "after\n");
                output?.stdout.write("Fixed.\n");
                return 0;
              },
            },
          );
          if (raw) {
            expect(outcome.exitCode, outcome.stderr).toBe(2);
            expect(outcome.stderr).toContain("not valid UTF-8");
            expect(launches).toBe(0);
            expect(await readFile(join(root, "app.txt"), "utf8")).toBe(
              "before\n",
            );
          } else {
            expect(outcome.exitCode, outcome.stderr).toBe(0);
            expect(launches).toBe(1);
            expect(await readFile(join(root, "app.txt"), "utf8")).toBe(
              "after\n",
            );
          }
        },
      );
    }
  }

  test.skipIf(process.platform === "win32")(
    "retains literal Unicode and quoted bytes in trusted nested checkout names",
    async () => {
      const root = await fixtures.create("patch-quoted-administration-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const child = join(root, "nested-\ufffd-é-\\377-tail");
      await mkdir(child);
      const nested = repositoryGit(child);
      nested("init", "--initial-branch=main");
      nested("config", "user.name", "Synthetic User");
      nested("config", "user.email", "synthetic@example.test");
      await writeFile(join(child, "app.txt"), "before\n");
      nested("add", ".");
      nested("commit", "-m", "Synthetic quoted checkout");
      git("add", ".");
      git("commit", "-m", "Synthetic parent");
      const bundle = await fixtures.create("patch-quoted-node-");
      const source = `
        import { execFileSync } from "node:child_process";
        import { realpath, writeFile } from "node:fs/promises";
        import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(bundle))};
        const root = ${JSON.stringify(root)};
        const child = ${JSON.stringify(child)};
        const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], {cwd: repository, input: options?.input, env: { ...process.env, ...(options?.indexFile === undefined ? {} : {GIT_INDEX_FILE: options.indexFile}) }}).toString(options?.encoding ?? "utf8"), true);
        await writeFile(child + "/app.txt", "after\\n");
        await controls.validate();
        process.stdout.write(JSON.stringify({ paths: controls.readOnlyPaths, expected: await realpath(child + "/.git") }));
      `;
      const protectedPaths = JSON.parse(
        execFileSync("node", ["--input-type=module", "-e", source], {
          encoding: "utf8",
        }),
      ) as { paths: string[]; expected: string };
      expect(protectedPaths.paths).toContain(protectedPaths.expected);
      expect(await readFile(join(child, "app.txt"), "utf8")).toBe("after\n");
    },
  );
  test("keeps directory patching available with translated Git diagnostics", async () => {
    const root = await fixtures.create("patch-translated-git-");
    await writeFile(join(root, "app.txt"), "before\n");
    const environment = {
      ...process.env,
      LANG: "de_DE.UTF-8",
      LANGUAGE: "de",
      LC_ALL: "de_DE.UTF-8",
    };
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      environment,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (args.includes("--show-toplevel"))
          expect(options?.environment?.["LC_ALL"]).toBe("C");
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(root, "app.txt"), "after\n");
        output?.stdout.write("Fixed.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(environment.LC_ALL).toBe("de_DE.UTF-8");
    expect(await readFile(join(root, "app.txt"), "utf8")).toBe("after\n");
  });
  test.each(["ordinary", "hook", "configuration"])(
    "checks newly created Git references while allowing ordinary source: %s",
    async (change) => {
      const root = await fixtures.create("patch-absent-references-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "core.hooksPath", "hooks");
      git("config", "include.path", "../missing-config");
      await writeFile(join(root, "app.txt"), "before\n");
      git("add", ".");
      git("commit", "-m", "Synthetic absent references");
      const index = await readFile(join(root, ".git/index"));
      let afterTurn = false;
      const laterCommands: string[][] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (afterTurn) laterCommands.push([...args]);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            await mkdir(join(root, "hooks"));
            await writeFile(join(root, "hooks/source.ts"), "fixed\n");
            await writeFile(join(root, "app.txt"), "after\n");
            if (change === "hook")
              await writeFile(
                join(root, "hooks/post-index-change"),
                "#!/bin/sh\nprintf unexpected > .git/hook-ran\n",
                { mode: 0o755 },
              );
            if (change === "configuration")
              await writeFile(
                join(root, "missing-config"),
                "[core]\n hooksPath = hooks\n",
              );
            output?.stdout.write("Fixed.\n");
            afterTurn = true;
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        change === "ordinary" ? 0 : 2,
      );
      if (change !== "ordinary") {
        expect(outcome.stderr).toContain(
          change === "hook"
            ? "Git hook became accessible"
            : "Git configuration or hooks changed location",
        );
        expect(laterCommands).toEqual([]);
      }
      expect(
        await readFile(join(root, ".git/hook-ran")).catch(() => null),
      ).toBeNull();
      expect(await readFile(join(root, ".git/index"))).toEqual(index);
      expect(await readFile(join(root, "hooks/source.ts"), "utf8")).toBe(
        "fixed\n",
      );
    },
  );
});
