import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  realpath,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, delimiter, dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import {
  inspectTrustedExecutable,
  resolveTrustedExecutable,
  withProtectedExecutableRoots,
} from "../src/trusted-executable.js";
import { bundledCodexSdkEnvironment } from "../src/codex-sdk-environment.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { PYTHON } from "./support/security-policy.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "trusted-executable-",
);

afterEach(cleanup);

async function resolveWindowsExecutable(
  candidate: string,
  path: string,
  protectedRoot: string,
  campaign = false,
): ReturnType<typeof resolveTrustedExecutable> {
  if (process.platform === "win32") {
    const run = () =>
      resolveTrustedExecutable(
        candidate,
        { Path: path, KEEP: "ok" },
        protectedRoot,
      );
    return campaign
      ? withProtectedExecutableRoots([protectedRoot], run)
      : run();
  }

  const script = `
    Object.defineProperty(process, "platform", { value: "win32" });
    const { resolveTrustedExecutable, withProtectedExecutableRoots } = await import(process.argv[1]);
    const run = () => resolveTrustedExecutable(
      process.argv[2],
      { Path: process.argv[3], KEEP: "ok" },
      process.argv[4],
    );
    console.log(JSON.stringify(await (process.argv[5] === "campaign" ? withProtectedExecutableRoots([process.argv[4]], run) : run())));
  `;
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      script,
      fileURLToPath(new URL("../src/trusted-executable.ts", import.meta.url)),
      candidate,
      path,
      protectedRoot,
      campaign ? "campaign" : "",
    ],
    { encoding: "utf8" },
  );
  expect(result.status).toBe(0);
  return JSON.parse(result.stdout) as Awaited<
    ReturnType<typeof resolveTrustedExecutable>
  >;
}

describe("trusted executable resolution", () => {
  test("pins named askpass scripts on the transport PATH outside the worktree", async () => {
    const root = await temporaryDirectory("askpass-");
    const repository = join(root, "repo");
    const trusted = join(root, "helpers");
    await Promise.all([mkdir(repository), mkdir(trusted)]);
    for (const directory of [repository, trusted]) {
      await writeFile(join(directory, "askpass.sh"), "#!/bin/sh\nexit 1\n", {
        mode: 0o700,
      });
    }
    const resolved = await inspectTrustedExecutable(
      "askpass.sh",
      { PATH: [".", relative(repository, trusted)].join(delimiter) },
      repository,
      { gitTransportDirectory: repository },
    );
    expect(resolved.executable).toBe(
      await realpath(join(trusted, "askpass.sh")),
    );
  });

  test.skipIf(process.platform === "win32")(
    "preserves a virtualenv interpreter selected for a Git transport",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repo");
      const venv = join(root, "venv");
      await mkdir(repository);
      expect(
        spawnSync(PYTHON, ["-m", "venv", "--without-pip", "--symlinks", venv])
          .status,
      ).toBe(0);
      const bin = join(venv, "bin");
      const { executable } = await inspectTrustedExecutable(
        join(bin, "python"),
        { PATH: bin },
        repository,
        { gitTransportDirectory: repository },
      );
      expect(executable).not.toBeNull();
      const result = spawnSync(
        executable!,
        ["-c", "import sys; print(sys.prefix)"],
        {
          encoding: "utf8",
        },
      );
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(await realpath(venv));
    },
  );

  test.skipIf(process.platform === "win32")(
    "pins askpass aliases that traverse a worktree link",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repo");
      await mkdir(repository);
      const helper = join(root, "trusted.sh");
      const alias = join(root, "askpass");
      const link = join(repository, "selected-helper");
      await writeFile(helper, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
      await symlink(helper, link);
      await symlink(link, alias);
      for (const name of ["askpass", alias]) {
        const resolved = await inspectTrustedExecutable(
          name,
          { PATH: root },
          repository,
          {
            gitTransportDirectory: repository,
          },
        );
        expect(resolved.executable).toBe(await realpath(helper));
      }
    },
  );

  test("keeps executable search boundaries isolated between concurrent campaigns", async () => {
    const first = await temporaryDirectory();
    const second = await temporaryDirectory();
    const environment = { PATH: [first, second].join(delimiter) };
    const inspectPath = async () =>
      (await inspectTrustedExecutable("git", environment, [])).environment[
        "PATH"
      ];
    expect(
      await Promise.all([
        withProtectedExecutableRoots([first], inspectPath),
        withProtectedExecutableRoots([second], inspectPath),
        inspectPath(),
      ]),
    ).toEqual([second, first, environment.PATH]);
  });

  test.skipIf(process.platform === "win32")(
    "campaigns isolate links into checkouts that materialize later",
    async () => {
      const first = await temporaryDirectory(),
        second = await temporaryDirectory(),
        tools = await temporaryDirectory();
      const alternate = join(dirname(first), basename(first).toUpperCase());
      const firstAlias = existsSync(alternate) ? alternate : first;
      for (const [name, directory] of [
        ["first", firstAlias],
        ["second", second],
      ] as const)
        await symlink(join(directory, "tool"), join(tools, name));
      // One checkout starts missing, the other replaces a link to a trusted tool.
      await symlink("/bin/sh", join(first, "tool"));
      await symlink(join(firstAlias, "tool"), join(tools, "git"));
      const bothInspected = Promise.withResolvers<void>();
      let pendingInspections = 2;
      const environments = await Promise.all(
        [first, second].map((root) =>
          withProtectedExecutableRoots([root], async () => {
            const input = { PATH: tools };
            // Capture both PATHs before either checkout changes a shared link target.
            const command = await inspectTrustedExecutable(
              "git",
              input,
              [],
            ).finally(() => {
              if (--pendingInspections === 0) bothInspected.resolve();
            });
            await bothInspected.promise;
            const path = command.environment["PATH"]!;
            if (root === first) {
              expect(command.executable).toBeNull();
              await unlink(join(root, "tool"));
            }
            await writeFile(join(root, "tool"), "#!/bin/sh\nexit 73\n", {
              mode: 0o700,
            });
            const selected = root === first ? "first" : "second";
            expect(
              spawnSync(selected, [], { env: { PATH: path } }).error,
            ).toMatchObject({ code: "ENOENT" });
            const neighbor = root === first ? "second" : "first";
            expect((await lstat(join(path, neighbor))).isSymbolicLink()).toBe(
              true,
            );
            return path;
          }),
        ),
      );
      expect(environments[0]).not.toBe(environments[1]);
      for (const path of environments) expect(existsSync(path)).toBe(false);
    },
  );

  test("Git transport resolves a relative PATH alias from its own directory inside a campaign", async () => {
    const directory = await temporaryDirectory();
    const checkout = join(directory, "checkout");
    const launcher = join(directory, "operator");
    const tools = join(directory, `tools${delimiter}literal`);
    await Promise.all([mkdir(checkout), mkdir(launcher), mkdir(tools)]);
    await symlink(
      tools,
      join(launcher, "bin"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const executable = join(tools, "proxy-tool");
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const selected = await withProtectedExecutableRoots([checkout], () =>
      inspectTrustedExecutable("proxy-tool", { PATH: "bin" }, checkout, {
        gitTransportDirectory: launcher,
      }),
    );
    expect(selected.executable).toBe(await realpath(executable));
  });

  test("accepts safe relative PATH entries without trusting repository links", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const unsafe = join(repository, "bin");
    const linked = join(root, "linked");
    const trusted = join(root, "trusted");
    const executable = process.platform === "win32" ? "git.exe" : "git";
    await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(unsafe, executable), "untrusted executable"),
      writeFile(join(trusted, executable), "trusted executable"),
    ]);
    await chmod(join(trusted, executable), 0o700);
    await symlink(
      unsafe,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );

    expect(
      await resolveTrustedExecutable(
        "git",
        {
          PATH: ["", unsafe, linked, trusted]
            .map((entry) => (entry ? relative(process.cwd(), entry) : entry))
            .join(delimiter),
          KEEP: "ok",
        },
        repository,
      ),
    ).toEqual({
      executable: join(trusted, executable),
      environment: { KEEP: "ok", PATH: trusted },
    });
  });

  test("preserves independent invocation and worktree protection roots", async () => {
    const root = await temporaryDirectory();
    const invocation = join(root, "invocation");
    const worktree = join(root, "worktree");
    const trusted = join(root, "trusted");
    const linked = join(root, "linked-invocation");
    const executable = process.platform === "win32" ? "git.exe" : "git";
    for (const directory of [invocation, worktree, trusted]) {
      await mkdir(directory);
      await writeFile(
        join(directory, executable),
        "synthetic local executable",
      );
      await chmod(join(directory, executable), 0o700);
    }
    await symlink(
      invocation,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );
    const resolved = await resolveTrustedExecutable(
      "git",
      {
        PATH: [linked, invocation, worktree, trusted].join(delimiter),
        KEEP: "unchanged",
      },
      [worktree, invocation],
    );
    expect(resolved).toEqual({
      executable: join(trusted, executable),
      environment: { PATH: trusted, KEEP: "unchanged" },
    });
  });

  test("sanitizes repository-linked PATH entries when no trusted executable exists", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const repositoryTools = join(repository, "tools");
    const windows = process.platform === "win32";
    const linkedExecutable = join(
      root,
      windows ? "linked-executable" : "tool:installation",
    );
    const safe = join(root, "safe");
    const executable = process.platform === "win32" ? "git.exe" : "git";
    await Promise.all([
      mkdir(repositoryTools, { recursive: true }),
      mkdir(linkedExecutable),
      mkdir(safe),
    ]);
    await writeFile(join(repositoryTools, executable), "#!/bin/sh\nexit 72\n", {
      mode: 0o700,
    });
    await symlink(
      join(repositoryTools, executable),
      join(linkedExecutable, executable),
      "file",
    );

    let entry = linkedExecutable;
    if (!windows) {
      const alias = join(root, "current");
      const version = join(linkedExecutable, "version");
      await mkdir(version);
      await symlink(version, alias);
      entry = alias + "/..";
    }
    const result = await inspectTrustedExecutable(
      "git",
      { PATH: [entry, safe].join(delimiter), KEEP: "ok" },
      repository,
    );
    expect(result).toEqual({
      executable: null,
      environment: { KEEP: "ok", PATH: safe },
    });
    if (!windows) {
      await writeFile(join(safe, executable), "#!/bin/sh\nexit 0\n", {
        mode: 0o700,
      });
      expect(
        spawnSync("/usr/bin/env", ["git"], { env: result.environment }).status,
      ).toBe(0);
    }
  });

  test.skipIf(process.platform === "win32")(
    "prefers the exact POSIX PATH variable over a lowercase path variable",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const decoy = join(root, "decoy");
      const trusted = join(root, "trusted");
      await Promise.all([mkdir(repository), mkdir(decoy), mkdir(trusted)]);
      await Promise.all([
        writeFile(join(decoy, "git"), "decoy executable"),
        writeFile(join(trusted, "git"), "trusted executable"),
      ]);
      await chmod(join(trusted, "git"), 0o700);

      await expect(
        resolveTrustedExecutable(
          "git",
          { path: decoy, PATH: trusted },
          repository,
        ),
      ).resolves.toEqual({
        executable: join(trusted, "git"),
        environment: { PATH: trusted },
      });
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves the invocation name of a trusted symlinked executable",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const trusted = join(root, "trusted");
      const wrapper = join(trusted, "wrapper");
      const git = join(trusted, "git");
      await Promise.all([mkdir(repository), mkdir(trusted)]);
      await writeFile(wrapper, "#!/bin/sh\nprintf '%s\\n' \"$0\"\n");
      await chmod(wrapper, 0o700);
      await symlink(wrapper, git);

      const resolved = await resolveTrustedExecutable(
        "git",
        { PATH: trusted },
        repository,
      );
      expect(resolved).toEqual({
        executable: git,
        environment: { PATH: trusted },
      });
      if (resolved === null) throw new Error("trusted Git was not resolved");

      const result = spawnSync(resolved.executable, [], {
        encoding: "utf8",
        env: resolved.environment,
      });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(git);
    },
  );

  test.skipIf(process.platform === "win32")(
    "canonicalizes aliased parents before preserving explicit launchers",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const repositoryBin = join(repository, "bin");
      const aliasedBin = join(root, "repository-bin-alias");
      const externalBin = join(repository, "external-bin");
      const repositoryAlias = join(root, "repository-alias");
      const trusted = join(root, "trusted");
      const wrapper = join(trusted, "python3");
      const launcher = join(repositoryBin, "python");
      await Promise.all([
        mkdir(repositoryBin, { recursive: true }),
        mkdir(trusted),
      ]);
      await writeFile(wrapper, "#!/bin/sh\nexit 0\n");
      await chmod(wrapper, 0o700);
      await symlink(wrapper, launcher);
      await symlink(repositoryBin, aliasedBin, "dir");
      await symlink(trusted, externalBin, "dir");
      await symlink(repository, repositoryAlias, "dir");

      for (const candidate of [
        launcher,
        join(aliasedBin, "python"),
        join(externalBin, "python3"),
        join(repositoryAlias, "external-bin", "python3"),
      ]) {
        await expect(
          resolveTrustedExecutable(candidate, { PATH: "" }, repository),
        ).resolves.toEqual({ executable: wrapper, environment: { PATH: "" } });
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "Node preserves explicit Python launcher identity through parent traversal",
    async () => {
      const root = await temporaryDirectory();
      const trusted = join(root, "trusted tools");
      const lexical = join(root, "lexical");
      const repository = join(root, "repository");
      const marker = join(root, "selected.txt");
      await Promise.all([
        mkdir(join(trusted, "child"), { recursive: true }),
        mkdir(lexical),
        mkdir(repository),
      ]);
      await symlink(join(trusted, "child"), join(lexical, "linked"), "dir");
      const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;
      for (const [directory, identity] of [
        [trusted, "intended"],
        [lexical, "wrong executable"],
      ]) {
        await writeFile(
          join(directory!, "python"),
          `#!/bin/sh\nprintf '%s' ${quote(identity!)} > ${quote(marker)}\nexec ${quote(Bun.which(PYTHON) ?? PYTHON)} "$@"\n`,
          { mode: 0o755 },
        );
      }
      const candidate = `${lexical}/linked/../python`;
      const runtimePath = join(root, "runtime.mjs");
      const build = spawnSync(
        process.execPath,
        [
          "build",
          fileURLToPath(new URL("../src/runtime.ts", import.meta.url)),
          "--target=node",
          "--format=esm",
          "--outfile",
          runtimePath,
        ],
        { encoding: "utf8" },
      );
      expect(build.status, build.stderr).toBe(0);
      const result = spawnSync(
        "node",
        [
          "--experimental-strip-types",
          "--input-type=module",
          "-e",
          `
      import { readFile, rm, chmod } from "node:fs/promises";
      import { spawnSync } from "node:child_process";
      import assert from "node:assert/strict";
      const { resolveTrustedExecutable } = await import(process.argv[1]);
      const { resolvePluginPython } = await import(process.argv[3]);
      const [candidates, repository, trusted, sibling, marker] = JSON.parse(process.argv[2]);
      for (const candidate of candidates) {
        const resolved = await resolveTrustedExecutable(candidate, { PATH: "" }, repository);
        assert.ok(resolved);
        const child = spawnSync(resolved.executable, ["-I", "-c", "import sys; assert sys.version_info >= (3, 10); print('real-python-ok')"], { env: resolved.environment, encoding: "utf8" });
        assert.equal(child.status, 0, child.stderr);
        assert.equal(child.stdout.trim(), "real-python-ok");
        assert.equal(await readFile(marker, "utf8"), "intended");
        assert.equal(resolved.executable, trusted + "/python");
        for (const candidate of ["~/linked/../python", "~\\\\linked\\\\..\\\\python"]) for (const source of ["configuredPath", "PYTHON"]) {
          const selected = await resolvePluginPython({
            environment: { HOME: sibling.slice(0, -"/python".length), PATH: "", ...(source === "PYTHON" ? { PYTHON: candidate } : {}) },
            ...(source === "configuredPath" ? { configuredPath: candidate } : {}),
            protectedRoot: repository,
          });
          assert.equal(selected, trusted + "/python");
          assert.equal(await readFile(marker, "utf8"), "intended");
        }
        await rm(sibling, { force: true });
      }
      assert.equal(await resolveTrustedExecutable(candidates[0], { PATH: "" }, trusted), null);
      await chmod(trusted + "/python", 0o600);
      assert.equal(await resolveTrustedExecutable(candidates[0], { PATH: "" }, repository), null);
    `,
          new URL("../src/trusted-executable.ts", import.meta.url).href,
          JSON.stringify([
            [
              candidate,
              relative(process.cwd(), lexical) + "/linked/../python",
              candidate,
            ],
            repository,
            trusted,
            join(lexical, "python"),
            marker,
          ]),
          pathToFileURL(runtimePath).href,
        ],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
    },
  );

  test("selects runnable Windows executables ahead of extensionless and batch files", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const second = join(root, "second");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(second)]);
    await Promise.all([
      writeFile(join(first, "git"), "extensionless"),
      writeFile(join(first, "git.cmd"), "batch"),
      writeFile(join(first, "git.bat"), "batch"),
      writeFile(join(second, "git.exe"), "executable"),
      writeFile(join(second, "git.com"), "executable"),
    ]);

    expect(
      await resolveWindowsExecutable(
        "git",
        [first, second].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(second, "git.exe"),
      environment: { KEEP: "ok", PATH: [first, second].join(delimiter) },
    });
  });

  test("accepts a Windows COM executable and rejects batch-only candidates", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const com = join(root, "com");
    const batch = join(root, "batch");
    await Promise.all([mkdir(repository), mkdir(com), mkdir(batch)]);
    await Promise.all([
      writeFile(join(com, "python3.com"), "executable"),
      writeFile(join(batch, "python3"), "extensionless"),
      writeFile(join(batch, "python3.cmd"), "batch"),
      writeFile(join(batch, "python3.bat"), "batch"),
    ]);

    expect(await resolveWindowsExecutable("python3", com, repository)).toEqual({
      executable: join(com, "python3.com"),
      environment: { KEEP: "ok", PATH: com },
    });
    expect(
      await resolveWindowsExecutable("python3", batch, repository),
    ).toBeNull();
  });

  test("resolves already-suffixed Windows executables without adding another extension", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(first, "python.exe.exe"), "wrong executable"),
      writeFile(join(trusted, "python.exe"), "python executable"),
      writeFile(join(trusted, "git.exe"), "git executable"),
      writeFile(join(trusted, "tool.com"), "com executable"),
      writeFile(join(trusted, "script.cmd"), "batch"),
    ]);

    for (const candidate of ["python.exe", "git.exe", "tool.com"]) {
      expect(
        await resolveWindowsExecutable(
          candidate,
          [first, trusted].join(delimiter),
          repository,
        ),
      ).toEqual({
        executable: join(trusted, candidate),
        environment: { KEEP: "ok", PATH: [first, trusted].join(delimiter) },
      });
    }
    expect(
      await resolveWindowsExecutable("script.cmd", trusted, repository),
    ).toBeNull();
  });

  test("resolves extensionless explicit Windows executable paths", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(trusted, "python.exe"), "python executable"),
      writeFile(join(trusted, "python.cmd"), "batch"),
    ]);

    expect(
      await resolveWindowsExecutable(
        join(trusted, "python"),
        trusted,
        repository,
      ),
    ).toEqual({
      executable: await realpath(join(trusted, "python.exe")),
      environment: { KEEP: "ok", PATH: trusted },
    });
    expect(
      await resolveWindowsExecutable(
        join(trusted, "python.cmd"),
        trusted,
        repository,
      ),
    ).toBeNull();
  });

  test("rejects Windows batch targets without requiring a canonical native suffix", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(trusted, "git.cmd"), "batch"),
      writeFile(join(trusted, "tool"), "extensionless"),
    ]);
    await Promise.all([
      symlink(join(trusted, "git.cmd"), join(trusted, "git.exe"), "file"),
      symlink(join(trusted, "tool"), join(trusted, "tool.exe"), "file"),
    ]);

    expect(
      await resolveWindowsExecutable("git", trusted, repository),
    ).toBeNull();
    expect(await resolveWindowsExecutable("tool", trusted, repository)).toEqual(
      {
        executable: join(trusted, "tool.exe"),
        environment: { KEEP: "ok", PATH: trusted },
      },
    );
  });

  test.each(["direct", "relay", "linked parent"])(
    "Windows campaign children exclude %s tool links through a selected source",
    async (route) => {
      const root = await temporaryDirectory();
      const source = join(root, "source"),
        aliases = join(root, "aliases"),
        pending = join(root, "pending"),
        nodeAliases = join(root, "node-aliases"),
        tools = join(root, "tools");
      await Promise.all(
        [source, aliases, pending, nodeAliases, tools].map((path) =>
          mkdir(path),
        ),
      );
      const alternate = join(root, "SOURCE");
      const spelling = existsSync(alternate) ? alternate : source;
      const via = route === "direct" ? spelling : join(root, "via");
      if (route === "linked parent") await symlink(spelling, via, "junction");
      if (route === "relay") {
        await mkdir(via);
        for (const name of ["git.exe", "rg.exe", "node.exe"])
          await symlink(join(spelling, name), join(via, name), "file");
      }
      const node = nodeCommand().command;
      await symlink(node, join(tools, "git.exe"), "file");
      await symlink(node, join(tools, "node.exe"), "file");
      await symlink(node, join(source, "git.exe"), "file");
      await writeFile(join(source, "node.exe"), "checkout-owned executable");
      await symlink(
        join(via, "node.exe"),
        join(nodeAliases, "node.exe"),
        "file",
      );
      await symlink(join(via, "git.exe"), join(aliases, "git.exe"), "file");
      await symlink(join(via, "rg.exe"), join(pending, "rg.com"), "file");
      if (process.platform !== "win32")
        await symlink(join(pending, "rg.com"), join(pending, "rg"));
      const command = await resolveWindowsExecutable(
        "git",
        [pending, aliases, nodeAliases, tools].join(delimiter),
        source,
        true,
      );
      expect(command).toEqual({
        executable: join(tools, "git.exe"),
        environment: { KEEP: "ok", PATH: tools },
      });
      await unlink(join(source, "git.exe"));
      for (const name of ["git.exe", "rg.exe"])
        await writeFile(join(source, name), "checkout-owned executable");
      const environment = bundledCodexSdkEnvironment(
        resolveCodexCommand({}).command,
        {
          PATH: process.env["PATH"] ?? "",
        },
      );
      await symlink(
        Bun.which("rg", { PATH: environment["PATH"] })!,
        join(tools, process.platform === "win32" ? "rg.exe" : "rg"),
        "file",
      );
      const checkout = join(root, "checkout");
      await mkdir(checkout);
      await writeFile(join(checkout, "visible.ts"), "");
      const inventory = spawnSync(
        "node.exe",
        [
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          "generate-in-scope-files",
          "--repo",
          checkout,
          "--scope",
          ".",
          "--out",
          join(root, "inventory.txt"),
        ],
        { env: command!.environment, encoding: "utf8" },
      );
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(inventory.stdout).toContain("Recorded 1 in-scope files.");
    },
  );

  test("removes PATH entries containing repository-linked Windows shims", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const unsafe = join(repository, "node_modules", ".bin");
    const linked = join(root, "linked");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(unsafe, "git.cmd"), "batch"),
      writeFile(join(unsafe, "git"), "extensionless"),
      writeFile(join(trusted, "git.exe"), "executable"),
    ]);
    await symlink(
      unsafe,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );

    expect(
      await resolveWindowsExecutable(
        "git",
        [unsafe, linked, trusted].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(trusted, "git.exe"),
      environment: { KEEP: "ok", PATH: trusted },
    });
  });

  test.skipIf(process.platform !== "win32")(
    "resolves a real Windows executable without trusting PATHEXT, repository junctions, or PATH casing",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const unsafe = join(repository, "node_modules", ".bin");
      const linked = join(root, "linked");
      const executable = await realpath(process.execPath);
      const trusted = await realpath(dirname(executable));
      const candidate = basename(executable);
      const stem = candidate.replace(/\.(?:exe|com)$/iu, "");
      const pathExtensions = ".CMD;.BAT;.COM;.EXE";
      await mkdir(unsafe, { recursive: true });
      await Promise.all([
        writeFile(join(unsafe, candidate), "untrusted executable fixture\n"),
        writeFile(join(unsafe, `${stem}.cmd`), "@echo off\r\nexit /b 1\r\n"),
        writeFile(join(unsafe, `${stem}.bat`), "@echo off\r\nexit /b 1\r\n"),
      ]);
      await symlink(unsafe, linked, "junction");

      await expect(
        resolveTrustedExecutable(
          candidate,
          {
            pAtH: [unsafe, linked, trusted].join(delimiter),
            PATHEXT: pathExtensions,
            KEEP: "ok",
          },
          repository,
        ),
      ).resolves.toEqual({
        executable,
        environment: {
          PATHEXT: pathExtensions,
          KEEP: "ok",
          PATH: trusted,
        },
      });
    },
  );

  test.skipIf(process.platform !== "win32")(
    "resolves executables from quoted Windows PATH entries",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const unsafe = join(repository, "tools");
      const trusted = join(root, "trusted tools");
      await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
      await Promise.all([
        writeFile(join(unsafe, "git.exe"), "untrusted executable"),
        writeFile(join(trusted, "git.exe"), "executable"),
      ]);

      await expect(
        resolveTrustedExecutable(
          "git",
          { Path: [`"${unsafe}"`, `"${trusted}"`].join(delimiter), KEEP: "ok" },
          repository,
        ),
      ).resolves.toEqual({
        executable: join(trusted, "git.exe"),
        environment: { KEEP: "ok", PATH: trusted },
      });
    },
  );
});
