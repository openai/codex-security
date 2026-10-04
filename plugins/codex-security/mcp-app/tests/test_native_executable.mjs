import { captureEnvironment } from "../../../../sdk/typescript/tests-support/process-environment.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join, relative, sep } from "node:path";
import { test } from "node:test";
import { loadSourceModule, privateDirectory } from "./helpers/source.mjs";

const { resolveCodexPath, resolveTrustedCodex, snapshotNativeEnvironment } =
  await loadSourceModule(
    new URL("../src/native-executable.ts", import.meta.url),
  );

test("native resolution uses explicit selection or a trusted PATH installation", async () => {
  const root = await privateDirectory("codex-security-native-path-");
  try {
    const repository = join(root, "repository");
    const external = join(root, "external bin");
    await Promise.all([mkdir(repository), mkdir(external)]);
    const name = process.platform === "win32" ? "codex.exe" : "codex";
    const localExecutable = join(repository, name);
    const executable = join(external, name);
    await Promise.all([
      copyFile(process.execPath, localExecutable),
      copyFile(process.execPath, executable),
    ]);
    const environment = { PATH: [repository, external].join(delimiter) };
    const resolved = await resolveTrustedCodex(environment, repository);
    assert.equal(resolved.executable, executable);
    assert.equal(resolved.environment.PATH, external);
    assert.equal(environment.PATH, [repository, external].join(delimiter));
    assert.equal(
      await resolveTrustedCodex(
        { ...environment, CODEX_CLI_PATH: localExecutable },
        repository,
      ),
      null,
    );
    assert.equal(
      await resolveTrustedCodex(
        { ...environment, CODEX_CLI_PATH: join(root, "missing") },
        repository,
      ),
      null,
    );
    assert.equal(
      (
        await resolveTrustedCodex(
          { ...environment, CODEX_CLI_PATH: executable },
          repository,
        )
      ).executable,
      executable,
    );
    for (const configured of [
      `~/external bin/${name}`,
      `~\\external bin\\${name}`,
    ]) {
      const environment = {
        HOME: root,
        USERPROFILE: root,
        CODEX_CLI_PATH: configured,
      };
      assert.equal(
        (await resolveTrustedCodex(environment, repository))?.executable,
        executable,
      );
      assert.equal(
        await resolveTrustedCodex(
          { ...environment, CODEX_CLI_PATH: `~/repository/${name}` },
          repository,
        ),
        null,
      );
    }
    const child = spawnSync(resolved.executable, ["--version"], {
      encoding: "utf8",
      env: resolved.environment,
    });
    assert.equal(child.status, 0);
    assert.equal(child.stdout.trim(), process.version);
    assert.equal(resolveCodexPath({ CODEX_CLI_PATH: "  " }), "codex");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("native environment binds the original Codex home before child cwd changes", async () => {
  const root = await privateDirectory("codex-security-native-home-");
  const restoreEnvironment = captureEnvironment([
    "CODEX_HOME",
    "HOME",
    "USERPROFILE",
  ]);
  try {
    const nested = join(root, "target", "nested");
    await mkdir(nested, { recursive: true });
    await mkdir(join(root, "target", "home"));
    // Windows resolves junction/.. lexically; POSIX follows the link first.
    await mkdir(join(root, "home"));
    await symlink(nested, join(root, "link"), "junction");
    process.env.HOME = root;
    process.env.USERPROFILE = root;
    const linkedHome = `${relative(process.cwd(), root)}${sep}link${sep}..${sep}home`;
    for (const [home, expectedPath] of [
      [linkedHome, linkedHome],
      [" ~/target/home ", join(root, "target", "home")],
      [`  ${join(root, "home")}  `, join(root, "home")],
    ]) {
      process.env.CODEX_HOME = home;
      const snapshot = await snapshotNativeEnvironment();
      assert.equal(snapshot.CODEX_HOME, await realpath(expectedPath));
      assert.equal(process.env.CODEX_HOME, home);
      const child = spawnSync(
        process.execPath,
        ["-e", "process.stdout.write(process.env.CODEX_HOME)"],
        { env: snapshot, cwd: nested, encoding: "utf8" },
      );
      assert.equal(child.status, 0);
      assert.equal(child.stdout, await realpath(expectedPath));
    }
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "Windows native snapshots normalize mixed-case settings",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await privateDirectory("codex-security-windows-env-");
    const names = ["CODEX_CLI_PATH", "CODEX_HOME", "PATH"];
    const previous = Object.fromEntries(
      Object.entries(process.env).filter(([key]) =>
        names.includes(key.toUpperCase()),
      ),
    );
    const values = {
      CODEX_CLI_PATH: join(root, "codex.exe"),
      CODEX_HOME: root,
      PATH: root,
    };
    try {
      for (const name of names) delete process.env[name];
      for (const [name, value] of Object.entries(values))
        process.env[name.toLowerCase()] = value;
      const snapshot = await snapshotNativeEnvironment();
      for (const [name, value] of Object.entries(values)) {
        assert.equal(snapshot[name], value);
        assert.deepEqual(
          Object.keys(snapshot).filter((key) => key.toUpperCase() === name),
          [name],
        );
        assert.equal(process.env[name.toLowerCase()], value);
      }
      assert.equal(resolveCodexPath(snapshot), values.CODEX_CLI_PATH);
    } finally {
      for (const name of names) delete process.env[name];
      Object.assign(process.env, previous);
      await rm(root, { recursive: true, force: true });
    }
  },
);

test(
  "Windows native resolution skips extensionless npm shims",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await privateDirectory("codex-security-windows-launcher-");
    try {
      const repository = join(root, "repository");
      const shims = join(root, "npm-shims");
      const bin = join(root, "native-bin");
      await Promise.all([mkdir(repository), mkdir(shims), mkdir(bin)]);
      await writeFile(join(shims, "codex"), "#!/bin/sh\nexit 1\n");
      const executable = join(bin, "codex.exe");
      await copyFile(process.execPath, executable);
      const environment = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => !["PATH", "CODEX_CLI_PATH"].includes(name.toUpperCase()),
        ),
      );
      environment.Path = [shims, bin].join(delimiter);
      const trusted = await resolveTrustedCodex(environment, repository);
      assert.equal(trusted.executable, executable);
      const child = spawnSync(trusted.executable, ["--version"], {
        encoding: "utf8",
        env: trusted.environment,
      });
      assert.equal(child.status, 0, child.stderr);
      assert.equal(child.stdout.trim(), process.version);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
