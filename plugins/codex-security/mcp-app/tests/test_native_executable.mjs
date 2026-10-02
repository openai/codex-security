import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [
    fileURLToPath(new URL("../src/native-executable.ts", import.meta.url)),
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { resolveCodexPath, resolveTrustedCodex, snapshotNativeEnvironment } =
  await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
const temporaryRoots = [];
try {
  await testCodexHomePathsStayBoundToOriginalDirectory();
  await testExplicitAndPathExecutables();
  if (process.platform === "win32") {
    await testWindowsWorkerEnvironmentPreservesMixedCaseKeys();
    await testWindowsLauncherSkipsExtensionlessNpmShim();
  }
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: "C:\\Tools\\codex.exe" }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  assert.equal(
    resolveCodexPath({ codex_cli_path: "C:\\Tools\\codex.exe" }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  const originalCwd = path.join(process.cwd(), "fixture-root");
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: "fixture/codex" }, "linux", originalCwd),
    path.join(originalCwd, "fixture/codex"),
  );
} finally {
  await Promise.all(
    temporaryRoots.map((root) => rm(root, { recursive: true, force: true })),
  );
}

async function testExplicitAndPathExecutables() {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-executable-"));
  temporaryRoots.push(root);
  const repository = path.join(root, "repository");
  const bin = path.join(repository, "bin");
  const external = path.join(root, "external");
  await Promise.all([mkdir(bin, { recursive: true }), mkdir(external)]);
  const name = process.platform === "win32" ? "codex.exe" : "codex";
  const selected = path.join(external, name);
  await Promise.all([
    copyFile(process.execPath, path.join(bin, name)),
    copyFile(process.execPath, selected),
  ]);
  for (const configured of [
    undefined,
    "codex",
    selected,
    `~/external/${name}`,
    `~\\external\\${name}`,
  ]) {
    const environment = {
      HOME: root,
      USERPROFILE: root,
      PATH: [bin, external].join(path.delimiter),
      ...(configured === undefined ? {} : { CODEX_CLI_PATH: configured }),
    };
    const trusted = await resolveTrustedCodex(environment, repository);
    assert.equal(await realpath(trusted.executable), await realpath(selected));
    assert.equal(trusted.environment.PATH, await realpath(external));
  }
  assert.equal(
    await resolveTrustedCodex(
      { CODEX_CLI_PATH: path.join(bin, name) },
      repository,
    ),
    null,
  );
}

async function testCodexHomePathsStayBoundToOriginalDirectory() {
  if (process.platform === "win32") {
    assert.equal(
      resolveCodexPath(
        { CODEX_CLI_PATH: "\\Tools\\codex.exe" },
        "win32",
        "C:\\original\\cwd",
      ),
      "C:\\Tools\\codex.exe",
    );
    assert.equal(
      resolveCodexPath(
        { CODEX_CLI_PATH: "/Tools/codex.exe" },
        "win32",
        "D:\\original\\cwd",
      ),
      "D:\\Tools\\codex.exe",
    );
  }

  // Root-relative Windows paths use the cwd drive, which can differ from TEMP.
  const root = await mkdtemp(
    path.join(
      process.platform === "win32" ? process.cwd() : tmpdir(),
      "codex-security-native-home-",
    ),
  );
  temporaryRoots.push(root);
  const target = path.join(root, "target", "nested");
  await Promise.all([
    mkdir(target, { recursive: true }),
    mkdir(path.join(root, "target", "home"), { recursive: true }),
    mkdir(path.join(root, "home")),
  ]);
  await symlink(target, path.join(root, "link"), "junction");

  const previousCodexHome = process.env.CODEX_HOME;
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.env.HOME = root;
  process.env.USERPROFILE = root;
  try {
    const homes = [
      `${root}${path.sep}link${path.sep}..${path.sep}home`,
      `${path.relative(process.cwd(), root)}${path.sep}link${path.sep}..${path.sep}home`,
      ...(process.platform === "win32"
        ? [`\\${path.relative(path.parse(root).root, root)}\\link\\..\\home`]
        : []),
    ];
    for (const [home, expectedPath] of [
      ...homes.map((home) => [home, home]),
      [" ~/target/home ", path.join(root, "target", "home")],
      [`  ${path.join(root, "home")}  `, path.join(root, "home")],
    ]) {
      process.env.CODEX_HOME = home;
      const expectedHome = await realpath(expectedPath);
      const environment = await snapshotNativeEnvironment();
      assert.equal(environment.CODEX_HOME, expectedHome);
      assert.equal(process.env.CODEX_HOME, home);
      const childCwd = await realpath(target);
      const child = spawnSync(
        process.execPath,
        [
          "-e",
          [
            "const { realpathSync } = require('node:fs');",
            "process.stdout.write(JSON.stringify({ cwd: process.cwd(), codexHome: process.env.CODEX_HOME, resolvedHome: realpathSync(process.env.CODEX_HOME) }));",
          ].join("\n"),
        ],
        { encoding: "utf8", env: environment, cwd: childCwd },
      );
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0);
      assert.deepEqual(JSON.parse(child.stdout), {
        cwd: childCwd,
        codexHome: expectedHome,
        resolvedHome: expectedHome,
      });
    }
  } finally {
    restoreEnv("CODEX_HOME", previousCodexHome);
    restoreEnv("HOME", previousHome);
    restoreEnv("USERPROFILE", previousUserProfile);
  }
}

async function testWindowsWorkerEnvironmentPreservesMixedCaseKeys() {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-windows-env-")),
  );
  temporaryRoots.push(root);
  const names = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_MANAGED_PACKAGE_ROOT",
    "LOCALAPPDATA",
  ];
  const previousEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      names.includes(key.toUpperCase()),
    ),
  );
  const values = {
    CODEX_CLI_PATH: path.join(root, "custom-codex.exe"),
    CODEX_HOME: root,
    CODEX_MANAGED_PACKAGE_ROOT: path.join(root, "managed-package"),
    LOCALAPPDATA: path.join(root, "local-app-data"),
  };
  try {
    for (const name of names) delete process.env[name];
    for (const [name, value] of Object.entries(values))
      process.env[name.toLowerCase()] = value;

    const environment = await snapshotNativeEnvironment();
    for (const [name, value] of Object.entries(values)) {
      assert.equal(environment[name], value);
      assert.deepEqual(
        Object.keys(environment).filter((key) => key.toUpperCase() === name),
        [name],
      );
      assert.equal(process.env[name.toLowerCase()], value);
    }
    assert.equal(resolveCodexPath(environment, "win32"), values.CODEX_CLI_PATH);
  } finally {
    for (const name of names) delete process.env[name];
    Object.assign(process.env, previousEnvironment);
  }
}

async function testWindowsLauncherSkipsExtensionlessNpmShim() {
  const root = await mkdtemp(
    path.join(tmpdir(), "codex-security-windows-launcher-"),
  );
  temporaryRoots.push(root);
  const shimDirectory = path.join(root, "npm-shims");
  const binaryDirectory = path.join(root, "native-bin");
  await Promise.all([mkdir(shimDirectory), mkdir(binaryDirectory)]);
  await writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n");
  await copyFile(process.execPath, path.join(binaryDirectory, "codex.exe"));

  const brokenEnvironment = windowsLauncherEnvironment(shimDirectory);
  const broken = spawnSync("codex", ["--version"], {
    encoding: "utf8",
    env: brokenEnvironment,
  });
  assert.equal(["ENOENT", "EPERM"].includes(broken.error?.code), true);

  const environment = windowsLauncherEnvironment(
    shimDirectory,
    binaryDirectory,
  );
  const fixed = spawnSync(
    resolveCodexPath(environment, "win32"),
    ["--version"],
    {
      encoding: "utf8",
      env: environment,
    },
  );
  assert.equal(fixed.error, undefined);
  assert.equal(fixed.status, 0);
  assert.equal(fixed.stdout.trim(), process.version);
}

function windowsLauncherEnvironment(...directories) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.toLowerCase() === "path") {
      delete environment[key];
    }
  }
  delete environment.CODEX_CLI_PATH;
  delete environment.CODEX_MANAGED_PACKAGE_ROOT;
  environment.Path = directories.join(path.delimiter);
  return environment;
}

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
