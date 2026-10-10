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
  await testWindowsPackageExecutables("managed");
  await testWindowsPackageExecutables("global");
  await testWindowsAppsRelocatedExecutable();
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

async function testWindowsPackageExecutables(installation) {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-native-package-")),
  );
  temporaryRoots.push(root);
  const repository = path.join(root, "repository");
  const packageDirectory = path.join(root, "npm", "node_modules");
  const shims =
    installation === "managed"
      ? path.join(packageDirectory, ".bin")
      : path.join(root, "npm");
  const packageRoot = path.join(packageDirectory, "@openai", "codex");
  const external = path.join(root, "external");
  await Promise.all([
    mkdir(repository),
    mkdir(shims, { recursive: true }),
    mkdir(packageRoot, { recursive: true }),
    mkdir(external),
  ]);
  await writeFile(
    path.join(packageRoot, "package.json"),
    '{"name":"@openai/codex"}',
  );
  await writeFile(path.join(shims, "codex.cmd"), "@exit /b 1\n");
  const directBinary = path.join(external, "codex.exe");
  await copyFile(process.execPath, directBinary);
  for (const [architecture, target] of [
    ["x64", "x86_64-pc-windows-msvc"],
    ["arm64", "aarch64-pc-windows-msvc"],
  ]) {
    const platformRoot = path.join(
      packageRoot,
      "node_modules",
      "@openai",
      `codex-win32-${architecture}`,
    );
    const binary = path.join(
      platformRoot,
      "vendor",
      target,
      "bin",
      "codex.exe",
    );
    await mkdir(path.dirname(binary), { recursive: true });
    await writeFile(
      path.join(platformRoot, "package.json"),
      JSON.stringify({ name: `@openai/codex-win32-${architecture}` }),
    );
    await copyFile(process.execPath, binary);
    const environment = { Path: [shims, external].join(path.delimiter) };
    if (installation === "managed") {
      environment.codex_managed_package_root = path.relative(root, packageRoot);
      environment.Path = [external, shims].join(path.delimiter);
    }
    const windowsApps = path.join(root, "WindowsApps", "codex.exe");
    for (const configured of [undefined, windowsApps]) {
      const fallback = await resolveTrustedCodex(
        { ...environment, codex_cli_path: configured },
        repository,
        "win32",
        root,
        architecture,
      );
      assert.equal(fallback?.executable, binary);
    }
    const trusted = await resolveTrustedCodex(
      environment,
      repository,
      "win32",
      root,
      architecture,
    );
    assert.equal(trusted?.executable, binary);
    assert.equal(
      resolveCodexPath(environment, "win32", root, architecture),
      binary,
    );
    assert.equal(
      trusted.environment.codex_managed_package_root,
      environment.codex_managed_package_root,
    );
    const child = spawnSync(
      trusted.executable,
      [
        "-e",
        "process.stdout.write(JSON.stringify({version:process.version,packageRoot:process.env.codex_managed_package_root}))",
      ],
      {
        encoding: "utf8",
        env: trusted.environment,
        cwd: repository,
      },
    );
    assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), {
      version: process.version,
      ...(installation === "managed"
        ? { packageRoot: environment.codex_managed_package_root }
        : {}),
    });
    for (const configured of [directBinary, "codex"]) {
      const selected = await resolveTrustedCodex(
        { ...environment, Path: external, codex_cli_path: configured },
        repository,
        "win32",
        root,
        architecture,
      );
      assert.equal(selected?.executable, directBinary);
    }
    assert.equal(
      (
        await resolveTrustedCodex(
          environment,
          packageDirectory,
          "win32",
          root,
          architecture,
        )
      )?.executable,
      directBinary,
    );
  }
}

async function testWindowsAppsRelocatedExecutable() {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "native-relocated-")),
  );
  temporaryRoots.push(root);
  const repository = path.join(root, "repository");
  const localAppData = path.join(root, "local");
  const binary = path.join(
    localAppData,
    "OpenAI",
    "Codex",
    "bin",
    "abcdef0123456789",
    "codex.exe",
  );
  await mkdir(repository);
  await mkdir(path.dirname(binary), { recursive: true });
  await copyFile(process.execPath, binary);
  const environment = {
    Path: "",
    localappdata: localAppData,
    codex_cli_path: path.join(root, "WindowsApps", "codex.exe"),
  };
  const trusted = await resolveTrustedCodex(
    environment,
    repository,
    "win32",
    root,
  );
  assert.equal(trusted?.executable, binary);
  const child = spawnSync(
    trusted.executable,
    ["-e", "process.stdout.write(process.version)"],
    {
      cwd: repository,
      env: trusted.environment,
      encoding: "utf8",
    },
  );
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, process.version);
  assert.equal(
    await resolveTrustedCodex(environment, localAppData, "win32", root),
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
    const literalHome = path.join(root, "literal home ");
    if (process.platform !== "win32") await mkdir(literalHome);
    for (const [home, expectedPath] of [
      ...homes.map((home) => [home, home]),
      ["~/target/home", path.join(root, "target", "home")],
      ...(process.platform === "win32" ? [] : [[literalHome, literalHome]]),
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
    const canonicalRoot = await realpath(root);
    for (const [home, expectedHome] of [
      [
        path.join(root, "missing", "home"),
        path.join(canonicalRoot, "missing", "home"),
      ],
      [
        `${root}${path.sep}link${path.sep}..${path.sep}missing${path.sep}home`,
        path.join(canonicalRoot, "target", "missing", "home"),
      ],
      [
        `${root}${path.sep}missing${path.sep}..${path.sep}link${path.sep}..${path.sep}new-home`,
        path.join(canonicalRoot, "target", "new-home"),
      ],
    ]) {
      process.env.CODEX_HOME = home;
      const environment = await snapshotNativeEnvironment();
      assert.equal(environment.CODEX_HOME, expectedHome);
      assert.equal(process.env.CODEX_HOME, home);
      await assert.rejects(realpath(expectedHome), { code: "ENOENT" });
    }
    const dangling = path.join(root, "dangling");
    await symlink(
      path.join(root, "target", "missing-child"),
      dangling,
      "junction",
    );
    for (const home of [
      `${dangling}${path.sep}..${path.sep}new-home`,
      `${dangling}${path.sep}`,
      path.relative(process.cwd(), path.join(root, "missing", "home")),
      ...(process.platform === "win32"
        ? [`\\${path.relative(path.parse(root).root, root)}\\missing\\home`]
        : []),
    ]) {
      process.env.CODEX_HOME = home;
      await assert.rejects(snapshotNativeEnvironment(), { code: "ENOENT" });
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
