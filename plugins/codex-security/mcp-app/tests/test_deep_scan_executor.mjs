import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const executorSource = new URL("../src/deep-scan/executor.ts", import.meta.url);
const bundle = await build({
  bundle: true,
  define: {
    "import.meta.url": JSON.stringify(executorSource.href)
  },
  stdin: {
    // Test the environment snapshot without adding a production export.
    contents: `${await readFile(executorSource, "utf8")}\nexport { snapshotWorkerEnvironment };`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource)
  },
  format: "esm",
  platform: "node",
  write: false
});
const { CodexSdkWorkerExecutor, resolveCodexPath, snapshotWorkerEnvironment } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);
const errorsBundle = await build({
  bundle: true,
  entryPoints: [fileURLToPath(new URL("../src/deep-scan/errors.ts", import.meta.url))],
  format: "esm",
  platform: "node",
  write: false
});
const { classifyCodexWorkerError } = await import(
  `data:text/javascript;base64,${Buffer.from(errorsBundle.outputFiles[0].contents).toString("base64")}`
);
const temporaryRoots = [];
const previousMarker = process.env.FAKE_CODEX_MARKER;
const trustedParentSandbox = Object.freeze({
  filesystemDenies: []
});
const trustedReadOnlyParentSandbox = Object.freeze({
  filesystemDenies: []
});
const trustedParentSandboxWithDenials = Object.freeze({
  filesystemDenies: [
    "/repo/.env",
    "/repo/**/.secret",
    "/repo/**/*.pem",
    "/repo/.env"
  ],
  globScanMaxDepth: 3
});
const emptyWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: { ":root": "read" },
  network: { enabled: false }
};
const deniedWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny",
    "/repo/**/.secret": "deny",
    "/repo/**/*.pem": "deny",
    glob_scan_max_depth: 3
  },
  network: { enabled: false }
};

try {
  if (process.platform !== "win32") {
    await testMissingParentSandboxFailsBeforeWorkerLaunch();
    await testDisallowedWorkerProfileFailsBeforeWorkerLaunch();
    await testRuntimePermissionProfileFallbackStopsAndDiscards();
    await testWorkerLaunchesWithoutGlobalCodex();
    await testPreflightBindsExecutableAndHomeBeforeChangingCwd();
    await testSdkInvocationAndThreadCapture();
    await testBedrockCredentialsReachWorker();
    await testArtifactServerUsesExtendedStartupTimeout();
    await testZeroSubagentsPreservesHostRestrictions();
    await testSdkResumesExistingThread();
    await testRetryNotificationDoesNotInterruptTurn();
    await testSandboxNamespaceDiagnosticIsSanitized();
    await testOwnedArtifactToolFailureDiagnosticIsSanitized();
    await testStreamTerminationWithoutTerminalEventFails();
    await testCompletedWorkerSettlesWithoutWaitingForProcessExit();
    await testAbortPropagation();
    await testConfigurationFailureIsNonRetryable();
    await testThreadStartConfigurationFailureIsNonRetryable();
    await testPolicyFailuresAreNonRetryable();
    await testRateLimitPolicyFailureRemainsRetryable();
    await testArtifactStartupTimeoutClassification();
  }
  assert.equal(resolveCodexPath({}, "darwin"), path.join(process.cwd(), "codex"));
  assert.equal(resolveCodexPath({}, "linux"), path.join(process.cwd(), "codex"));
  assert.equal(resolveCodexPath({}, "win32"), path.join(process.cwd(), "codex.exe"));
  const absoluteConfiguredPath = path.join(path.parse(process.cwd()).root, "fixture", "codex");
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: ` ${absoluteConfiguredPath} ` }),
    absoluteConfiguredPath
  );
  const originalCwd = path.join(process.cwd(), "fixture-root");
  const relativeConfiguredPath = path.join("fixtures", "codex");
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: relativeConfiguredPath }, "linux", process.arch, originalCwd),
    path.join(originalCwd, "fixtures", "codex")
  );
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: relativeConfiguredPath }, "win32", process.arch, originalCwd),
    path.join(originalCwd, "fixtures", "codex")
  );
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: " C:\\Tools\\codex.exe " }, "win32"),
    "C:\\Tools\\codex.exe"
  );
  assert.equal(
    resolveCodexPath({ codex_cli_path: " C:\\Tools\\codex.exe " }, "win32"),
    "C:\\Tools\\codex.exe"
  );
  assert.equal(
    resolveCodexPath({ codex_cli_path: "/ignored/codex" }, "linux", process.arch, originalCwd),
    path.join(originalCwd, "codex")
  );
  testSpawnPermissionErrorsAreNonRetryable();
  testTextualMissingPathErrorsAreNonRetryable();
  await testWindowsAppsCodexFallsBackToRelocatedBinary();
  await testWindowsNpmPackageResolution();
  await testWindowsNpmPackageResolution("managed");
  if (process.platform === "win32") {
    await testWindowsLongExecutableLaunches();
    await testWindowsRootRelativePathsStayBoundToOriginalDrive();
    await testWindowsWorkerEnvironmentPreservesMixedCaseKeys();
    await testWindowsLauncherSkipsExtensionlessNpmShim();
  }
} finally {
  restoreEnv("FAKE_CODEX_MARKER", previousMarker);
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}

function testSpawnPermissionErrorsAreNonRetryable() {
  for (const code of ["ENOENT", "EACCES", "ENOEXEC", "EPERM"]) {
    const original = Object.assign(new Error(`spawn codex ${code}`), { code });
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified.name, "DeepScanNonRetryableError");
    assert.equal(classified.cause, original);
  }
}

function testTextualMissingPathErrorsAreNonRetryable() {
  for (const diagnostic of [
    "Error: No such file or directory (os error 2)",
    "Error: The system cannot find the file specified. (os error 2)"
  ]) {
    const original = new Error([
      "Codex Exec exited with code 1:",
      diagnostic
    ].join("\n"));
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified.name, "DeepScanNonRetryableError");
    assert.equal(classified.cause, original);
  }
}

async function testWindowsRootRelativePathsStayBoundToOriginalDrive() {
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: "\\Tools\\codex.exe" }, "win32", process.arch, "C:\\original\\cwd"),
    "C:\\Tools\\codex.exe"
  );
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: "/Tools/codex.exe" }, "win32", process.arch, "D:\\original\\cwd"),
    "D:\\Tools\\codex.exe"
  );

  const root = await mkdtemp(path.join(tmpdir(), "codex-security-windows-home-"));
  temporaryRoots.push(root);
  const target = path.join(root, "target", "nested");
  await Promise.all([
    mkdir(target, { recursive: true }),
    mkdir(path.join(root, "target", "home"), { recursive: true }),
    mkdir(path.join(root, "home"))
  ]);
  await symlink(target, path.join(root, "link"), "junction");

  const previousCwd = process.cwd();
  const previousCodexHome = process.env.CODEX_HOME;
  try {
    process.chdir(root);
    const rootRelativeHome = `\\${path.relative(path.parse(root).root, root)}\\link\\..\\home`;
    process.env.CODEX_HOME = rootRelativeHome;
    const expectedHome = await realpath(rootRelativeHome);
    const environment = await snapshotWorkerEnvironment();
    assert.equal(environment.CODEX_HOME, expectedHome);
    assert.equal(process.env.CODEX_HOME, rootRelativeHome);
    const childCwd = await realpath(target);
    const child = spawnSync(process.execPath, ["-e", [
      "const { realpathSync } = require('node:fs');",
      "process.stdout.write(JSON.stringify({ cwd: process.cwd(), codexHome: process.env.CODEX_HOME, resolvedHome: realpathSync(process.env.CODEX_HOME) }));"
    ].join("\n")], { encoding: "utf8", env: environment, cwd: childCwd });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0);
    assert.deepEqual(JSON.parse(child.stdout), {
      cwd: childCwd,
      codexHome: expectedHome,
      resolvedHome: expectedHome
    });
  } finally {
    process.chdir(previousCwd);
    restoreEnv("CODEX_HOME", previousCodexHome);
  }
}

async function testWindowsLongExecutableLaunches() {
  const fixture = await fakeCodexFixture();
  const executable = path.join(
    fixture.root,
    ...Array(10).fill("nested executable directory"),
    "node.exe"
  );
  const promptPath = path.join(fixture.root, "prompt.md");
  const workingDirectory = path.join(fixture.root, "artifacts");
  const codexHome = path.join(fixture.root, "codex-home");
  await Promise.all([
    mkdir(path.dirname(executable), { recursive: true }),
    mkdir(workingDirectory),
    mkdir(codexHome),
    writeFile(promptPath, "fixture long executable worker\n")
  ]);
  await copyFile(process.execPath, executable);
  assert.ok(executable.length > 260);
  const previousCodexPath = process.env.CODEX_CLI_PATH;
  const previousCodexHome = process.env.CODEX_HOME;
  const originalSpawn = childProcess.spawn;
  const launchedCommands = [];
  const children = [];
  childProcess.spawn = (command, args, options) => {
    if (command !== executable && command !== path.toNamespacedPath(executable)) {
      return originalSpawn(command, args, options);
    }
    // Keep the production executable argument intact at Node's Windows spawn boundary.
    launchedCommands.push(command);
    const child = originalSpawn(command, [fixture.executablePath, ...args], options);
    children.push(child);
    return child;
  };
  syncBuiltinESMExports();
  try {
    process.env.CODEX_HOME = codexHome;
    for (const configured of [executable, path.toNamespacedPath(executable)]) {
      process.env.CODEX_CLI_PATH = configured;
      assert.equal((await snapshotWorkerEnvironment()).CODEX_CLI_PATH, configured);
      const result = await new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      });
      assert.equal(result.threadId, "fixture-thread-id");
      assert.equal(result.finalResponse, "fixture final response");
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assert.deepEqual(invocation.argv.slice(0, 2), ["exec", "--experimental-json"]);
      assertReadOnlyWorkerPolicy(invocation.argv);
      assert.equal(invocation.codexHome, await realpath(codexHome));
      const preflight = JSON.parse(await readFile(fixture.preflightMarkerPath, "utf8"));
      assert.deepEqual(preflight.requests.map((request) => request.method), [
        "config/read", "permissionProfile/list"
      ]);
      assert.equal(process.env.CODEX_CLI_PATH, configured);
    }
    assert.deepEqual(launchedCommands, Array(4).fill(path.toNamespacedPath(executable)));
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    // The SDK removes child listeners when its event iterator closes.
    await Promise.all(children.map((child) => {
      if (child.stdout.closed && child.stderr.closed
        && (child.exitCode !== null || child.signalCode !== null)) return;
      return new Promise((resolve) => {
        child.once("close", resolve);
        if (child.exitCode === null && child.signalCode === null) child.kill();
      });
    }));
    restoreEnv("CODEX_CLI_PATH", previousCodexPath);
    restoreEnv("CODEX_HOME", previousCodexHome);
  }
}

async function testWindowsWorkerEnvironmentPreservesMixedCaseKeys() {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-windows-env-"));
  temporaryRoots.push(root);
  const names = ["CODEX_CLI_PATH", "CODEX_HOME", "CODEX_MANAGED_PACKAGE_ROOT", "LOCALAPPDATA"];
  const previousEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => names.includes(key.toUpperCase()))
  );
  const values = {
    CODEX_CLI_PATH: path.join(root, "custom-codex.exe"),
    CODEX_HOME: root,
    CODEX_MANAGED_PACKAGE_ROOT: path.join(root, "managed-package"),
    LOCALAPPDATA: path.join(root, "local-app-data")
  };
  try {
    for (const name of names) delete process.env[name];
    for (const [name, value] of Object.entries(values)) process.env[name.toLowerCase()] = value;

    const environment = await snapshotWorkerEnvironment();
    for (const [name, value] of Object.entries(values)) {
      assert.equal(environment[name], value);
      assert.deepEqual(Object.keys(environment).filter((key) => key.toUpperCase() === name), [name]);
      assert.equal(process.env[name.toLowerCase()], value);
    }
    assert.equal(resolveCodexPath(environment, "win32"), values.CODEX_CLI_PATH);
  } finally {
    for (const name of names) delete process.env[name];
    Object.assign(process.env, previousEnvironment);
  }
}

async function testWindowsAppsCodexFallsBackToRelocatedBinary() {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-windows-cache-"));
  temporaryRoots.push(root);
  const localAppData = path.join(root, "LocalAppData");
  const olderBinary = path.join(localAppData, "OpenAI", "Codex", "bin", "11111111", "codex.exe");
  const currentBinary = path.join(localAppData, "OpenAI", "Codex", "bin", "22222222", "codex.exe");
  const emptyBinary = path.join(localAppData, "OpenAI", "Codex", "bin", "33333333", "codex.exe");
  const protectedDirectory = path.join(root, "WindowsApps", "OpenAI.Codex_fixture", "resources");
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetTriple = architecture === "arm64"
    ? "aarch64-pc-windows-msvc"
    : "x86_64-pc-windows-msvc";
  const managedPackage = path.join(protectedDirectory, "node_modules", "@openai", "codex");
  const platformPackage = path.join(managedPackage, "node_modules", "@openai", `codex-win32-${architecture}`);
  const protectedPackageBinary = path.join(platformPackage, "vendor", targetTriple, "bin", "codex.exe");
  await Promise.all([
    mkdir(path.dirname(olderBinary), { recursive: true }),
    mkdir(path.dirname(currentBinary), { recursive: true }),
    mkdir(path.dirname(emptyBinary), { recursive: true }),
    mkdir(path.dirname(protectedPackageBinary), { recursive: true })
  ]);
  await Promise.all([
    copyFile(process.execPath, olderBinary),
    copyFile(process.execPath, currentBinary),
    writeFile(emptyBinary, ""),
    writeFile(path.join(protectedDirectory, "codex.exe"), "protected direct binary"),
    writeFile(path.join(managedPackage, "package.json"), JSON.stringify({ name: "@openai/codex" })),
    writeFile(path.join(platformPackage, "package.json"), JSON.stringify({ name: `@openai/codex-win32-${architecture}` })),
    writeFile(protectedPackageBinary, "protected package binary")
  ]);
  await Promise.all([
    utimes(olderBinary, new Date(1_000), new Date(1_000)),
    utimes(currentBinary, new Date(2_000), new Date(2_000)),
    utimes(emptyBinary, new Date(3_000), new Date(3_000))
  ]);

  const resolved = resolveCodexPath({
    CODEX_CLI_PATH: "C:\\Program Files\\WindowsApps\\OpenAI.Codex_fixture\\resources\\codex.exe",
    LOCALAPPDATA: localAppData
  }, "win32");
  assert.equal(resolved, currentBinary);
  assert.equal(resolveCodexPath({
    CODEX_MANAGED_PACKAGE_ROOT: managedPackage,
    Path: protectedDirectory,
    LOCALAPPDATA: localAppData
  }, "win32", architecture), currentBinary);
  assert.equal(resolveCodexPath({
    LOCALAPPDATA: path.relative(root, localAppData)
  }, "win32", architecture, root), currentBinary);
  assert.equal(resolveCodexPath({
    localappdata: localAppData
  }, "win32", architecture), currentBinary);
  const explicitOverride = path.join(root, "custom-codex.exe");
  assert.equal(resolveCodexPath({
    CODEX_CLI_PATH: explicitOverride,
    CODEX_MANAGED_PACKAGE_ROOT: managedPackage,
    Path: protectedDirectory,
    LOCALAPPDATA: localAppData
  }, "win32", architecture), explicitOverride);

  if (process.platform === "win32") {
    const launched = spawnSync(resolved, ["--version"], { encoding: "utf8" });
    assert.equal(launched.error, undefined);
    assert.equal(launched.status, 0);
    assert.equal(launched.stdout.trim(), process.version);
  }
}

async function testWindowsLauncherSkipsExtensionlessNpmShim() {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-windows-launcher-"));
  temporaryRoots.push(root);
  const shimDirectory = path.join(root, "npm-shims");
  const binaryDirectory = path.join(root, "native-bin");
  await Promise.all([mkdir(shimDirectory), mkdir(binaryDirectory)]);
  await writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n");
  await copyFile(process.execPath, path.join(binaryDirectory, "codex.exe"));

  const brokenEnvironment = windowsLauncherEnvironment(shimDirectory);
  const broken = spawnSync("codex", ["--version"], {
    encoding: "utf8",
    env: brokenEnvironment
  });
  assert.equal(["ENOENT", "EPERM"].includes(broken.error?.code), true);

  const environment = windowsLauncherEnvironment(shimDirectory, binaryDirectory);
  const fixed = spawnSync(resolveCodexPath(environment, "win32"), ["--version"], {
    encoding: "utf8",
    env: environment
  });
  assert.equal(fixed.error, undefined);
  assert.equal(fixed.status, 0);
  assert.equal(fixed.stdout.trim(), process.version);
}

async function testWindowsNpmPackageResolution(installation = "global") {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-windows-npm-"));
  temporaryRoots.push(root);
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetTriple = architecture === "arm64"
    ? "aarch64-pc-windows-msvc"
    : "x86_64-pc-windows-msvc";
  const packageDirectory = installation === "managed"
    ? path.join(root, "node_modules")
    : path.join(root, "npm", "node_modules");
  const shimDirectory = installation === "managed"
    ? path.join(packageDirectory, ".bin")
    : path.join(root, "npm");
  const codexPackage = path.join(packageDirectory, "@openai", "codex");
  const platformPackage = path.join(
    codexPackage,
    "node_modules",
    "@openai",
    `codex-win32-${architecture}`
  );
  const nativeBinary = path.join(platformPackage, "vendor", targetTriple, "bin", "codex.exe");
  await Promise.all([
    mkdir(path.dirname(nativeBinary), { recursive: true }),
    mkdir(shimDirectory, { recursive: true })
  ]);
  await Promise.all([
    writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n"),
    writeFile(path.join(codexPackage, "package.json"), JSON.stringify({ name: "@openai/codex" })),
    writeFile(
      path.join(platformPackage, "package.json"),
      JSON.stringify({ name: `@openai/codex-win32-${architecture}` })
    ),
    copyFile(process.execPath, nativeBinary)
  ]);

  const environment = windowsLauncherEnvironment(shimDirectory);
  if (installation === "managed") {
    environment.CODEX_MANAGED_PACKAGE_ROOT = codexPackage;
  }
  assert.equal(
    await realpath(resolveCodexPath(environment, "win32", architecture)),
    await realpath(nativeBinary)
  );
  if (installation === "managed") {
    const mixedCaseEnvironment = { ...environment, codex_managed_package_root: codexPackage };
    delete mixedCaseEnvironment.CODEX_MANAGED_PACKAGE_ROOT;
    assert.equal(
      await realpath(resolveCodexPath(mixedCaseEnvironment, "win32", architecture)),
      await realpath(nativeBinary)
    );
  }
  if (process.platform === "win32") {
    assert.equal(
      spawnSync("codex.exe", ["--version"], { encoding: "utf8", env: environment }).error?.code,
      "ENOENT"
    );

    const fixed = spawnSync(resolveCodexPath(environment, "win32", architecture), ["--version"], {
      encoding: "utf8",
      env: environment
    });
    assert.equal(fixed.error, undefined);
    assert.equal(fixed.status, 0);
    assert.equal(fixed.stdout.trim(), process.version);
  }
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

async function testWorkerLaunchesWithoutGlobalCodex() {
  const fixture = await fakeCodexFixture();
  const previousCodexPath = process.env.CODEX_CLI_PATH;
  const previousSearchPath = process.env.PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  process.env.PATH = path.dirname(process.execPath);

  try {
    const globalCodex = spawnSync("codex", ["--version"], {
      encoding: "utf8",
      env: process.env
    });
    assert.equal(globalCodex.error?.code, "ENOENT");

    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture nested worker without global codex\n");

    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: new AbortController().signal
    });

    assert.equal(result.threadId, "fixture-thread-id");
    assert.equal(result.finalResponse, "fixture final response");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    assert.deepEqual(invocation.argv.slice(0, 2), ["exec", "--experimental-json"]);
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousCodexPath);
    restoreEnv("PATH", previousSearchPath);
  }
}

async function testPreflightBindsExecutableAndHomeBeforeChangingCwd() {
  const fixture = await fakeCodexFixture();
  const originalCwd = process.cwd();
  const promptPath = path.join(fixture.root, "prompt.md");
  const workingDirectory = path.join(fixture.root, "artifacts");
  const nonExecutableDirectory = path.join(fixture.root, "non-executable-bin");
  const directoryShadow = path.join(fixture.root, "directory-shadow-bin");
  const binaryDirectory = path.join(fixture.root, "relative-bin");
  const codexPath = path.join(binaryDirectory, "codex");
  const homeTargetRoot = path.join(fixture.root, "home-target");
  const homeTargetChild = path.join(homeTargetRoot, "child");
  const codexHome = path.join(homeTargetRoot, "home");
  const homeLink = path.join(fixture.root, "home-link");
  await Promise.all([
    mkdir(workingDirectory),
    mkdir(nonExecutableDirectory),
    mkdir(path.join(directoryShadow, "codex"), { recursive: true }),
    mkdir(binaryDirectory),
    mkdir(homeTargetChild, { recursive: true }),
    mkdir(codexHome, { recursive: true })
  ]);
  assert.notEqual(workingDirectory, originalCwd);
  await writeFile(promptPath, "fixture bound worker executable and home\n");
  await writeFile(path.join(nonExecutableDirectory, "codex"), "not executable\n");
  await copyFile(fixture.executablePath, codexPath);
  await chmod(codexPath, 0o755);
  await symlink(homeTargetChild, homeLink, "dir");
  const relativeHome = `${path.relative(originalCwd, homeLink)}/../home`;
  const expectedHome = await realpath(relativeHome);
  assert.notEqual(path.resolve(originalCwd, relativeHome), expectedHome);

  const previousCodexPath = process.env.CODEX_CLI_PATH;
  const previousCodexHome = process.env.CODEX_HOME;
  const previousSearchPath = process.env.PATH;
  const previousLowercaseSearchPath = process.env.path;
  process.env.CODEX_HOME = relativeHome;
  process.env.path = path.relative(originalCwd, nonExecutableDirectory);
  process.env.PATH = [
    path.relative(originalCwd, nonExecutableDirectory),
    path.relative(originalCwd, directoryShadow),
    path.relative(originalCwd, binaryDirectory),
    path.dirname(process.execPath)
  ].join(path.delimiter);
  try {
    for (const [configured, expectedExecutable] of [
      [path.relative(originalCwd, fixture.executablePath), fixture.executablePath],
      [undefined, codexPath],
      ["codex", codexPath]
    ]) {
      if (configured === undefined) delete process.env.CODEX_CLI_PATH;
      else process.env.CODEX_CLI_PATH = configured;
      assert.equal(resolveCodexPath(), expectedExecutable);
      const result = await new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal,
      });

      assert.equal(result.finalResponse, "fixture final response");
      const preflight = JSON.parse(await readFile(fixture.preflightMarkerPath, "utf8"));
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assert.equal(preflight.cwd, await realpath(workingDirectory));
      assert.equal(invocation.cwd, originalCwd);
      assert.equal(preflight.codexHome, expectedHome);
      assert.equal(invocation.codexHome, expectedHome);
      assert.equal(process.env.CODEX_HOME, relativeHome);
      assert.deepEqual(preflight.requests, [
        { method: "config/read", cwd: workingDirectory },
        { method: "permissionProfile/list", cwd: workingDirectory }
      ]);
      assert.deepEqual(invocation.argv.slice(0, 2), ["exec", "--experimental-json"]);
      assertFlagPair(invocation.argv, "--cd", workingDirectory);
    }
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousCodexPath);
    restoreEnv("CODEX_HOME", previousCodexHome);
    restoreEnv("PATH", previousSearchPath);
    restoreEnv("path", previousLowercaseSearchPath);
  }
}

async function testSdkInvocationAndThreadCapture() {
  const fixture = await fakeCodexFixture(deniedWorkerPermissionProfile);
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    assert.equal(workingDirectory.startsWith("/repo/"), false);
    await writeFile(promptPath, "fixture worker prompt\n");
    let callbackThreadId;
    const result = await new CodexSdkWorkerExecutor({
      model: "gpt-5.6-luna",
      reasoningEffort: "xhigh",
      parentSandbox: trustedParentSandboxWithDenials
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 3,
      signal: new AbortController().signal,
      onThreadStarted: (threadId) => {
        callbackThreadId = threadId;
      }
    });
    assert.equal(result.threadId, "fixture-thread-id");
    assert.equal(callbackThreadId, "fixture-thread-id");
    assert.equal(result.finalResponse, "fixture final response");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    assert.equal(invocation.stdin, "fixture worker prompt\n");
    assert.equal(
      invocation.originator,
      process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE || "codex_sdk_ts"
    );
    assert.deepEqual(invocation.argv.slice(0, 2), ["exec", "--experimental-json"]);
    assertFlagPair(invocation.argv, "--model", "gpt-5.6-luna");
    assert.equal(invocation.argv.includes('model_reasoning_effort="xhigh"'), true);
    assertReadOnlyWorkerPolicy(invocation.argv);
    assert.equal(
      workerPermissionProfileOverride(invocation.argv),
      'permissions.codex_security_deep_scan_worker={extends=":read-only",filesystem={":root"="read","/repo/.env"="deny","/repo/**/.secret"="deny","/repo/**/*.pem"="deny",glob_scan_max_depth=3},network={enabled=false}}'
    );
    assertWorkerSubagentPolicy(invocation.argv, 3);
    assertFlagPair(invocation.argv, "--cd", workingDirectory);
    assert.equal(invocation.argv.includes("--skip-git-repo-check"), true);
    assert.equal(invocation.argv.includes('mcp_servers.codex-security.command="node"'), true);
    assert.equal(invocation.argv.includes("mcp_servers.codex-security.enabled=false"), true);
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testBedrockCredentialsReachWorker() {
  const fixture = await fakeCodexFixture();
  const mcpConfig = JSON.parse(
    await readFile(new URL("../../.mcp.json", import.meta.url), "utf8")
  );
  const awsEnvironment = Object.fromEntries(
    mcpConfig.mcpServers["codex-security"].env_vars
      .filter((name) => name.startsWith("AWS_"))
      .map((name) => [name, `synthetic-bedrock-${name.toLowerCase()}`])
  );
  assert.ok(awsEnvironment.AWS_BEARER_TOKEN_BEDROCK);
  assert.ok(awsEnvironment.AWS_ACCESS_KEY_ID);
  assert.ok(awsEnvironment.AWS_SECRET_ACCESS_KEY);
  const environment = {
    ...awsEnvironment,
    CODEX_CLI_PATH: fixture.executablePath,
    FAKE_CODEX_BEDROCK_ENV_KEYS: JSON.stringify(Object.keys(awsEnvironment))
  };
  const previousEnvironment = Object.fromEntries(
    Object.keys(environment).map((name) => [name, process.env[name]])
  );
  Object.assign(process.env, environment);

  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "CAPTURE_SYNTHETIC_BEDROCK_AUTH\n");
    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: new AbortController().signal
    });
    assert.equal(result.finalResponse, "fixture final response");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    assert.deepEqual(invocation.bedrockAuthentication, awsEnvironment);
  } finally {
    for (const [name, value] of Object.entries(previousEnvironment)) {
      restoreEnv(name, value);
    }
  }
}

async function testZeroSubagentsPreservesHostRestrictions() {
  for (const model of ["gpt-5.6-luna", "gpt-5.6-sol"]) {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, "fixture zero-subagent worker prompt\n");
      const result = await new CodexSdkWorkerExecutor({
        model,
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      });
      assert.equal(result.finalResponse, "fixture final response");
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assertFlagPair(invocation.argv, "--model", model);
      assertWorkerSubagentPolicy(invocation.argv, 0);
      assertReadOnlyWorkerPolicy(invocation.argv);
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
}

async function testArtifactServerUsesExtendedStartupTimeout() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture artifact worker prompt\n");
    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
      artifactContext: {
        pluginRoot: fixture.root,
        scanRoot: path.join(fixture.root, "scans"),
        repoRoot: fixture.root,
        scanId: "fixture-scan-id"
      }
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: new AbortController().signal,
      artifactContext: { root: workingDirectory, layout: "worker" }
    });
    assert.equal(result.finalResponse, "fixture final response");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    assert.equal(
      invocation.argv.includes("mcp_servers.cs_artifacts.startup_timeout_sec=180"),
      true
    );
    assert.equal(invocation.argv.includes("mcp_servers.cs_artifacts.required=true"), true);
    assert.equal(
      invocation.argv.includes("mcp_servers.cs_artifacts.tool_timeout_sec=86400"),
      true
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testSdkResumesExistingThread() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "original worker prompt\n");
    const result = await new CodexSdkWorkerExecutor({
      model: "gpt-5.6-sol",
      reasoningEffort: "ultra",
      parentSandbox: trustedReadOnlyParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 3,
      signal: new AbortController().signal,
      resumeThreadId: "fixture-existing-thread",
      continuationPrompt: "continue the existing worker\n"
    });
    assert.equal(result.threadId, "fixture-existing-thread");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    const resumeIndex = invocation.argv.indexOf("resume");
    assert.notEqual(resumeIndex, -1);
    assert.equal(invocation.argv[resumeIndex + 1], "fixture-existing-thread");
    assertFlagPair(invocation.argv, "--model", "gpt-5.6-sol");
    assert.equal(invocation.argv.includes('model_reasoning_effort="ultra"'), true);
    assertReadOnlyWorkerPolicy(invocation.argv);
    assertWorkerSubagentPolicy(invocation.argv, 3);
    assert.equal(invocation.stdin, "continue the existing worker\n");
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testRetryNotificationDoesNotInterruptTurn() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "RETRYABLE_STREAM_ERROR\n");
    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 3,
      signal: new AbortController().signal
    });
    assert.equal(result.threadId, "fixture-thread-id");
    assert.equal(result.finalResponse, "fixture final response");
    const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
    assert.equal(invocation.argv.includes("--model"), false);
    assert.equal(invocation.argv.some((arg) => arg.startsWith("model_reasoning_effort=")), false);
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testSandboxNamespaceDiagnosticIsSanitized() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "BWRAP_NAMESPACE_FAILURE\n");
    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 3,
      signal: new AbortController().signal
    });
    assert.deepEqual(result.diagnostics, [{
      code: "sandbox_namespace_exhausted",
      message: "Codex worker sandbox namespace creation failed (bwrap ENOSPC)."
    }]);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(serialized, /super-secret-command|private source text/);
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testOwnedArtifactToolFailureDiagnosticIsSanitized() {
  for (const { prompt, tool, reason } of [
    {
      prompt: "OWNED_ARTIFACT_TOOL_REJECTED",
      tool: "record_codex_security_deep_reduction",
      reason: "returned an error"
    },
    {
      prompt: "OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "record_codex_security_deep_reduction",
      reason: "transport failed"
    },
    {
      prompt: "OWNED_ARTIFACT_TOOL_UNCLASSIFIED_FAILURE",
      tool: "record_codex_security_deep_reduction",
      reason: "failed"
    },
    {
      prompt: "LEGACY_OWNED_ARTIFACT_TOOL_REJECTED",
      tool: "record_codex_security_deep_reduction",
      reason: "returned an error"
    },
    {
      prompt: "DISCOVERY_OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "record_codex_security_discovery_candidates",
      reason: "transport failed"
    },
    { prompt: "FOREIGN_ARTIFACT_TOOL_REJECTED" },
    {
      prompt: "ADDITIONAL_OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "additional_codex_security_worker_tool",
      reason: "transport failed"
    }
  ]) {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, `${prompt}\n`);
      const result = await new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      });
      if (tool) {
        assert.deepEqual(result.diagnostics, [{
          code: "artifact_tool_failed",
          message: `Codex worker artifact tool ${tool} ${reason}.`
        }]);
      } else {
        assert.equal(result.diagnostics, undefined);
      }
      assert.doesNotMatch(
        JSON.stringify(result),
        /synthetic-secret|private source|private output|private\/customer\/path/i
      );
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
}

async function testStreamTerminationWithoutTerminalEventFails() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "INCOMPLETE_STREAM\n");
    await assert.rejects(
      new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 3,
        signal: new AbortController().signal
      }),
      /before turn\.completed.*fixture stream interrupted/i
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testAbortPropagation() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "BLOCK_AFTER_START\n");
    const abortController = new AbortController();
    const execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: abortController.signal,
      onThreadStarted: () => abortController.abort("fixture cancellation")
    });
    await assert.rejects(execution, (error) => error?.name === "AbortError" || /abort|SIGTERM/i.test(error?.message ?? ""));
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testCompletedWorkerSettlesWithoutWaitingForProcessExit() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  const controller = new AbortController();
  const unexpectedErrors = [];
  const captureUnexpectedError = (error) => unexpectedErrors.push(error);
  let execution;
  let timeout;
  let childPid;

  process.on("uncaughtException", captureUnexpectedError);
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "COMPLETE_THEN_HANG\n");
    execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: controller.signal
    });

    const result = await Promise.race([
      execution,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort("completed worker fixture timed out");
          reject(new Error("completed worker did not settle after turn.completed"));
        }, 1_000);
      })
    ]);
    clearTimeout(timeout);
    assert.equal(result.threadId, "fixture-thread-id");
    assert.equal(result.finalResponse, "fixture final response");
    childPid = JSON.parse(await readFile(fixture.markerPath, "utf8")).pid;

    controller.abort("coordinator immediately canceled its remaining workers");
    await new Promise((resolve) => setTimeout(resolve, 250));

    assert.deepEqual(unexpectedErrors, []);
    assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
  } finally {
    clearTimeout(timeout);
    if (!controller.signal.aborted) controller.abort("completed worker fixture cleanup");
    await execution?.catch(() => {});
    if (childPid) {
      try {
        process.kill(childPid, "SIGKILL");
      } catch {}
    }
    process.removeListener("uncaughtException", captureUnexpectedError);
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testConfigurationFailureIsNonRetryable() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "CONFIG_ERROR\n");
    await assert.rejects(
      new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "setup",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      }),
      (error) => error?.name === "DeepScanNonRetryableError"
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testThreadStartConfigurationFailureIsNonRetryable() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "THREAD_START_CONFIG_ERROR\n");
    await assert.rejects(
      new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "setup",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      }),
      (error) => error?.name === "DeepScanNonRetryableError"
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testPolicyFailuresAreNonRetryable() {
  for (const prompt of [
    "CYBER_POLICY_ERROR",
    "SAFETY_POLICY_ERROR",
    "CYBERSECURITY_RISK_ERROR",
    "HIGH_RISK_CYBER_ACTIVITY_ERROR"
  ]) {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, `${prompt}\n`);
      await assert.rejects(
        new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox
        }).run({
          kind: "discovery",
          promptPath,
          workingDirectory,
          subagents: 0,
          signal: new AbortController().signal
        }),
        (error) => error?.name === "DeepScanNonRetryableError"
      );
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
}

async function testRateLimitPolicyFailureRemainsRetryable() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "RATE_LIMIT_CYBER_POLICY_ERROR\n");
    await assert.rejects(
      new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      }),
      (error) => error?.name !== "DeepScanNonRetryableError"
        && /429 Too Many Requests/.test(error?.message ?? "")
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testArtifactStartupTimeoutClassification() {
  for (const { prompt, retryable } of [
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT", retryable: true },
    { prompt: "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_SYNC_AUTH_WARNING", retryable: true },
    { prompt: "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT_SYNC_AUTH_WARNING", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_BOTH_AUTH_WARNINGS", retryable: true },
    { prompt: "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT_BOTH_AUTH_WARNINGS", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_BOTH_AUTH_WARNINGS", retryable: true },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_WITH_MISSING_API_KEY", retryable: false },
    { prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_WITH_POLICY_REFUSAL", retryable: false },
    {
      prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING_WITH_MISSING_API_KEY",
      retryable: false
    },
    {
      prompt: "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_BOTH_AUTH_WARNINGS_WITH_POLICY_REFUSAL",
      retryable: false
    },
    { prompt: "OTHER_MCP_STARTUP_TIMEOUT", retryable: false },
    {
      prompt: "OTHER_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING",
      retryable: false
    },
    { prompt: "CATALOG_AUTH_ONLY", retryable: false },
    { prompt: "SYNC_AUTH_ONLY", retryable: false }
  ]) {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, `${prompt}\n`);
      await assert.rejects(
        new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox
        }).run({
          kind: "discovery",
          promptPath,
          workingDirectory,
          subagents: 0,
          signal: new AbortController().signal
        }),
        (error) => (error?.name !== "DeepScanNonRetryableError") === retryable,
        `${prompt} should ${retryable ? "remain retryable" : "remain terminal"}`
      );
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
}

async function testMissingParentSandboxFailsBeforeWorkerLaunch() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    await assert.rejects(
      new CodexSdkWorkerExecutor().run({
        kind: "discovery",
        promptPath: path.join(fixture.root, "missing-prompt.md"),
        workingDirectory: path.join(fixture.root, "artifacts"),
        subagents: 0,
        signal: new AbortController().signal
      }),
      (error) => error?.name === "DeepScanNonRetryableError"
        && /verified parent sandbox metadata/i.test(error.message)
    );
    await assert.rejects(
      readFile(fixture.markerPath, "utf8"),
      (error) => error?.code === "ENOENT"
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testDisallowedWorkerProfileFailsBeforeWorkerLaunch() {
  const fixture = await fakeCodexFixture(emptyWorkerPermissionProfile, false);
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture blocked worker prompt\n");

    await assert.rejects(
      new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal
      }),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("codex_security_deep_scan_worker")
        && error.message.includes("[allowed_permission_profiles]")
        && error.message.includes("codex_security_deep_scan_worker = true")
        && error.message.includes("Deep Scan did not run.")
    );
    await assert.rejects(
      readFile(fixture.markerPath, "utf8"),
      (error) => error?.code === "ENOENT"
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testRuntimePermissionProfileFallbackStopsAndDiscards() {
  for (const marker of [
    "PERMISSION_PROFILE_FALLBACK_ITEM",
    "PERMISSION_PROFILE_FALLBACK_EVENT"
  ]) {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, `${marker}\n`);

      await assert.rejects(
        new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox
        }).run({
          kind: "discovery",
          promptPath,
          workingDirectory,
          subagents: 0,
          signal: new AbortController().signal,
        }),
        (error) => error?.name === "DeepScanNonRetryableError"
          && error.message.includes("worker was stopped")
          && error.message.includes("results were discarded")
          && !error.message.includes("did not run")
      );
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assert.equal(invocation.stdin, `${marker}\n`);
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
}

async function fakeCodexFixture(
  preflightProfile = emptyWorkerPermissionProfile,
  preflightAllowed = true
) {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-sdk-executor-"));
  temporaryRoots.push(root);
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(scriptPath, [
    "#!/usr/bin/env node",
    'import { writeFileSync } from "node:fs";',
    `const preflightProfile = ${JSON.stringify(preflightProfile)};`,
    `const preflightAllowed = ${JSON.stringify(preflightAllowed)};`,
    `const preflightMarkerPath = ${JSON.stringify(preflightMarkerPath)};`,
    "if (process.argv.includes('app-server')) {",
    "  const preflight = { cwd: process.cwd(), codexHome: process.env.CODEX_HOME, requests: [] };",
    "  writeFileSync(preflightMarkerPath, JSON.stringify(preflight));",
    "  let buffer = '';",
    "  process.stdin.setEncoding('utf8');",
    "  process.stdin.on('data', (chunk) => {",
    "    buffer += chunk;",
    "    while (true) {",
    "      const newline = buffer.indexOf('\\n');",
    "      if (newline < 0) return;",
    "      const line = buffer.slice(0, newline).trim();",
    "      buffer = buffer.slice(newline + 1);",
    "      if (!line) continue;",
    "      const message = JSON.parse(line);",
    "      if (message.method === 'initialized') continue;",
    "      if (message.method === 'config/read' || message.method === 'permissionProfile/list') {",
    "        preflight.requests.push({ method: message.method, cwd: message.params?.cwd });",
    "        writeFileSync(preflightMarkerPath, JSON.stringify(preflight));",
    "      }",
    "      let result;",
    "      if (message.method === 'initialize') {",
    "        result = { userAgent: 'fixture', codexHome: '/fixture', platformFamily: 'unix', platformOs: 'macos' };",
    "      } else if (message.method === 'config/read') {",
    "        result = { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: preflightProfile } }, origins: {}, layers: null };",
    "      } else if (message.method === 'permissionProfile/list') {",
    "        result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: preflightAllowed }], nextCursor: null };",
    "      } else if (message.method === 'configRequirements/read') {",
    "        result = { requirements: { allowedPermissionProfiles: { existing_profile: true } } };",
    "      } else {",
    "        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }) + '\\n');",
    "        continue;",
    "      }",
    "      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');",
    "    }",
    "  });",
    "  process.stdin.on('end', () => process.exit(0));",
    "} else {",
    "let stdin = '';",
    "for await (const chunk of process.stdin) stdin += chunk;",
    "const bedrockAuthentication = stdin.includes('CAPTURE_SYNTHETIC_BEDROCK_AUTH') ? Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_BEDROCK_ENV_KEYS).map((name) => [name, process.env[name]])) : undefined;",
    "writeFileSync(process.env.FAKE_CODEX_MARKER, JSON.stringify({ argv: process.argv.slice(2), stdin, cwd: process.cwd(), codexHome: process.env.CODEX_HOME, originator: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE, ...(stdin.includes('COMPLETE_THEN_HANG') ? { pid: process.pid } : {}), ...(bedrockAuthentication ? { bedrockAuthentication } : {}) }));",
    "if (stdin.includes('COMPLETE_THEN_HANG')) process.on('SIGTERM', () => setTimeout(() => process.exit(0), 100));",
    "if (stdin.includes('THREAD_START_CONFIG_ERROR')) { console.error('Error: thread/start: thread/start failed: agents.max_threads cannot be set when features.multi_agent_v2 is enabled (code -32600)'); process.exit(1); }",
    "if (stdin.includes('CONFIG_ERROR')) { console.error('failed to load configuration: invalid value'); process.exit(2); }",
    "if (stdin.includes('MCP_STARTUP_TIMEOUT') || stdin.includes('CATALOG_AUTH_ONLY') || stdin.includes('SYNC_AUTH_ONLY')) {",
    "  const syncWarning = stdin.includes('SYNC_AUTH_WARNING') || stdin.includes('SYNC_AUTH_ONLY');",
    "  const bothWarnings = stdin.includes('BOTH_AUTH_WARNINGS');",
    "  if (!syncWarning || bothWarnings) console.error('chatgpt authentication required for remote plugin catalog; api key auth is not supported');",
    "  if (syncWarning || bothWarnings) console.error('chatgpt authentication required to sync remote plugins; api key auth is not supported');",
    "  if (!stdin.includes('CATALOG_AUTH_ONLY') && !stdin.includes('SYNC_AUTH_ONLY')) {",
    "    const serverName = stdin.includes('OTHER_MCP_STARTUP_TIMEOUT') ? 'other_server' : stdin.includes('LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT') ? 'codex_security_artifacts' : 'cs_artifacts';",
    "    const timeout = stdin.includes('REQUEST_TIMED_OUT') ? 'request timed out' : 'timed out handshaking with MCP server after 30s';",
    "    console.error('required MCP servers failed to initialize: ' + serverName + ': ' + timeout);",
    "  }",
    "  if (stdin.includes('WITH_MISSING_API_KEY')) console.error('missing API key');",
    "  if (stdin.includes('WITH_POLICY_REFUSAL')) console.error('Request blocked by cyberPolicy.');",
    "  process.exit(1);",
    "}",
    "const resumeIndex = process.argv.indexOf('resume');",
    "const threadId = resumeIndex === -1 ? 'fixture-thread-id' : process.argv[resumeIndex + 1];",
    "console.log(JSON.stringify({ type: 'thread.started', thread_id: threadId }));",
    "const permissionProfileFallbackWarning = 'Configured value for `permission_profile` is disallowed by requirements; falling back from `codex_security_deep_scan_worker` to required value `:read-only`.';",
    "if (stdin.includes('PERMISSION_PROFILE_FALLBACK_ITEM')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'warning-1', type: 'error', message: permissionProfileFallbackWarning } }));",
    "if (stdin.includes('PERMISSION_PROFILE_FALLBACK_EVENT')) console.log(JSON.stringify({ type: 'error', message: permissionProfileFallbackWarning }));",
    "if (stdin.includes('BLOCK_AFTER_START')) await new Promise(() => {});",
    "if (stdin.includes('RATE_LIMIT_CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: '429 Too Many Requests: Request blocked by cyberPolicy.' } })); process.exit(0); }",
    "if (stdin.includes('CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by cyberPolicy.' } })); process.exit(0); }",
    "if (stdin.includes('SAFETY_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by a safety policy violation.' } })); process.exit(0); }",
    "if (stdin.includes('CYBERSECURITY_RISK_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for possible cybersecurity risk.' } })); process.exit(0); }",
    "if (stdin.includes('HIGH_RISK_CYBER_ACTIVITY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for potentially high-risk cyber activity.' } })); process.exit(0); }",
    "if (stdin.includes('RETRYABLE_STREAM_ERROR')) console.log(JSON.stringify({ type: 'error', message: 'Reconnecting... 2/5 (stream disconnected before completion: websocket closed by server before response.completed)' }));",
    "if (stdin.includes('INCOMPLETE_STREAM')) { console.log(JSON.stringify({ type: 'error', message: 'fixture stream interrupted' })); process.exit(0); }",
    "if (stdin.includes('BWRAP_NAMESPACE_FAILURE')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'command-1', type: 'command_execution', command: 'super-secret-command', aggregated_output: 'private source text\\nbwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_user_namespaces exceeded (ENOSPC)', exit_code: 1, status: 'failed' } }));",
    "if (stdin.includes('ARTIFACT_TOOL_')) {",
    "  const server = stdin.includes('FOREIGN_ARTIFACT_TOOL_') ? 'untrusted_server' : stdin.includes('LEGACY_OWNED_ARTIFACT_TOOL_') ? 'codex_security_artifacts' : 'cs_artifacts';",
    "  const tool = stdin.includes('ADDITIONAL_OWNED_ARTIFACT_TOOL_') ? 'additional_codex_security_worker_tool' : stdin.includes('DISCOVERY_OWNED_ARTIFACT_TOOL_') ? 'record_codex_security_discovery_candidates' : 'record_codex_security_deep_reduction';",
    "  const item = { id: 'mcp-1', type: 'mcp_tool_call', server, tool, arguments: { secret: 'Bearer synthetic-secret', source: 'private source text' }, result: stdin.includes('REJECTED') ? { content: [{ type: 'text', text: 'private output sk-proj-synthetic-secret' }] } : null, error: stdin.includes('TRANSPORT_FAILED') ? { message: 'transport closed sk-proj-synthetic-secret /private/customer/path' } : null, status: 'failed' };",
    "  console.log(JSON.stringify({ type: 'item.completed', item }));",
    "}",
    "console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture final response' } }));",
    "console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));",
    "if (stdin.includes('COMPLETE_THEN_HANG')) { setInterval(() => {}, 1_000); await new Promise(() => {}); }",
    "}",
    ""
  ].join("\n"));
  await chmod(scriptPath, 0o755);
  process.env.FAKE_CODEX_MARKER = markerPath;
  return { root, markerPath, preflightMarkerPath, executablePath: scriptPath };
}

function assertFlagPair(args, flag, value) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  assert.equal(args[index + 1], value);
}

function assertReadOnlyWorkerPolicy(args) {
  assert.equal(args.includes("--sandbox"), false);
  assert.equal(args.includes("--add-dir"), false);
  assert.equal(args.includes('approval_policy="never"'), true);
  assert.deepEqual(
    args.filter((arg) => arg.startsWith("approval_policy=")),
    ['approval_policy="never"']
  );
  assert.equal(args.some((arg) => arg.includes("network_access")), false);
  assert.equal(
    args.includes('default_permissions="codex_security_deep_scan_worker"'),
    true
  );
  const override = workerPermissionProfileOverride(args);
  assert.equal(override.includes('extends=":read-only"'), true);
  assert.equal(override.includes('":root"="read"'), true);
  assert.equal(override.includes('network={enabled=false}'), true);
  assert.equal(override.includes('"write"'), false);
}

function workerPermissionProfileOverride(args) {
  const overrides = args.filter((arg) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker=")
  );
  assert.equal(overrides.length, 1);
  return overrides[0];
}

function assertWorkerSubagentPolicy(args, subagents) {
  assert.equal(args.includes("features.multi_agent_v2.enabled=false"), true);
  assert.equal(args.includes("features.multi_agent_v2.enabled=true"), false);
  assert.equal(
    args.includes(`features.multi_agent_v2.max_concurrent_threads_per_session=${subagents + 1}`),
    true
  );
  assert.equal(args.some((arg) => arg.startsWith("features.multi_agent=")), false);

  if (subagents === 0) {
    assert.equal(args.some((arg) => arg.startsWith("agents.max_threads=")), false);
    assert.equal(args.includes("features.enable_fanout=false"), true);
    assert.equal(
      args.some((arg) => arg.startsWith("features.code_mode.excluded_tool_namespaces=")),
      false
    );
    assert.equal(args.some((arg) => arg.startsWith("features.code_mode.enabled=")), false);
  } else {
    assert.equal(args.includes(`agents.max_threads=${subagents}`), true);
    assert.equal(args.some((arg) => arg.startsWith("features.enable_fanout=")), false);
    assert.equal(
      args.some((arg) => arg.startsWith("features.code_mode.excluded_tool_namespaces=")),
      false
    );
  }
}

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
