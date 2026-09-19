import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

const executorSource = new URL("../src/deep-scan/executor.ts", import.meta.url);
const bundle = await build({
  bundle: true,
  nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
  define: {
    "import.meta.url": JSON.stringify(executorSource.href)
  },
  stdin: {
    // Test the environment snapshot without adding a production export.
    contents: `${await readFile(executorSource, "utf8")}\nexport { snapshotWorkerEnvironment, codexWorkerConfig, codexWorkerConfigPath };`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource)
  },
  format: "esm",
  platform: "node",
  write: false
});
const { CodexSdkWorkerExecutor, resolveCodexPath, snapshotWorkerEnvironment, codexWorkerConfig, codexWorkerConfigPath } = await import(
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
    "/repo/temp[1]",
    { path: "/repo/temp[1]" },
    "/repo/secret[1]",
    { path: "/repo/secret[1]" },
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
    "/repo/temp[1]": { ".": "deny" },
    "/repo/secret[1]": { ".": "deny" },
    "/": { "repo/temp[1]": "deny", "repo/secret[1]": "deny" },
    glob_scan_max_depth: 3
  },
  network: { enabled: false }
};

try {
  await runTests();
} finally {
  restoreEnv("FAKE_CODEX_MARKER", previousMarker);
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}

async function runTests() {
  if (process.argv[2] === "reconstructed-worker-fixture") {
    return await testIsolatedReconstructedWorkers(process.argv[3]);
  }
  if (process.argv[2] === "provider-snapshot-fixture") {
    return await testRuntimeProviderSnapshots(process.argv[3], process.argv[4]);
  }
  await testOpenAiCredentialsReachWorker();
  await testWorkerReasoningSummaries();
  await testWorkerProviderSelection();
  await testIsolatedReconstructedWorkers();
  await testRuntimeProviderSnapshots();
  await testWorkerCancellation();
  await testDisallowedWorkerProfileFailsBeforeWorkerLaunch();
  if (process.platform !== "win32") await testNullUsageCompletion();
  if (process.platform !== "win32") {
    await testMissingParentSandboxFailsBeforeWorkerLaunch();
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
    assert.deepEqual(
      parseToml(workerPermissionProfileOverride(invocation.argv)).permissions.codex_security_deep_scan_worker,
      deniedWorkerPermissionProfile
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

async function testOpenAiCredentialsReachWorker() {
  const noAccount = { account: null, requiresOpenaiAuth: true };
  const cases = [
    { openai: "synthetic-openai-key", expected: "synthetic-openai-key" },
    { openai: "  synthetic-openai-key  ", codex: " ", expected: "synthetic-openai-key" },
    { openai: "synthetic-openai-key", codex: "synthetic-selected-key", expected: "synthetic-selected-key" },
    { codex: "synthetic-selected-key", expected: "synthetic-selected-key" },
    { openai: "synthetic-openai-key", accountResult: { account: { type: "apiKey" }, requiresOpenaiAuth: true } },
    { openai: "synthetic-openai-key", accountResult: { account: { type: "chatgpt" }, requiresOpenaiAuth: true } },
    { openai: "synthetic-provider-key", accountResult: { account: null, requiresOpenaiAuth: false } },
    {},
    { openai: " " }
  ];
  for (const entry of cases) {
    const fixture = await fakeCodexFixture(emptyWorkerPermissionProfile, true, entry.accountResult ?? noAccount);
    const previousEnvironment = Object.fromEntries(
      ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_CLI_PATH", "CODEX_HOME"].map((name) => [name, process.env[name]])
    );
    const originalSpawn = childProcess.spawn;
    try {
      restoreEnv("OPENAI_API_KEY", entry.openai);
      restoreEnv("CODEX_API_KEY", entry.codex);
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = fixture.root;
      childProcess.spawn = (command, args, options) => originalSpawn(
        command,
        command === process.execPath || command === path.toNamespacedPath(process.execPath)
          ? [fixture.executablePath, ...args]
          : args,
        options
      );
      syncBuiltinESMExports();
      const promptPath = path.join(fixture.root, "prompt.md");
      await writeFile(promptPath, "CAPTURE_SYNTHETIC_OPENAI_AUTH\n");
      const executor = new CodexSdkWorkerExecutor({ parentSandbox: trustedParentSandbox });
      for (const kind of ["discovery", "dedup"]) {
        for (const resumeThreadId of [undefined, "fixture-resume"]) {
          await executor.run({
            kind,
            promptPath,
            workingDirectory: fixture.root,
            subagents: 0,
            resumeThreadId,
            signal: new AbortController().signal
          });
          const preflight = JSON.parse(await readFile(fixture.preflightMarkerPath, "utf8"));
          const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
          assert.equal(preflight.codexHome, fixture.root);
          assert.equal(invocation.codexHome, fixture.root);
          assert.equal(invocation.openaiAuthentication.CODEX_API_KEY, entry.expected);
          assert.equal(invocation.openaiAuthentication.OPENAI_API_KEY, entry.openai);
          assert.equal(process.env.CODEX_API_KEY, entry.codex);
          assert.equal(process.env.OPENAI_API_KEY, entry.openai);
          assert.equal(invocation.argv.some((arg) => arg.includes("synthetic-")), false);
        }
      }
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      for (const [name, value] of Object.entries(previousEnvironment)) restoreEnv(name, value);
    }
  }
}

async function testIsolatedReconstructedWorkers(selectedName) {
  if (!selectedName) {
    await Promise.all(["first", "second"].map((name) =>
      promisify(childProcess.execFile)(process.execPath, [fileURLToPath(import.meta.url), "reconstructed-worker-fixture", name])
    ));
    return;
  }
  const previousMarker = process.env.FAKE_CODEX_MARKER;
  const originalSpawn = childProcess.spawn;
  const children = [];
  const scans = [];
  try {
    for (const name of [selectedName]) {
      const fixture = await fakeCodexFixture(deniedWorkerPermissionProfile);
      const codexHome = path.join(fixture.root, "home");
      const configPath = path.join(fixture.root, "scan config.toml");
      const promptPath = path.join(fixture.root, "prompt.md");
      await mkdir(codexHome);
      const config = {
        model: `fixture-${name}-inherited`,
        model_provider: `fixture-${name}-provider`,
        model_reasoning_effort: "medium",
        model_reasoning_summary: name === "first" ? "none" : "concise",
        service_tier: name === "first" ? "flex" : "fast"
      };
      await writeFile(configPath, stringifyToml(config));
      const workerConfigPath = codexWorkerConfigPath(configPath);
      await mkdir(path.dirname(workerConfigPath), { recursive: true });
      await writeFile(workerConfigPath, stringifyToml(config));
      await writeFile(promptPath, "CAPTURE_SYNTHETIC_OPENAI_AUTH NULL_USAGE\n");
      const executable = path.join(fixture.root, process.platform === "win32" ? "node.exe" : "node");
      if (process.platform === "win32") {
        await copyFile(process.execPath, executable);
      } else {
        await symlink(process.execPath, executable);
      }
      const environment = {
          CODEX_CLI_PATH: executable,
          PATH: path.dirname(process.execPath),
          ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
          CODEX_HOME: codexHome,
          CODEX_SECURITY_CONFIG_PATH: configPath,
          CODEX_API_KEY: `synthetic-${name}-credential`,
          FAKE_CODEX_MARKER: fixture.markerPath,
          FAKE_CODEX_SCAN_VALUE: name
      };
      Object.assign(process.env, environment);
      const settings = {
        model: `fixture-${name}-override`,
        reasoningEffort: "ultra",
        parentSandbox: trustedParentSandboxWithDenials
      };
      scans.push({ name, fixture, config, configPath, promptPath, settings, environment, executor: new CodexSdkWorkerExecutor(settings) });
    }
    childProcess.spawn = (command, args, options) => {
      const scan = scans.find((scan) => options?.env?.FAKE_CODEX_MARKER === scan.fixture.markerPath);
      if (scan) assert.equal(command, path.toNamespacedPath(scan.environment.CODEX_CLI_PATH));
      const child = originalSpawn(command, scan ? [scan.fixture.executablePath, ...args] : args, options);
      if (scan) children.push(child);
      return child;
    };
    syncBuiltinESMExports();

    for (const phase of ["fresh", "resume", "reconstructed"]) {
      for (const scan of scans) {
        scan.environment.CODEX_API_KEY = `synthetic-${scan.name}-${phase}-credential`;
        scan.environment.FAKE_CODEX_SCAN_VALUE = `${scan.name}-${phase}`;
        Object.assign(process.env, scan.environment);
      }
      if (phase === "reconstructed") {
        for (const scan of scans) {
          scan.executor = new CodexSdkWorkerExecutor(scan.settings);
        }
      }
      for (const kind of ["discovery", "dedup"]) {
        await Promise.all(scans.map(async (scan) => {
          const resumeThreadId = phase === "fresh" ? undefined : `fixture-${scan.name}-resumed`;
          const result = await scan.executor.run({
            kind, promptPath: scan.promptPath, workingDirectory: scan.fixture.root,
            subagents: scan.name === "first" ? 0 : 2,
            resumeThreadId, continuationPrompt: "CAPTURE_SYNTHETIC_OPENAI_AUTH NULL_USAGE continuation",
            signal: new AbortController().signal
          });
          assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
          const child = JSON.parse(await readFile(scan.fixture.markerPath, "utf8"));
          const preflight = JSON.parse(await readFile(scan.fixture.preflightMarkerPath, "utf8"));
          assert.equal(await realpath(child.executable), await realpath(scan.environment.CODEX_CLI_PATH));
          assert.equal(child.codexHome, scan.environment.CODEX_HOME);
          assert.equal(preflight.codexHome, child.codexHome);
          assert.equal(child.scanValue, `${scan.name}-${phase}`);
          assert.equal(child.configPath, scan.configPath);
          assert.deepEqual(child.openaiAuthentication, { CODEX_API_KEY: `synthetic-${scan.name}-${phase}-credential` });
          assertFlagPair(child.argv, "--model", scan.settings.model);
          for (const key of ["model_provider", "model_reasoning_summary", "service_tier"]) {
            const override = `${key}=${JSON.stringify(scan.config[key])}`;
            assert.equal(child.argv.includes(override), true, override);
            assert.equal(preflight.argv.includes(override), true, override);
          }
          assert.equal(child.argv.includes('model_reasoning_effort="ultra"'), true);
          assert.equal(preflight.argv.includes('model_reasoning_effort="ultra"'), true);
          assert.equal(preflight.argv.includes(`model=${JSON.stringify(scan.settings.model)}`), true);
          assertReadOnlyWorkerPolicy(child.argv);
          assertWorkerSubagentPolicy(child.argv, scan.name === "first" ? 0 : 2);
          for (const invocation of [child, preflight]) {
            assert.deepEqual(
              parseToml(workerPermissionProfileOverride(invocation.argv)).permissions.codex_security_deep_scan_worker,
              deniedWorkerPermissionProfile
            );
          }
          assert.equal(child.argv.includes("resume"), resumeThreadId !== undefined);
          assert.equal(child.stdin.includes("continuation"), resumeThreadId !== undefined);
        }));
      }
      if (phase === "fresh") {
        for (const scan of scans) {
          await writeFile(scan.configPath, 'model_provider = "changed-provider"\nmodel_reasoning_summary = "detailed"\n');
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("FAKE_CODEX_MARKER", previousMarker);
    // The SDK removes child listeners before the copied executable is safe to delete on Windows.
    await Promise.all(children.map((child) => {
      if (child.stdout.closed && child.stderr.closed
        && (child.exitCode !== null || child.signalCode !== null)) return;
      return new Promise((resolve) => {
        child.once("close", resolve);
        if (child.exitCode === null && child.signalCode === null) child.kill();
      });
    }));
  }
}

async function testRuntimeProviderSnapshots(selectedName, sharedHome) {
  if (!selectedName) {
    sharedHome = await mkdtemp(path.join(tmpdir(), "shared-worker-home-"));
    temporaryRoots.push(sharedHome);
    await Promise.all(["openrouter", "fireworks", "command-auth", "cloud.production", "cloud production", "shared-default", "shared-default-configured", "openai", "shared-external"].map((name) =>
      promisify(childProcess.execFile)(process.execPath, [fileURLToPath(import.meta.url), "provider-snapshot-fixture", name, sharedHome])
    ));
    return;
  }
  const originalSpawn = childProcess.spawn;
  const previousMarker = process.env.FAKE_CODEX_MARKER;
  const scans = [];
  try {
    for (const name of [selectedName]) {
      const configPath = path.join(sharedHome, `${name}.toml`);
      const workerConfigPath = codexWorkerConfigPath(configPath);
      const permissionProfile = {
        ...deniedWorkerPermissionProfile,
        filesystem: { ...deniedWorkerPermissionProfile.filesystem, [workerConfigPath]: "deny" }
      };
      const fixture = await fakeCodexFixture(permissionProfile);
      const promptPath = path.join(fixture.root, "prompt.md");
      const provider = name.startsWith("shared-default") ? "openai" : name === "shared-external" ? "openrouter" : name.startsWith("cloud") ? "amazon-bedrock" : name === "command-auth" ? "openrouter" : name;
      const definition = provider === "amazon-bedrock"
        ? { aws: { region: "us-west-2", profile: "synthetic" } }
        : {
          name: "Synthetic provider", base_url: `https://${provider}.example.test/v1`, wire_api: "responses",
          experimental_bearer_token: `synthetic-${name}-selected-token`,
          http_headers: { Authorization: `synthetic-${name}-selected-header` },
          env_http_headers: { "X-Synthetic-Auth": "SYNTHETIC_PROVIDER_HEADER" },
          query_params: { "api-version": "synthetic-version" },
          ...(name === "command-auth"
            ? { auth: { command: "synthetic-auth-helper", args: [], cwd: fixture.root } }
            : { env_key: `${provider.toUpperCase()}_API_KEY` })
        };
      const auth = name.startsWith("shared-") ? {
        cli_auth_credentials_store: name === "shared-default" ? "file" : "keyring",
        forced_login_method: name === "shared-default" ? "chatgpt" : "api",
        forced_chatgpt_workspace_id: `synthetic-${name}`
      } : {};
      const config = { model: "inherited-model", model_provider: provider, ...(name === "shared-default" ? {} : { model_providers: { [provider]: definition } }), model_reasoning_summary: "concise", service_tier: "flex", ...auth };
      const input = {
        ...config,
        model_providers: {
          ...config.model_providers,
          unrelated: { experimental_bearer_token: `synthetic-${name}-unrelated-token` }
        }
      };
      if (name.startsWith("shared-default")) delete input.model_provider;
      if (name.startsWith("cloud")) {
        input.model_provider = "openai";
        input.profile = name;
        input.profiles = {
          [name]: { model_provider: provider },
          inactive: { model_provider: "unrelated" }
        };
      }
      // These preflight projections intentionally differ from the runtime snapshot.
      const preflight = name.startsWith("cloud")
        ? { model_provider: "openai", model_reasoning_summary: "concise" }
        : { model_provider: provider, model_providers: { [provider]: { base_url: "https://default.example.test/v1", env_key: `${provider.toUpperCase()}_API_KEY` } } };
      await writeFile(configPath, stringifyToml(preflight));
      await writeFile(promptPath, "NULL_USAGE");
      const codexHome = name.startsWith("shared-") ? sharedHome : path.join(fixture.root, "home");
      await mkdir(codexHome, { recursive: true });
      await writeFile(workerConfigPath, stringifyToml(codexWorkerConfig(input)));
      // Simulate a later session replacing the shared home configuration.
      await writeFile(path.join(codexHome, "config.toml"), 'model_provider = "changed-home-provider"\n');
      const environment = { CODEX_CLI_PATH: process.execPath, CODEX_HOME: codexHome, CODEX_SECURITY_CONFIG_PATH: configPath, FAKE_CODEX_MARKER: fixture.markerPath, FAKE_CODEX_WORKER_CONFIG: workerConfigPath, SYNTHETIC_PROVIDER_HEADER: `synthetic-${name}-header-env`, ...(definition.env_key ? { [definition.env_key]: `synthetic-${name}-env-key` } : {}), FAKE_CODEX_PROVIDER_ENV_KEYS: JSON.stringify(["SYNTHETIC_PROVIDER_HEADER", ...(definition.env_key ? [definition.env_key] : [])]) };
      Object.assign(process.env, environment);
      const settings = {
        model: "worker-model", reasoningEffort: "ultra", parentSandbox: {
          ...trustedParentSandboxWithDenials,
          filesystemDenies: [...trustedParentSandboxWithDenials.filesystemDenies, workerConfigPath]
        }
      };
      scans.push({ name, permissionProfile, fixture, configPath, promptPath, config, input, auth, settings, environment, workerConfigPath, executor: new CodexSdkWorkerExecutor(settings) });
    }
    childProcess.spawn = (command, args, options) => {
      const scan = scans.find((scan) => options?.env?.FAKE_CODEX_MARKER === scan.fixture.markerPath);
      return originalSpawn(command, scan ? [scan.fixture.executablePath, ...args] : args, options);
    };
    syncBuiltinESMExports();
    for (const phase of ["fresh", "resume", "reconstructed"]) {
      if (phase === "reconstructed") {
        for (const scan of scans) {
          await writeFile(scan.workerConfigPath, stringifyToml(codexWorkerConfig(scan.input)));
          scan.executor = new CodexSdkWorkerExecutor(scan.settings);
        }
      }
      for (const kind of ["discovery", "dedup"]) {
        const outcomes = await Promise.allSettled(scans.map(async (scan) => {
          const resumeThreadId = phase === "fresh" ? undefined : "resumed-worker";
          await scan.executor.run({ kind, promptPath: scan.promptPath, workingDirectory: scan.fixture.root, subagents: 0, resumeThreadId, signal: new AbortController().signal });
          for (const file of [scan.fixture.markerPath, scan.fixture.preflightMarkerPath]) {
            const child = JSON.parse(await readFile(file, "utf8"));
            const overrides = {};
            for (let i = 0; i < child.argv.length; i++) {
              if (["-c", "--config"].includes(child.argv[i])) Object.assign(overrides, parseToml(child.argv[++i]));
            }
            assert.deepEqual(overrides.permissions.codex_security_deep_scan_worker, scan.permissionProfile);
            assert.equal(overrides.model_provider, scan.config.model_provider, `${scan.name} ${phase} ${kind}`);
            assert.equal(JSON.stringify(child).includes(`synthetic-${scan.name}-unrelated-token`), false);
            assert.deepEqual(parseToml(child.workerConfig), phase === "resume" ? { model_provider: "changed-after-launch" } : scan.config);
            assert.deepEqual(child.providerAuthentication, Object.fromEntries(
              JSON.parse(scan.environment.FAKE_CODEX_PROVIDER_ENV_KEYS)
                .map((key) => [key, scan.environment[key]])
            ));
            assert.deepEqual(overrides.model_providers, scan.config.model_providers, `${scan.name} ${phase} ${kind}`);
            for (const [key, value] of Object.entries(scan.auth)) {
              assert.equal(overrides[key], value, `${scan.name} ${phase} ${kind} ${key}`);
            }
            assert.equal(overrides.model_reasoning_effort, "ultra");
            assert.equal(overrides.model_reasoning_summary, "concise");
            assert.equal(overrides.service_tier, "flex");
            assert.equal(child.codexHome, scan.environment.CODEX_HOME);
          }
          const child = JSON.parse(await readFile(scan.fixture.markerPath, "utf8"));
          assertFlagPair(child.argv, "--model", "worker-model");
          assertReadOnlyWorkerPolicy(child.argv);
          assertWorkerSubagentPolicy(child.argv, 0);
          assert.equal(child.argv.includes("resume"), resumeThreadId !== undefined);
        }));
        const failures = outcomes.filter((outcome) => outcome.status === "rejected");
        if (failures.length) throw new AggregateError(failures.map((outcome) => outcome.reason), "Worker runtime provider controls failed");
      }
      if (phase === "fresh") {
        for (const scan of scans) await writeFile(scan.workerConfigPath, 'model_provider = "changed-after-launch"\n');
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("FAKE_CODEX_MARKER", previousMarker);
  }
}

async function testWorkerProviderSelection() {
  const fixture = await fakeCodexFixture();
  const saved = Object.fromEntries(
    ["CODEX_CLI_PATH", "CODEX_HOME", "CODEX_SECURITY_CONFIG_PATH", "OPENAI_API_KEY", "CODEX_API_KEY"].map((name) => [name, process.env[name]])
  );
  const originalSpawn = childProcess.spawn;
  try {
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_API_KEY;
    const configPath = path.join(fixture.root, "scan config.toml");
    const promptPath = path.join(fixture.root, "prompt.md");
    await writeFile(configPath, 'model_provider = "fixture-provider"\n');
    const workerConfigPath = codexWorkerConfigPath(configPath);
    await mkdir(path.dirname(workerConfigPath), { recursive: true });
    await writeFile(workerConfigPath, 'model_provider = "fixture-provider"\n');
    process.env.CODEX_HOME = fixture.root;
    await writeFile(promptPath, "fixture provider selection");
    process.env.CODEX_CLI_PATH = process.execPath;
    process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
    childProcess.spawn = (command, args, options) => originalSpawn(
      command,
      command === process.execPath || command === path.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      options
    );
    syncBuiltinESMExports();
    const executor = new CodexSdkWorkerExecutor({ parentSandbox: trustedParentSandbox });
    for (const kind of ["discovery", "dedup"]) {
      await executor.run({
        kind, promptPath, workingDirectory: fixture.root, subagents: 0,
        signal: new AbortController().signal
      });
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assert.equal(invocation.argv.includes('model_provider="fixture-provider"'), true);
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of Object.entries(saved)) restoreEnv(name, value);
  }
}

async function testNullUsageCompletion() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    await writeFile(promptPath, "NULL_USAGE\n");
    for (const kind of ["discovery", "dedup"]) {
      for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
        const result = await new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox
        }).run({
          kind, promptPath, workingDirectory: fixture.root, subagents: 0,
          resumeThreadId, signal: new AbortController().signal
        });
        assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
        assert.equal(result.finalResponse, "fixture final response");
      }
    }
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testWorkerReasoningSummaries() {
  const cases = [
    ["", undefined],
    ['model_reasoning_summary = "none"\n', "none"],
    ['model_reasoning_summary = "auto"\n', "auto"],
    ['model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel_reasoning_summary = "concise"\n', "concise"],
    ['model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel = "fixture-model"\n[profiles.other]\nmodel_reasoning_summary = "detailed"\n', "none"]
  ];
  const saved = Object.fromEntries(
    ["CODEX_CLI_PATH", "CODEX_SECURITY_CONFIG_PATH", "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", "OPENAI_API_KEY", "CODEX_API_KEY"].map((name) => [name, process.env[name]])
  );
  const originalSpawn = childProcess.spawn;
  try {
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_API_KEY;
    for (const [configuration, expected] of cases) {
      const fixture = await fakeCodexFixture(deniedWorkerPermissionProfile);
      const configPath = path.join(fixture.root, "active scan config.toml");
      const promptPath = path.join(fixture.root, "prompt.md");
      await writeFile(configPath, configuration);
      await writeFile(promptPath, "synthetic worker configuration fixture");
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
      process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = path.join(fixture.root, "deep settings.toml");
      childProcess.spawn = (command, args, options) => originalSpawn(
        command,
        command === process.execPath || command === path.toNamespacedPath(process.execPath)
          ? [fixture.executablePath, ...args]
          : args,
        options
      );
      syncBuiltinESMExports();
      const executor = new CodexSdkWorkerExecutor({
        model: "fixture-model",
        reasoningEffort: "xhigh",
        parentSandbox: trustedParentSandboxWithDenials
      });
      // A running coordinator retains its settings if the source file changes.
      for (const kind of ["discovery", "dedup"]) {
        for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
          await executor.run({
            kind, promptPath, workingDirectory: fixture.root, subagents: 0,
            resumeThreadId, signal: new AbortController().signal
          });
          const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
          if (expected === undefined) {
            assert.equal(invocation.argv.some((arg) => arg.startsWith("model_reasoning_summary=")), false);
          } else {
            assert.equal(invocation.argv.includes(`model_reasoning_summary=${JSON.stringify(expected)}`), true);
          }
          assert.equal(invocation.argv.includes('model_reasoning_effort="xhigh"'), true);
          assert.equal(invocation.configPath, configPath);
          assert.equal(invocation.deepConfigPath, process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH);
          for (const file of [fixture.markerPath, fixture.preflightMarkerPath]) {
            const child = JSON.parse(await readFile(file, "utf8"));
            assert.equal(child.argv.some((arg) => arg.startsWith("model_provider=")), false);
          }
          assertReadOnlyWorkerPolicy(invocation.argv);
          assertWorkerSubagentPolicy(invocation.argv, 0);
          await writeFile(configPath, 'model_reasoning_summary = "detailed"\n');
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of Object.entries(saved)) restoreEnv(name, value);
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

async function testWorkerCancellation() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  const originalSpawn = childProcess.spawn;
  let worker;
  let workerSignal;
  let cancelDuringCleanup;
  let timeout;
  childProcess.spawn = (command, args, options) => {
    const child = originalSpawn(command, command === process.execPath || command === path.toNamespacedPath(process.execPath)
      ? [fixture.executablePath, ...args] : args, options);
    if (args[0] === "exec") {
      assertFlagPair(args, "--thread-source", "security_scan");
      worker = child;
      workerSignal = options.signal;
      const kill = child.kill;
      child.kill = function (...args) {
        cancelDuringCleanup?.();
        return kill.apply(this, args);
      };
    }
    return child;
  };
  syncBuiltinESMExports();
  process.env.CODEX_CLI_PATH = process.execPath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    const executor = new CodexSdkWorkerExecutor({ parentSandbox: trustedParentSandbox });
    const run = (controller, onThreadStarted) => executor.run({
      kind: "discovery", promptPath, workingDirectory, subagents: 0,
      signal: controller.signal, onThreadStarted
    });
    const preAborted = new AbortController();
    const beforeStartup = new Error("coordinator canceled before worker startup");
    preAborted.abort(beforeStartup);
    await assert.rejects(run(preAborted), (error) => error === beforeStartup);
    assert.equal(worker, undefined);
    await assert.rejects(readFile(fixture.preflightMarkerPath), { code: "ENOENT" });
    await assert.rejects(readFile(fixture.markerPath), { code: "ENOENT" });

    for (const prompt of ["BLOCK_AFTER_START", "COMPLETE_THEN_HANG", "FAIL_THEN_HANG"]) {
      await writeFile(promptPath, `${prompt}\n`);
      const controller = new AbortController();
      const cancellation = new Error("coordinator canceled its remaining workers");
      // Exercise cancellation inside the real SDK's iterator cleanup, before kill returns.
      cancelDuringCleanup = prompt === "COMPLETE_THEN_HANG"
        ? () => controller.abort(cancellation) : undefined;
      const deadline = new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`${prompt} worker did not settle`)), 10_000);
      });
      const execution = Promise.race([
        run(controller, () => {
          if (prompt === "BLOCK_AFTER_START") controller.abort(cancellation);
        }),
        deadline
      ]);
      if (prompt === "BLOCK_AFTER_START") {
        await assert.rejects(execution, (error) => error?.name === "AbortError" || /abort|SIGTERM/i.test(error?.message ?? ""));
        assert.equal(workerSignal.aborted, true);
        assert.equal(workerSignal.reason, cancellation);
      } else {
        if (prompt === "FAIL_THEN_HANG") {
          await assert.rejects(execution, /fixture worker failed/);
          controller.abort(cancellation);
        } else {
          const result = await execution;
          assert.equal(result.threadId, "fixture-thread-id");
          assert.equal(result.finalResponse, "fixture final response");
        }
        assert.equal(controller.signal.aborted, true);
        assert.equal(workerSignal.aborted, false);
      }
      assert.notEqual(workerSignal, controller.signal);
      assert.equal(worker.killed, true);
      if (worker.exitCode === null && worker.signalCode === null) {
        await Promise.race([new Promise((resolve) => worker.once("close", resolve)), deadline]);
      }
      clearTimeout(timeout);
      cancelDuringCleanup = undefined;
    }
  } finally {
    clearTimeout(timeout);
    cancelDuringCleanup = undefined;
    if (worker && worker.exitCode === null && worker.signalCode === null) worker.kill("SIGKILL");
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
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
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = (command, args, options) => originalSpawn(
    command,
    command === process.execPath || command === path.toNamespacedPath(process.execPath)
      ? [fixture.executablePath, ...args] : args,
    options
  );
  syncBuiltinESMExports();
  process.env.CODEX_CLI_PATH = process.execPath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture blocked worker prompt\n");

    for (const kind of ["discovery", "dedup"]) {
      for (const resumeThreadId of [undefined, "fixture-resumed-worker"]) {
        await assert.rejects(
          new CodexSdkWorkerExecutor({
            parentSandbox: trustedParentSandbox
          }).run({
            kind,
            resumeThreadId,
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
      }
    }
    await assert.rejects(
      readFile(fixture.markerPath, "utf8"),
      (error) => error?.code === "ENOENT"
    );
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
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
  preflightAllowed = true,
  accountResult = { account: { type: "apiKey" }, requiresOpenaiAuth: true }
) {
  const root = await mkdtemp(path.join(tmpdir(), "codex-security-sdk-executor-"));
  temporaryRoots.push(root);
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(scriptPath, [
    "#!/usr/bin/env node",
    'import { readFileSync, writeFileSync } from "node:fs";',
    `const preflightProfile = ${JSON.stringify(preflightProfile)};`,
    `const preflightAllowed = ${JSON.stringify(preflightAllowed)};`,
    `const accountResult = ${JSON.stringify(accountResult)};`,
    `const preflightMarkerPath = ${JSON.stringify(preflightMarkerPath)};`,
    "const workerConfig = process.env.FAKE_CODEX_WORKER_CONFIG ? readFileSync(process.env.FAKE_CODEX_WORKER_CONFIG, 'utf8') : undefined;",
    "const providerAuthentication = process.env.FAKE_CODEX_PROVIDER_ENV_KEYS ? Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_PROVIDER_ENV_KEYS).map((name) => [name, process.env[name]])) : undefined;",
    "if (process.argv.includes('app-server')) {",
    "  const preflight = { workerConfig, providerAuthentication, argv: process.argv.slice(2), cwd: process.cwd(), codexHome: process.env.CODEX_HOME, requests: [] };",
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
    "      } else if (message.method === 'account/read') {",
    "        result = accountResult;",
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
    "const openaiAuthentication = stdin.includes('CAPTURE_SYNTHETIC_OPENAI_AUTH') ? { OPENAI_API_KEY: process.env.OPENAI_API_KEY, CODEX_API_KEY: process.env.CODEX_API_KEY } : undefined;",
    "const bedrockAuthentication = stdin.includes('CAPTURE_SYNTHETIC_BEDROCK_AUTH') ? Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_BEDROCK_ENV_KEYS).map((name) => [name, process.env[name]])) : undefined;",
    "writeFileSync(process.env.FAKE_CODEX_MARKER, JSON.stringify({ workerConfig, providerAuthentication, executable: process.execPath, argv: process.argv.slice(2), stdin, cwd: process.cwd(), codexHome: process.env.CODEX_HOME, configPath: process.env.CODEX_SECURITY_CONFIG_PATH, scanValue: process.env.FAKE_CODEX_SCAN_VALUE, deepConfigPath: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH, originator: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE, ...(openaiAuthentication ? { openaiAuthentication } : {}), ...(bedrockAuthentication ? { bedrockAuthentication } : {}) }));",
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
    "if (stdin.includes('BLOCK_AFTER_START')) { setInterval(() => {}, 1_000); await new Promise(() => {}); }",
    "if (stdin.includes('FAIL_THEN_HANG')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'fixture worker failed' } })); setInterval(() => {}, 1_000); await new Promise(() => {}); }",
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
    "console.log(JSON.stringify({ type: 'turn.completed', usage: stdin.includes('NULL_USAGE') ? null : { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));",
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
