import { readJson, writeJson } from "./support/json.ts";
import { assertFlagPair } from "./assertions.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { mock } from "node:test";
import assert from "node:assert/strict";
import childProcess, {
  spawnSync,
  type SpawnOptions,
  type ChildProcess,
} from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  realpath,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

import type {
  CodexWorkerDiagnostic,
  CodexWorkerRequest,
  DeepScanWorkerKind,
} from "../src/deep-scan/types.js";

const executorSource = new URL("../src/deep-scan/executor.ts", import.meta.url);

const {
  CodexSdkWorkerExecutor,
  resolveCodexPath,
  snapshotWorkerEnvironment,
  appendSafeItemDiagnostic,
  classifyCodexWorkerError,
  DeepScanNonRetryableError,
  isCodexCybersecurityPolicyRefusal,
} = await importModule({
  define: {
    "import.meta.url": JSON.stringify(executorSource.href),
  },
  stdin: {
    // Test the environment snapshot without adding a production export.
    contents: `${await readFile(executorSource, "utf8")}
export { snapshotWorkerEnvironment, appendSafeItemDiagnostic };
export * from "./errors.js";`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource),
  },
});

const temporaryDirectories = createTemporaryDirectories();
const previousMarker = process.env.FAKE_CODEX_MARKER;
const trustedParentSandbox = Object.freeze({
  filesystemDenies: [],
});
const trustedParentSandboxWithDenials = Object.freeze({
  filesystemDenies: [
    "/repo/.env",
    "/repo/**/.secret",
    "/repo/**/*.pem",
    "/repo/.env",
  ],
  globScanMaxDepth: 3,
});
const emptyWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: { ":root": "read" },
  network: { enabled: false },
};
const ipcFrameError =
  "code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length 76008279 exceeds 67108864 bytes";
const deniedWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny",
    "/repo/**/.secret": "deny",
    "/repo/**/*.pem": "deny",
    glob_scan_max_depth: 3,
  },
  network: { enabled: false },
};

try {
  testCodeModeFrameDiagnosticBoundaries();
  await testOpenAiCredentialsReachWorker();
  await testWorkerRuntimeSettings();
  await testWorkerCyberAccessSettings();
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
    await testCodeModeFrameDiagnosticSurvivesSuccessfulTurn();
    await testStreamTerminationWithoutTerminalEventFails();
    await testCompletedWorkerSettlesWithoutWaitingForProcessExit();
    await testAbortPropagation();
    await testUnstructuredConfigurationFailureRemainsRetryable();
    await testUnstructuredThreadStartFailureRemainsRetryable();
    await testPolicyFailuresRemainWorkerErrors();
    await testMalformedCommandEventsRemainRetryable();
    await testRateLimitPolicyFailureRemainsRetryable();
    await testArtifactStartupTimeoutClassification();
  }
  assert.equal(
    resolveCodexPath({}, "darwin"),
    path.join(process.cwd(), "codex"),
  );
  assert.equal(
    resolveCodexPath({}, "linux"),
    path.join(process.cwd(), "codex"),
  );
  assert.equal(
    resolveCodexPath({}, "win32"),
    path.join(process.cwd(), "codex.exe"),
  );
  const absoluteConfiguredPath = path.join(
    path.parse(process.cwd()).root,
    "fixture",
    "codex",
  );
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: ` ${absoluteConfiguredPath} ` }),
    absoluteConfiguredPath,
  );
  const originalCwd = path.join(process.cwd(), "fixture-root");
  const relativeConfiguredPath = path.join("fixtures", "codex");
  assert.equal(
    resolveCodexPath(
      { CODEX_CLI_PATH: relativeConfiguredPath },
      "linux",
      process.arch,
      originalCwd,
    ),
    path.join(originalCwd, "fixtures", "codex"),
  );
  assert.equal(
    resolveCodexPath(
      { CODEX_CLI_PATH: relativeConfiguredPath },
      "win32",
      process.arch,
      originalCwd,
    ),
    path.join(originalCwd, "fixtures", "codex"),
  );
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: " C:\\Tools\\codex.exe " }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  assert.equal(
    resolveCodexPath({ codex_cli_path: " C:\\Tools\\codex.exe " }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  assert.equal(
    resolveCodexPath(
      { codex_cli_path: "/ignored/codex" },
      "linux",
      process.arch,
      originalCwd,
    ),
    path.join(originalCwd, "codex"),
  );
  testOsErrorCodesRemainRetryable();
  testTextualMissingPathErrorsRemainRetryable();
  testWorkerErrorClassificationPreservesExplicitFailures();
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
  await temporaryDirectories.cleanup();
}

function testOsErrorCodesRemainRetryable() {
  for (const code of ["ENOENT", "EACCES", "ENOEXEC", "EPERM"]) {
    const original = Object.assign(new Error(`spawn codex ${code}`), { code });
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
  }
}

function testTextualMissingPathErrorsRemainRetryable() {
  for (const diagnostic of [
    "Error: No such file or directory (os error 2)",
    "Error: The system cannot find the file specified. (os error 2)",
  ]) {
    const original = new Error(
      ["Codex Exec exited with code 1:", diagnostic].join("\n"),
    );
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
  }
}

function testWorkerErrorClassificationPreservesExplicitFailures() {
  const explicit = new DeepScanNonRetryableError(
    "Explicitly rejected worker permission profile.",
  );
  assert.equal(classifyCodexWorkerError(explicit), explicit);

  const refusalMessages = [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
  ];
  for (const message of refusalMessages) {
    const original = new Error(message);
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
    assert.equal(isCodexCybersecurityPolicyRefusal(classified), true);

    const explicitRefusal = new DeepScanNonRetryableError(message);
    assert.equal(classifyCodexWorkerError(explicitRefusal), explicitRefusal);

    for (const unrecognized of [
      `Source fixture: ${message}`,
      `${message} Source fixture.`,
      JSON.stringify({ message }),
      `Codex Exec exited with code 1: ${message}`,
      `429 Too Many Requests: ${message}`,
      ` ${message}`,
      `${message}\n`,
      message.toLowerCase(),
    ]) {
      const unrelated = new Error(unrecognized);
      assert.equal(classifyCodexWorkerError(unrelated), unrelated);
      assert.equal(isCodexCybersecurityPolicyRefusal(unrelated), false);
    }
  }

  for (const message of [
    "config parser handles unknown keys",
    "failed to load configuration: invalid value",
    "agents.max_threads cannot be set when features.multi_agent_v2 is enabled",
    "authentication required",
    "not logged in",
    "missing API key",
    "Codex Exec exited with code 2: failed to load configuration: invalid value",
    "chatgpt authentication required for remote plugin catalog; api key auth is not supported",
    "chatgpt authentication required to sync remote plugins; api key auth is not supported",
  ]) {
    const original = new Error(message);
    assert.equal(classifyCodexWorkerError(original), original);
  }
  for (const code of ["ECONNRESET", "EPIPE", "ETIMEDOUT", "cyber_policy"]) {
    const original = Object.assign(new Error("Unrecognized worker failure"), {
      code,
    });
    assert.equal(classifyCodexWorkerError(original), original);
  }
}

async function testWindowsRootRelativePathsStayBoundToOriginalDrive() {
  assert.equal(
    resolveCodexPath(
      { CODEX_CLI_PATH: "\\Tools\\codex.exe" },
      "win32",
      process.arch,
      "C:\\original\\cwd",
    ),
    "C:\\Tools\\codex.exe",
  );
  assert.equal(
    resolveCodexPath(
      { CODEX_CLI_PATH: "/Tools/codex.exe" },
      "win32",
      process.arch,
      "D:\\original\\cwd",
    ),
    "D:\\Tools\\codex.exe",
  );

  const root = await temporaryDirectories.create(
    "codex-security-windows-home-",
  );
  const target = path.join(root, "target", "nested");
  await mkdir(target, { recursive: true });
  await mkdir(path.join(root, "target", "home"), { recursive: true });
  await mkdir(path.join(root, "home"));
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
    const child = spawnSync(
      process.execPath,
      [
        "-e",
        `const { realpathSync } = require('node:fs');
process.stdout.write(JSON.stringify({ cwd: process.cwd(), codexHome: process.env.CODEX_HOME, resolvedHome: realpathSync(process.env.CODEX_HOME) }));`,
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
    "node.exe",
  );
  const promptPath = path.join(fixture.root, "prompt.md");
  const workingDirectory = path.join(fixture.root, "artifacts");
  const codexHome = path.join(fixture.root, "codex-home");
  await mkdir(path.dirname(executable), { recursive: true });
  await mkdir(workingDirectory);
  await mkdir(codexHome);
  await writeFile(promptPath, "fixture long executable worker\n");
  await copyFile(process.execPath, executable);
  assert.ok(executable.length > 260);
  const previousCodexPath = process.env.CODEX_CLI_PATH;
  const previousCodexHome = process.env.CODEX_HOME;
  const originalSpawn = childProcess.spawn;
  const launchedCommands: string[] = [];
  const children: ChildProcess[] = [];
  childProcess.spawn = ((
    command: string,
    args: readonly string[],
    options: SpawnOptions,
  ) => {
    if (
      command !== executable &&
      command !== path.toNamespacedPath(executable)
    ) {
      return originalSpawn(command, args, options);
    }
    // Keep the production executable argument intact at Node's Windows spawn boundary.
    launchedCommands.push(command);
    const child = originalSpawn(
      command,
      [fixture.executablePath, ...args],
      options,
    );
    children.push(child);
    return child;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    process.env.CODEX_HOME = codexHome;
    for (const configured of [executable, path.toNamespacedPath(executable)]) {
      process.env.CODEX_CLI_PATH = configured;
      assert.equal(
        (await snapshotWorkerEnvironment()).CODEX_CLI_PATH,
        configured,
      );
      const result = await runWorker(promptPath, workingDirectory);
      assert.equal(result.threadId, "fixture-thread-id");
      const invocation = await readJson(fixture.markerPath);
      assert.deepEqual(invocation.argv.slice(0, 2), [
        "exec",
        "--experimental-json",
      ]);
      assertReadOnlyWorkerPolicy(invocation.argv);
      assert.equal(invocation.codexHome, await realpath(codexHome));
      const preflight = await readJson(fixture.preflightMarkerPath);
      assert.deepEqual(
        preflight.requests.map((request: { method: string }) => request.method),
        ["config/read", "permissionProfile/list"],
      );
      assert.equal(process.env.CODEX_CLI_PATH, configured);
    }
    assert.deepEqual(
      launchedCommands,
      Array(4).fill(path.toNamespacedPath(executable)),
    );
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    // The SDK removes child listeners when its event iterator closes.
    await Promise.all(
      children.map((child) => {
        if (
          child.stdout!.closed &&
          child.stderr!.closed &&
          (child.exitCode !== null || child.signalCode !== null)
        )
          return;
        return new Promise((resolve) => {
          child.once("close", resolve);
          child.kill();
        });
      }),
    );
    restoreEnv("CODEX_CLI_PATH", previousCodexPath);
    restoreEnv("CODEX_HOME", previousCodexHome);
  }
}

async function testWindowsWorkerEnvironmentPreservesMixedCaseKeys() {
  const root = await temporaryDirectories.create("codex-security-windows-env-");
  const values = {
    CODEX_CLI_PATH: path.join(root, "custom-codex.exe"),
    CODEX_HOME: root,
    CODEX_MANAGED_PACKAGE_ROOT: path.join(root, "managed-package"),
    LOCALAPPDATA: path.join(root, "local-app-data"),
  };
  const previousEnvironment = Object.entries(process.env).filter(([key]) =>
    Object.hasOwn(values, key.toUpperCase()),
  );
  try {
    for (const name of Object.keys(values)) delete process.env[name];
    for (const [name, value] of Object.entries(values))
      process.env[name.toLowerCase()] = value;

    const environment = await snapshotWorkerEnvironment();
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
    for (const name of Object.keys(values)) delete process.env[name];
    for (const [name, value] of previousEnvironment) process.env[name] = value;
  }
}

async function testWindowsAppsCodexFallsBackToRelocatedBinary() {
  const root = await temporaryDirectories.create(
    "codex-security-windows-cache-",
  );
  const localAppData = path.join(root, "LocalAppData");
  const olderBinary = path.join(
    localAppData,
    "OpenAI",
    "Codex",
    "bin",
    "11111111",
    "codex.exe",
  );
  const currentBinary = path.join(
    localAppData,
    "OpenAI",
    "Codex",
    "bin",
    "22222222",
    "codex.exe",
  );
  const emptyBinary = path.join(
    localAppData,
    "OpenAI",
    "Codex",
    "bin",
    "33333333",
    "codex.exe",
  );
  const protectedDirectory = path.join(
    root,
    "WindowsApps",
    "OpenAI.Codex_fixture",
    "resources",
  );
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetTriple =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : "x86_64-pc-windows-msvc";
  const managedPackage = path.join(
    protectedDirectory,
    "node_modules",
    "@openai",
    "codex",
  );
  const platformPackage = path.join(
    managedPackage,
    "node_modules",
    "@openai",
    `codex-win32-${architecture}`,
  );
  const protectedPackageBinary = path.join(
    platformPackage,
    "vendor",
    targetTriple,
    "bin",
    "codex.exe",
  );
  await mkdir(path.dirname(olderBinary), { recursive: true });
  await mkdir(path.dirname(currentBinary), { recursive: true });
  await mkdir(path.dirname(emptyBinary), { recursive: true });
  await mkdir(path.dirname(protectedPackageBinary), { recursive: true });
  await copyFile(process.execPath, olderBinary);
  await copyFile(process.execPath, currentBinary);
  await writeFile(emptyBinary, "");
  await writeFile(
    path.join(protectedDirectory, "codex.exe"),
    "protected direct binary",
  );
  await writeJson(path.join(managedPackage, "package.json"), {
    name: "@openai/codex",
  });
  await writeJson(path.join(platformPackage, "package.json"), {
    name: `@openai/codex-win32-${architecture}`,
  });
  await writeFile(protectedPackageBinary, "protected package binary");
  await utimes(olderBinary, new Date(1_000), new Date(1_000));
  await utimes(currentBinary, new Date(2_000), new Date(2_000));
  await utimes(emptyBinary, new Date(3_000), new Date(3_000));

  const resolved = resolveCodexPath(
    {
      CODEX_CLI_PATH:
        "C:\\Program Files\\WindowsApps\\OpenAI.Codex_fixture\\resources\\codex.exe",
      LOCALAPPDATA: localAppData,
    },
    "win32",
  );
  assert.equal(resolved, currentBinary);
  assert.equal(
    resolveCodexPath(
      {
        CODEX_MANAGED_PACKAGE_ROOT: managedPackage,
        Path: protectedDirectory,
        LOCALAPPDATA: localAppData,
      },
      "win32",
      architecture,
    ),
    currentBinary,
  );
  assert.equal(
    resolveCodexPath(
      {
        LOCALAPPDATA: path.relative(root, localAppData),
      },
      "win32",
      architecture,
      root,
    ),
    currentBinary,
  );
  assert.equal(
    resolveCodexPath(
      {
        localappdata: localAppData,
      },
      "win32",
      architecture,
    ),
    currentBinary,
  );
  const explicitOverride = path.join(root, "custom-codex.exe");
  assert.equal(
    resolveCodexPath(
      {
        CODEX_CLI_PATH: explicitOverride,
        CODEX_MANAGED_PACKAGE_ROOT: managedPackage,
        Path: protectedDirectory,
        LOCALAPPDATA: localAppData,
      },
      "win32",
      architecture,
    ),
    explicitOverride,
  );

  if (process.platform === "win32") {
    const launched = spawnSync(resolved, ["--version"], { encoding: "utf8" });
    assert.equal(launched.error, undefined);
    assert.equal(launched.status, 0);
    assert.equal(launched.stdout.trim(), process.version);
  }
}

async function testWindowsLauncherSkipsExtensionlessNpmShim() {
  const root = await temporaryDirectories.create(
    "codex-security-windows-launcher-",
  );
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
  assert.equal(
    ["ENOENT", "EPERM"].includes(
      (broken.error as NodeJS.ErrnoException | undefined)?.code!,
    ),
    true,
  );

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

async function testWindowsNpmPackageResolution(installation = "global") {
  const root = await temporaryDirectories.create("codex-security-windows-npm-");
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetTriple =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : "x86_64-pc-windows-msvc";
  const packageDirectory =
    installation === "managed"
      ? path.join(root, "node_modules")
      : path.join(root, "npm", "node_modules");
  const shimDirectory =
    installation === "managed"
      ? path.join(packageDirectory, ".bin")
      : path.join(root, "npm");
  const codexPackage = path.join(packageDirectory, "@openai", "codex");
  const platformPackage = path.join(
    codexPackage,
    "node_modules",
    "@openai",
    `codex-win32-${architecture}`,
  );
  const nativeBinary = path.join(
    platformPackage,
    "vendor",
    targetTriple,
    "bin",
    "codex.exe",
  );
  await mkdir(path.dirname(nativeBinary), { recursive: true });
  await mkdir(shimDirectory, { recursive: true });
  await writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n");
  await writeJson(path.join(codexPackage, "package.json"), {
    name: "@openai/codex",
  });
  await writeJson(path.join(platformPackage, "package.json"), {
    name: `@openai/codex-win32-${architecture}`,
  });
  await copyFile(process.execPath, nativeBinary);

  const environment = windowsLauncherEnvironment(shimDirectory);
  if (installation === "managed") {
    environment.CODEX_MANAGED_PACKAGE_ROOT = codexPackage;
  }
  assert.equal(
    await realpath(resolveCodexPath(environment, "win32", architecture)),
    await realpath(nativeBinary),
  );
  if (installation === "managed") {
    const mixedCaseEnvironment: NodeJS.ProcessEnv = {
      ...environment,
      codex_managed_package_root: codexPackage,
    };
    delete mixedCaseEnvironment.CODEX_MANAGED_PACKAGE_ROOT;
    assert.equal(
      await realpath(
        resolveCodexPath(mixedCaseEnvironment, "win32", architecture),
      ),
      await realpath(nativeBinary),
    );
  }
  if (process.platform === "win32") {
    assert.equal(
      (
        spawnSync("codex.exe", ["--version"], {
          encoding: "utf8",
          env: environment,
        }).error as NodeJS.ErrnoException | undefined
      )?.code,
      "ENOENT",
    );

    const fixed = spawnSync(
      resolveCodexPath(environment, "win32", architecture),
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
}

function windowsLauncherEnvironment(...directories: string[]) {
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
      env: process.env,
    });
    assert.equal(
      (globalCodex.error as NodeJS.ErrnoException | undefined)?.code,
      "ENOENT",
    );

    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture nested worker without global codex\n");

    const result = await runWorker(promptPath, workingDirectory);

    assert.equal(result.threadId, "fixture-thread-id");
    const invocation = await readJson(fixture.markerPath);
    assert.deepEqual(invocation.argv.slice(0, 2), [
      "exec",
      "--experimental-json",
    ]);
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
  await mkdir(workingDirectory);
  await mkdir(nonExecutableDirectory);
  await mkdir(path.join(directoryShadow, "codex"), { recursive: true });
  await mkdir(binaryDirectory);
  await mkdir(homeTargetChild, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  assert.notEqual(workingDirectory, originalCwd);
  await writeFile(promptPath, "fixture bound worker executable and home\n");
  await writeFile(
    path.join(nonExecutableDirectory, "codex"),
    "not executable\n",
  );
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
    path.dirname(process.execPath),
  ].join(path.delimiter);
  try {
    for (const [configured, expectedExecutable] of [
      [
        path.relative(originalCwd, fixture.executablePath),
        fixture.executablePath,
      ],
      [undefined, codexPath],
      ["codex", codexPath],
    ] as const) {
      if (configured === undefined) delete process.env.CODEX_CLI_PATH;
      else process.env.CODEX_CLI_PATH = configured;
      assert.equal(resolveCodexPath(), expectedExecutable);
      const result = await runWorker(promptPath, workingDirectory);

      assert.equal(result.threadId, "fixture-thread-id");
      const preflight = await readJson(fixture.preflightMarkerPath);
      const invocation = await readJson(fixture.markerPath);
      assert.equal(preflight.cwd, await realpath(workingDirectory));
      assert.equal(invocation.cwd, originalCwd);
      assert.equal(preflight.codexHome, expectedHome);
      assert.equal(invocation.codexHome, expectedHome);
      assert.equal(process.env.CODEX_HOME, relativeHome);
      assert.deepEqual(preflight.requests, [
        { method: "config/read", cwd: workingDirectory },
        { method: "permissionProfile/list", cwd: workingDirectory },
      ]);
      assert.deepEqual(invocation.argv.slice(0, 2), [
        "exec",
        "--experimental-json",
      ]);
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
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    assert.equal(workingDirectory.startsWith("/repo/"), false);
    await writeFile(promptPath, "fixture worker prompt\n");
    const onThreadId = mock.fn();
    const result = await new CodexSdkWorkerExecutor({
      model: "gpt-5.6-luna",
      reasoningEffort: "xhigh",
      parentSandbox: trustedParentSandboxWithDenials,
    }).run(
      workerRequest(promptPath, workingDirectory, {
        subagents: 3,
        onThreadStarted: onThreadId,
      }),
    );
    assert.equal(result.threadId, "fixture-thread-id");
    const callbackThreadId = onThreadId.mock.calls.at(-1)?.arguments[0];
    assert.equal(callbackThreadId, "fixture-thread-id");
    const invocation = await readJson(fixture.markerPath);
    assert.equal(invocation.stdin, "fixture worker prompt\n");
    assert.equal(
      invocation.originator,
      process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE || "codex_sdk_ts",
    );
    assert.deepEqual(invocation.argv.slice(0, 2), [
      "exec",
      "--experimental-json",
    ]);
    assertFlagPair(invocation.argv, "--model", "gpt-5.6-luna");
    assertConfigOverrides(invocation.argv, {
      model_reasoning_effort: "xhigh",
      "mcp_servers.codex-security.command": "node",
      "mcp_servers.codex-security.enabled": false,
    });
    assertReadOnlyWorkerPolicy(invocation.argv);
    assert.equal(
      workerPermissionProfileOverride(invocation.argv),
      'permissions.codex_security_deep_scan_worker={extends=":read-only",filesystem={":root"="read","/repo/.env"="deny","/repo/**/.secret"="deny","/repo/**/*.pem"="deny",glob_scan_max_depth=3},network={enabled=false}}',
    );
    assertWorkerSubagentPolicy(invocation.argv, 3);
    assertFlagPair(invocation.argv, "--cd", workingDirectory);
    assert.equal(invocation.argv.includes("--skip-git-repo-check"), true);
  }, deniedWorkerPermissionProfile);
}

async function testOpenAiCredentialsReachWorker() {
  const noAccount = { account: null, requiresOpenaiAuth: true };
  let virtualenv: string | undefined;
  if (process.platform !== "win32") {
    const root = await temporaryDirectories.create(
      "codex-security-worker-python-",
    );
    virtualenv = path.join(root, "venv");
    const created = spawnSync(
      "python3",
      ["-m", "venv", "--without-pip", virtualenv],
      {
        encoding: "utf8",
        env: {
          PATH: process.env.PATH,
          LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH,
        },
      },
    );
    assert.equal(created.status, 0, created.stderr);
  }
  const cases = [
    { openai: "synthetic-openai-key", expected: "synthetic-openai-key" },
    {
      openai: "  synthetic-openai-key  ",
      codex: " ",
      expected: "synthetic-openai-key",
    },
    {
      openai: "synthetic-openai-key",
      codex: "synthetic-selected-key",
      expected: "synthetic-selected-key",
    },
    { codex: "synthetic-selected-key", expected: "synthetic-selected-key" },
    {
      openai: "synthetic-openai-key",
      accountResult: { account: { type: "apiKey" }, requiresOpenaiAuth: true },
    },
    {
      openai: "synthetic-openai-key",
      accountResult: { account: { type: "chatgpt" }, requiresOpenaiAuth: true },
    },
    {
      openai: "synthetic-provider-key",
      accountResult: { account: null, requiresOpenaiAuth: false },
    },
    {},
    { openai: " " },
  ];
  for (const entry of cases) {
    const fixture = await fakeCodexFixture(
      emptyWorkerPermissionProfile,
      true,
      entry.accountResult ?? noAccount,
    );
    const runtimeEnvironment = {
      PATH: [
        virtualenv === undefined
          ? path.join(fixture.root, "runner-tools")
          : path.join(virtualenv, "bin"),
        path.dirname(process.execPath),
      ].join(path.delimiter),
      HOME: path.join(fixture.root, "home"),
      PYTHON:
        virtualenv === undefined
          ? path.join(fixture.root, "tools", "python3")
          : "python3",
      PYTHONUTF8: "1",
      LD_LIBRARY_PATH:
        (process.env.LD_LIBRARY_PATH === undefined
          ? ""
          : process.env.LD_LIBRARY_PATH + path.delimiter) +
        path.join(fixture.root, "libraries"),
      CODEX_SECURITY_STATE_DIR: path.join(fixture.root, "state"),
      RUNNER_TRACKING_ID: "synthetic-worker-job",
    };
    const previousEnvironment = [
      "OPENAI_API_KEY",
      "CODEX_API_KEY",
      "CODEX_CLI_PATH",
      "CODEX_HOME",
      ...Object.keys(runtimeEnvironment),
    ].map((name) => [name, process.env[name]] as const);
    const originalSpawn = childProcess.spawn;
    try {
      restoreEnv("OPENAI_API_KEY", entry.openai);
      restoreEnv("CODEX_API_KEY", entry.codex);
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = fixture.root;
      Object.assign(process.env, runtimeEnvironment);
      childProcess.spawn = ((
        command: string,
        args: readonly string[],
        options: SpawnOptions,
      ) =>
        originalSpawn(
          command,
          command === process.execPath ||
            command === path.toNamespacedPath(process.execPath)
            ? [fixture.executablePath, ...args]
            : args,
          options,
        )) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const promptPath = path.join(fixture.root, "prompt.md");
      await writeFile(
        promptPath,
        `CAPTURE_SYNTHETIC_OPENAI_AUTH\n${virtualenv === undefined ? "" : "CAPTURE_SYNTHETIC_PYTHON\n"}`,
      );
      const executor = new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
      });
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resume"]) {
          await executor.run(
            workerRequest(promptPath, fixture.root, { kind, resumeThreadId }),
          );
          const preflight = await readJson(fixture.preflightMarkerPath);
          const invocation = await readJson(fixture.markerPath);
          assert.equal(preflight.codexHome, fixture.root);
          assert.equal(
            preflight.runnerTrackingId,
            runtimeEnvironment.RUNNER_TRACKING_ID,
          );
          assert.equal(
            preflight.libraryPath,
            runtimeEnvironment.LD_LIBRARY_PATH,
          );
          assert.equal(invocation.codexHome, fixture.root);
          assert.deepEqual(invocation.runtimeEnvironment, runtimeEnvironment);
          if (virtualenv !== undefined) {
            assert.equal(invocation.pythonPrefix, virtualenv);
            assert.equal(
              invocation.pythonLibraryPath,
              runtimeEnvironment.LD_LIBRARY_PATH,
            );
          }
          for (const [name, value] of Object.entries(runtimeEnvironment)) {
            assert.equal(process.env[name], value);
          }
          assert.equal(
            invocation.openaiAuthentication.CODEX_API_KEY,
            entry.expected,
          );
          assert.equal(
            invocation.openaiAuthentication.OPENAI_API_KEY,
            entry.openai,
          );
          assert.equal(process.env.CODEX_API_KEY, entry.codex);
          assert.equal(process.env.OPENAI_API_KEY, entry.openai);
          assert.equal(
            invocation.argv.some((arg: string) => arg.includes("synthetic-")),
            false,
          );
        }
      }
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      for (const [name, value] of previousEnvironment) restoreEnv(name, value);
    }
  }
}

async function testWorkerRuntimeSettings() {
  const cases = [
    ["", undefined],
    ['model_reasoning_summary = "none"\n', "none"],
    ['model_reasoning_summary = "auto"\n', "auto"],
    [
      'model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel_reasoning_summary = "concise"\n',
      "concise",
    ],
    [
      'model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel = "fixture-model"\n[profiles.other]\nmodel_reasoning_summary = "detailed"\n',
      "none",
    ],
  ];
  const saved = [
    "PYTHON",
    "PATH",
    "CODEX_SECURITY_GIT",
    "GIT_SSH_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "SYNTHETIC_GATEWAY_KEY",
  ].map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  try {
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_API_KEY;
    for (const [configuration, expected] of cases) {
      const fixture = await fakeCodexFixture(
        deniedWorkerPermissionProfile,
        true,
        { account: null, requiresOpenaiAuth: false },
      );
      const python = path.join(fixture.root, "selected venv", "bin", "python");
      const helperPython = path.join(
        fixture.root,
        "helper venv",
        "bin",
        "python",
      );
      process.env.PYTHON = python;
      const gitEnvironment = {
        PATH: path.join(fixture.root, "selected tools"),
        CODEX_SECURITY_GIT: path.join(fixture.root, "selected tools", "git"),
        GIT_SSH_COMMAND: "synthetic-ssh --fixture",
        GIT_CONFIG_GLOBAL: path.join(fixture.root, "operator.gitconfig"),
      };
      Object.assign(process.env, gitEnvironment);
      const configPath = path.join(fixture.root, "active scan config.toml");
      const codexHome = path.join(fixture.root, "scan home");
      const promptPath = path.join(fixture.root, "prompt.md");
      await mkdir(codexHome);
      await writeFile(
        path.join(codexHome, "config.toml"),
        `model = "fixture-inherited-model"
model_reasoning_effort = "medium"
model_provider = "synthetic"
[model_providers.synthetic]
name = "Synthetic gateway"
base_url = "https://gateway.example.test/v1"
wire_api = "responses"
env_key = "SYNTHETIC_GATEWAY_KEY"`,
      );
      await writeFile(configPath, configuration!);
      await writeFile(promptPath, "synthetic worker configuration fixture");
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = codexHome;
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
      process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = path.join(
        fixture.root,
        "deep settings.toml",
      );
      const launches: {
        command?: string;
        args: readonly string[];
        environment?: NodeJS.ProcessEnv;
        markerPath: string;
      }[] = [];
      childProcess.spawn = ((
        command: string,
        args: readonly string[],
        options: SpawnOptions,
      ) => {
        const markerPath = path.join(
          fixture.root,
          `invocation-${launches.length}.json`,
        );
        const environment = {
          ...options!.env,
          FAKE_CODEX_MARKER: markerPath,
          FAKE_CODEX_PREFLIGHT_MARKER: markerPath,
        };
        launches.push({ command, args, environment, markerPath });
        return originalSpawn(
          command,
          command === process.execPath ||
            command === path.toNamespacedPath(process.execPath)
            ? [fixture.executablePath, ...args]
            : args,
          { ...options, env: environment },
        );
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const settings = [
        { model: "gpt-5.6-sol", reasoningEffort: "xhigh" },
        { model: "gpt-6-astra", reasoningEffort: "ultra" },
        { model: "gpt-6.1-sol", reasoningEffort: "max" },
        { model: "gpt-6-sol", reasoningEffort: "high" },
        { model: "fixture-future-model", reasoningEffort: "future-effort" },
        // Omitted settings preserve the model and effort in the Codex home.
        {},
      ];
      const providerKeys = settings.map((_, index) =>
        index < 2 ? `synthetic-gateway-key-${index}` : undefined,
      );
      const executors = settings.map(
        (modelSettings) =>
          new CodexSdkWorkerExecutor({
            ...modelSettings,
            parentSandbox: trustedParentSandboxWithDenials,
            artifactContext: {
              pluginRoot: fixture.root,
              repoRoot: fixture.root,
              scanId: `fixture-scan-${modelSettings.model ?? "inherited"}`,
              pythonCommand: helperPython,
            },
          }),
      );
      // A running coordinator retains its settings if the source file changes.
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
          launches.length = 0;
          await Promise.all(
            executors.map((executor, index) => {
              // Each concurrent launch snapshots its own scan environment.
              if (providerKeys[index] === undefined) {
                delete process.env.SYNTHETIC_GATEWAY_KEY;
              } else {
                process.env.SYNTHETIC_GATEWAY_KEY = providerKeys[index];
              }
              return executor.run(
                workerRequest(promptPath, fixture.root, {
                  kind,
                  resumeThreadId,
                  artifactContext: {
                    root: fixture.root,
                    layout: kind === "dedup" ? "reducer" : "worker",
                    ...(kind === "dedup"
                      ? {
                          deepReducer: {
                            scanRoot: fixture.root,
                            claimedWorkers: [],
                          },
                        }
                      : {}),
                  },
                }),
              );
            }),
          );
          const workerLaunches = launches.filter(
            ({ args }) => args[0] === "exec",
          );
          assert.equal(workerLaunches.length, settings.length);
          for (const [
            index,
            { model, reasoningEffort },
          ] of settings.entries()) {
            const workerLaunch = workerLaunches.find(({ args }) =>
              model === undefined
                ? !args.includes("--model")
                : args[args.indexOf("--model") + 1] === model,
            );
            assert.ok(workerLaunch, `missing worker launch for ${model}`);
            assert.equal(
              workerLaunch.command,
              process.platform === "win32"
                ? path.toNamespacedPath(process.execPath)
                : process.execPath,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_CLI_PATH,
              process.execPath,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_HOME,
              await realpath(codexHome),
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_CONFIG_PATH,
              configPath!,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
            );
            assert.equal(
              workerPermissionProfileOverride(workerLaunch.args),
              'permissions.codex_security_deep_scan_worker={extends=":read-only",filesystem={":root"="read","/repo/.env"="deny","/repo/**/.secret"="deny","/repo/**/*.pem"="deny",glob_scan_max_depth=3},network={enabled=false}}',
            );
            const invocation = await readJson(workerLaunch.markerPath);
            assert.equal(invocation.providerKey, providerKeys[index]);
            assert.equal(workerLaunch.environment!.CODEX_API_KEY, undefined);
            assert.equal(
              process.env.SYNTHETIC_GATEWAY_KEY,
              providerKeys.at(-1),
            );
            assertConfigOverrides(invocation.argv, {
              model_reasoning_summary: expected,
            });
            assert.deepEqual(
              invocation.argv.filter((arg: string) =>
                arg.startsWith("model_reasoning_effort="),
              ),
              reasoningEffort === undefined
                ? []
                : [`model_reasoning_effort=${JSON.stringify(reasoningEffort)}`],
            );
            if (model === undefined) {
              assert.equal(invocation.argv.includes("--model"), false);
            } else {
              assertFlagPair(invocation.argv, "--model", model);
            }
            assert.equal(
              invocation.argv.includes("resume"),
              resumeThreadId !== undefined,
            );
            assert.equal(invocation.configPath, configPath);
            assert.deepEqual(invocation.gitEnvironment, gitEnvironment);
            for (const [name, value] of Object.entries(gitEnvironment)) {
              assert.equal(process.env[name], value);
            }
            assert.equal(invocation.python, python);
            assertConfigOverrides(invocation.argv, {
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_PYTHON_COMMAND":
                helperPython,
            });
            assert.equal(process.env.PYTHON, python);
            assert.equal(
              invocation.deepConfigPath,
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
            );
            assertReadOnlyWorkerPolicy(invocation.argv);
            assertWorkerSubagentPolicy(invocation.argv, 0);
          }
          for (const launch of launches.filter(({ args }) =>
            args.includes("app-server"),
          )) {
            const preflight = await readJson(launch.markerPath);
            assert.deepEqual(preflight.gitEnvironment, gitEnvironment);
            assert.equal(
              workerPermissionProfileOverride(launch.args),
              workerPermissionProfileOverride(workerLaunches[0].args),
            );
          }
          await writeFile(configPath, 'model_reasoning_summary = "detailed"\n');
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}

async function testWorkerCyberAccessSettings() {
  const cases: {
    name: string;
    configuration: string;
    program?: string;
    serviceTier?: string;
    features?: Record<string, boolean>;
    configPath?: string;
    executor?: import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  }[] = [
    { name: "unset", configuration: "" },
    {
      name: "blue",
      configuration:
        'service_tier = "fast"\n[codex_security]\ncyber_access_program = "daybreak_blue"\n[features]\napi_key_cyber_access_programs = true\napi_key_model_discovery = true\n',
      serviceTier: "fast",
      program: "daybreak_blue",
      features: {
        api_key_cyber_access_programs: true,
        api_key_model_discovery: true,
      },
    },
    {
      name: "explicit-false",
      configuration:
        'service_tier = "flex"\n[codex_security]\ncyber_access_program = "daybreak_blue"\n[features]\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n',
      serviceTier: "flex",
      program: "daybreak_blue",
      features: {
        api_key_cyber_access_programs: false,
        api_key_model_discovery: false,
      },
    },
    {
      name: "other-program",
      configuration:
        'service_tier = "flex"\nprofile = "cloud.production"\n[profiles."cloud.production"]\nservice_tier = "fast"\n[codex_security]\ncyber_access_program = "standard"\n[features]\napi_key_cyber_access_programs = true\napi_key_model_discovery = false\n',
      serviceTier: "fast",
      program: "standard",
      features: {
        api_key_cyber_access_programs: true,
        api_key_model_discovery: false,
      },
    },
    {
      name: "features-only",
      configuration:
        'service_tier = "fast"\nprofile = "selected"\n[profiles.selected]\nmodel = "fixture-model"\n[features]\napi_key_cyber_access_programs = false\napi_key_model_discovery = true\n',
      serviceTier: "fast",
      features: {
        api_key_cyber_access_programs: false,
        api_key_model_discovery: true,
      },
    },
  ];
  const saved = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
  ].map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  const fixture = await fakeCodexFixture();
  const promptPath = path.join(fixture.root, "prompt.md");
  const launches: { args: readonly string[]; markerPath: string }[] = [];
  try {
    delete process.env.OPENAI_API_KEY;
    process.env.CODEX_API_KEY = "synthetic-worker-api-key";
    process.env.CODEX_CLI_PATH = process.execPath;
    process.env.CODEX_HOME = fixture.root;
    await writeFile(promptPath, "CAPTURE_SYNTHETIC_OPENAI_AUTH");
    childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: SpawnOptions,
    ) => {
      const markerPath = path.join(
        fixture.root,
        `cyber-${launches.length}.json`,
      );
      const environment = {
        ...options!.env,
        FAKE_CODEX_MARKER: markerPath,
        FAKE_CODEX_PREFLIGHT_MARKER: markerPath,
      };
      launches.push({ args, markerPath });
      return originalSpawn(command, [fixture.executablePath, ...args], {
        ...options,
        env: environment,
      });
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    for (const testCase of cases) {
      testCase.configPath = path.join(fixture.root, `${testCase.name}.toml`);
      await writeFile(testCase.configPath, testCase.configuration);
      testCase.executor = new CodexSdkWorkerExecutor({
        model: testCase.name,
        parentSandbox: trustedParentSandbox,
      });
    }
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
        launches.length = 0;
        await Promise.all(
          cases.map((testCase) => {
            // Each scan captures its own config before its asynchronous launch.
            process.env.CODEX_SECURITY_CONFIG_PATH = testCase.configPath;
            return testCase.executor!.run(
              workerRequest(promptPath, fixture.root, { kind, resumeThreadId }),
            );
          }),
        );
        const workerLaunches = launches.filter(
          ({ args }) => args[0] === "exec",
        );
        assert.equal(workerLaunches.length, cases.length);
        for (const { name, program, serviceTier, features = {} } of cases) {
          const launch = workerLaunches.find(
            ({ args }) => args[args.indexOf("--model") + 1] === name,
          );
          const invocation = await readJson(launch!.markerPath);
          assert.deepEqual(
            invocation.argv.filter((arg: string) =>
              arg.startsWith("service_tier="),
            ),
            serviceTier === undefined
              ? []
              : [`service_tier=${JSON.stringify(serviceTier)}`],
          );
          if (program === undefined) {
            assert.equal(
              invocation.argv.includes("--cyber-access-program"),
              false,
            );
          } else {
            assertFlagPair(invocation.argv, "--cyber-access-program", program);
          }
          for (const feature of [
            "api_key_cyber_access_programs",
            "api_key_model_discovery",
          ]) {
            assert.deepEqual(
              invocation.argv.filter((arg: string) =>
                arg.startsWith(`features.${feature}=`),
              ),
              features[feature] === undefined
                ? []
                : [`features.${feature}=${features[feature]}`],
            );
          }
          assert.equal(
            invocation.openaiAuthentication.CODEX_API_KEY,
            "synthetic-worker-api-key",
          );
          assert.equal(
            invocation.argv.includes("resume"),
            resumeThreadId !== undefined,
          );
          assertReadOnlyWorkerPolicy(invocation.argv);
          assertWorkerSubagentPolicy(invocation.argv, 0);
        }
        // Running coordinators and their resumed workers retain their own settings.
        for (const { configPath } of cases) {
          await writeFile(
            configPath!,
            '[codex_security]\ncyber_access_program = "daybreak_red"\n[features]\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n',
          );
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}

async function testBedrockCredentialsReachWorker() {
  const fixture = await fakeCodexFixture();
  const mcpConfig = await readJson(import.meta.dirname, "../../.mcp.json");
  const awsEnvironment = Object.fromEntries(
    mcpConfig.mcpServers["codex-security"].env_vars
      .filter((name: string) => name.startsWith("AWS_"))
      .map((name: string) => [name, `synthetic-bedrock-${name.toLowerCase()}`]),
  );
  assert.ok(awsEnvironment.AWS_BEARER_TOKEN_BEDROCK);
  assert.ok(awsEnvironment.AWS_ACCESS_KEY_ID);
  assert.ok(awsEnvironment.AWS_SECRET_ACCESS_KEY);
  const environment = {
    ...awsEnvironment,
    CODEX_CLI_PATH: fixture.executablePath,
    FAKE_CODEX_BEDROCK_ENV_KEYS: JSON.stringify(Object.keys(awsEnvironment)),
  };
  const previousEnvironment = Object.keys(environment).map(
    (name) => [name, process.env[name]] as const,
  );
  Object.assign(process.env, environment);

  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "CAPTURE_SYNTHETIC_BEDROCK_AUTH\n");
    const executor = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    });
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "fixture-bedrock-resume"]) {
        const result = await executor.run(
          workerRequest(promptPath, workingDirectory, { kind, resumeThreadId }),
        );
        assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
        const invocation = await readJson(fixture.markerPath);
        assert.deepEqual(invocation.bedrockAuthentication, awsEnvironment);
        assert.equal(
          invocation.argv.includes("resume"),
          resumeThreadId !== undefined,
        );
        assert.ok(
          invocation.argv.some((arg: string) =>
            arg.includes("mcp_servers.codex-security.enabled=false"),
          ),
        );
      }
    }
  } finally {
    for (const [name, value] of previousEnvironment) {
      restoreEnv(name, value);
    }
  }
}

async function testZeroSubagentsPreservesHostRestrictions() {
  for (const model of ["gpt-5.6-luna", "gpt-5.6-sol"]) {
    await withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
      await writeFile(promptPath, "fixture zero-subagent worker prompt\n");
      const result = await new CodexSdkWorkerExecutor({
        model,
        parentSandbox: trustedParentSandbox,
      }).run(workerRequest(promptPath, workingDirectory));
      assert.equal(result.threadId, "fixture-thread-id");
      const invocation = await readJson(fixture.markerPath);
      assertFlagPair(invocation.argv, "--model", model);
      assertWorkerSubagentPolicy(invocation.argv, 0);
      assertReadOnlyWorkerPolicy(invocation.argv);
    });
  }
}

async function testArtifactServerUsesExtendedStartupTimeout() {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, "fixture artifact worker prompt\n");
    const result = await new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
      artifactContext: {
        pluginRoot: fixture.root,
        repoRoot: fixture.root,
        scanId: "fixture-scan-id",
      },
    }).run(
      workerRequest(promptPath, workingDirectory, {
        artifactContext: { root: workingDirectory, layout: "worker" },
      }),
    );
    assert.equal(result.threadId, "fixture-thread-id");
    const invocation = await readJson(fixture.markerPath);
    assertConfigOverrides(invocation.argv, {
      "mcp_servers.cs_artifacts.startup_timeout_sec": 180,
      "mcp_servers.cs_artifacts.required": true,
      "mcp_servers.cs_artifacts.tool_timeout_sec": 86400,
    });
  });
}

async function testSdkResumesExistingThread() {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, "original worker prompt\n");
    const result = await new CodexSdkWorkerExecutor({
      model: "gpt-5.6-sol",
      reasoningEffort: "ultra",
      parentSandbox: trustedParentSandbox,
    }).run(
      workerRequest(promptPath, workingDirectory, {
        subagents: 3,
        resumeThreadId: "fixture-existing-thread",
        continuationPrompt: "continue the existing worker\n",
      }),
    );
    assert.equal(result.threadId, "fixture-existing-thread");
    const invocation = await readJson(fixture.markerPath);
    const resumeIndex = invocation.argv.indexOf("resume");
    assert.notEqual(resumeIndex, -1);
    assert.equal(invocation.argv[resumeIndex + 1], "fixture-existing-thread");
    assertFlagPair(invocation.argv, "--model", "gpt-5.6-sol");
    assertConfigOverrides(invocation.argv, { model_reasoning_effort: "ultra" });
    assertReadOnlyWorkerPolicy(invocation.argv);
    assertWorkerSubagentPolicy(invocation.argv, 3);
    assert.equal(invocation.stdin, "continue the existing worker\n");
  });
}

async function testRetryNotificationDoesNotInterruptTurn() {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, "RETRYABLE_STREAM_ERROR\n");
    const result = await runWorker(promptPath, workingDirectory, {
      subagents: 3,
    });
    assert.equal(result.threadId, "fixture-thread-id");
    const invocation = await readJson(fixture.markerPath);
    assert.equal(invocation.argv.includes("--model"), false);
    assertConfigOverrides(invocation.argv, {
      model_reasoning_effort: undefined,
    });
  });
}

async function testSandboxNamespaceDiagnosticIsSanitized() {
  const result = await runFixtureWorker(
    "BWRAP_NAMESPACE_FAILURE",
    "discovery",
    3,
  );
  assert.deepEqual(result.diagnostics, [
    {
      code: "sandbox_namespace_exhausted",
      message: "Codex worker sandbox namespace creation failed (bwrap ENOSPC).",
    },
  ]);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /super-secret-command|private source text/);
}

async function testOwnedArtifactToolFailureDiagnosticIsSanitized() {
  for (const { prompt, tool, reason } of [
    {
      prompt: "OWNED_ARTIFACT_TOOL_REJECTED",
      tool: "record_codex_security_deep_reduction",
      reason: "returned an error",
    },
    {
      prompt: "OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "record_codex_security_deep_reduction",
      reason: "transport failed",
    },
    {
      prompt: "OWNED_ARTIFACT_TOOL_UNCLASSIFIED_FAILURE",
      tool: "record_codex_security_deep_reduction",
      reason: "failed",
    },
    {
      prompt: "LEGACY_OWNED_ARTIFACT_TOOL_REJECTED",
      tool: "record_codex_security_deep_reduction",
      reason: "returned an error",
    },
    {
      prompt: "DISCOVERY_OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "record_codex_security_discovery_candidates",
      reason: "transport failed",
    },
    { prompt: "FOREIGN_ARTIFACT_TOOL_REJECTED" },
    {
      prompt: "ADDITIONAL_OWNED_ARTIFACT_TOOL_TRANSPORT_FAILED",
      tool: "additional_codex_security_worker_tool",
      reason: "transport failed",
    },
  ]) {
    const result = await runFixtureWorker(prompt);
    if (tool) {
      assert.deepEqual(result.diagnostics, [
        {
          code: "artifact_tool_failed",
          message: `Codex worker artifact tool ${tool} ${reason}.`,
        },
      ]);
    } else {
      assert.equal(result.diagnostics, undefined);
    }
    assert.doesNotMatch(
      JSON.stringify(result),
      /synthetic-secret|private source|private output|private\/customer\/path/i,
    );
  }
}

function testCodeModeFrameDiagnosticBoundaries() {
  const failedArtifactTool = {
    type: "mcp_tool_call",
    server: "cs_artifacts",
    tool: "get_codex_security_deep_reducer_inputs",
    status: "failed",
  };
  const resultWithText = (text: string) => ({
    content: [{ type: "text", text }],
  });
  for (const item of [
    { type: "error", message: ipcFrameError },
    { ...failedArtifactTool, error: { message: ipcFrameError } },
    { ...failedArtifactTool, result: resultWithText(ipcFrameError) },
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendSafeItemDiagnostic(diagnostics, failedArtifactTool);
    appendSafeItemDiagnostic(diagnostics, item);
    appendSafeItemDiagnostic(diagnostics, failedArtifactTool);
    assert.deepEqual(diagnostics, [
      { code: "artifact_tool_failed", message: ipcFrameError },
    ]);
  }
  for (const message of [
    `private source: ${ipcFrameError}`,
    `${ipcFrameError} private output`,
    `${ipcFrameError}\n`,
    JSON.stringify({ error: ipcFrameError }),
    ipcFrameError.replace("76008279", "unknown"),
    "private path /customer/repo: IPC frame limit exceeded",
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendSafeItemDiagnostic(diagnostics, { type: "error", message });
    appendSafeItemDiagnostic(diagnostics, {
      ...failedArtifactTool,
      result: resultWithText(message),
    });
    assert.deepEqual(diagnostics, [
      {
        code: "artifact_tool_failed",
        message:
          "Codex worker artifact tool get_codex_security_deep_reducer_inputs returned an error.",
      },
    ]);
  }
  for (const item of [
    {
      ...failedArtifactTool,
      server: "foreign_server",
      result: resultWithText(ipcFrameError),
    },
    {
      type: "command_execution",
      status: "failed",
      aggregated_output: ipcFrameError,
    },
    { type: "agent_message", text: ipcFrameError },
    { type: "unknown", status: "failed", error: { message: ipcFrameError } },
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendSafeItemDiagnostic(diagnostics, item);
    assert.deepEqual(diagnostics, []);
  }
}

async function testCodeModeFrameDiagnosticSurvivesSuccessfulTurn() {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    for (const event of [
      { type: "error", message: ipcFrameError },
      {
        type: "item.completed",
        item: { id: "error-1", type: "error", message: ipcFrameError },
      },
    ]) {
      await writeFile(
        promptPath,
        `IPC_DIAGNOSTIC_EVENT\n${JSON.stringify(event)}\n`,
      );
      const result = await runWorker(promptPath, workingDirectory, {
        kind: "dedup",
      });
      assert.equal(result.threadId, "fixture-thread-id");
      assert.deepEqual(result.diagnostics, [
        { code: "artifact_tool_failed", message: ipcFrameError },
      ]);
    }
  });
}

async function testStreamTerminationWithoutTerminalEventFails() {
  await assert.rejects(
    runFixtureWorker("INCOMPLETE_STREAM", "discovery", 3),
    /before turn\.completed.*fixture stream interrupted/i,
  );
}

async function testAbortPropagation() {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, "BLOCK_AFTER_START\n");
    const abortController = new AbortController();
    const execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: abortController.signal,
      onThreadStarted: () => abortController.abort("fixture cancellation"),
    });
    await assert.rejects(
      execution,
      (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
        error?.name === "AbortError" ||
        /abort|SIGTERM/i.test(error?.message ?? ""),
    );
  });
}

async function testCompletedWorkerSettlesWithoutWaitingForProcessExit() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  const controller = new AbortController();
  const unexpectedErrors: unknown[] = [];
  const captureUnexpectedError = (error: NodeJS.ErrnoException) =>
    unexpectedErrors.push(error);
  let execution;
  let timeout;
  let childPid!: number;

  process.on("uncaughtException", captureUnexpectedError);
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "COMPLETE_THEN_HANG\n");
    execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    }).run({
      kind: "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: controller.signal,
    });

    const result = await Promise.race([
      execution,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort("completed worker fixture timed out");
          reject(
            new Error("completed worker did not settle after turn.completed"),
          );
        }, 1_000);
      }),
    ]);
    clearTimeout(timeout);
    assert.equal(result.threadId, "fixture-thread-id");
    childPid = (await readJson(fixture.markerPath)).pid;

    controller.abort("coordinator immediately canceled its remaining workers");
    await new Promise((resolve) => setTimeout(resolve, 250));

    assert.deepEqual(unexpectedErrors, []);
    assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
  } finally {
    clearTimeout(timeout);
    controller.abort("completed worker fixture cleanup");
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

async function testUnstructuredConfigurationFailureRemainsRetryable() {
  await assert.rejects(
    runFixtureWorker("CONFIG_ERROR", "setup"),
    (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
      error?.name === "Error" &&
      error.message.startsWith("Codex Exec exited with code 2:"),
  );
}

async function testUnstructuredThreadStartFailureRemainsRetryable() {
  await assert.rejects(
    runFixtureWorker("THREAD_START_CONFIG_ERROR", "setup"),
    (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
      error?.name === "Error" &&
      error.message.startsWith("Codex Exec exited with code 1:"),
  );
}

async function testPolicyFailuresRemainWorkerErrors() {
  for (const prompt of [
    "CYBER_POLICY_ERROR",
    "SAFETY_POLICY_ERROR",
    "CYBERSECURITY_RISK_ERROR",
    "HIGH_RISK_CYBER_ACTIVITY_ERROR",
    "UPSTREAM_CYBERSECURITY_RISK_ERROR",
    "UPSTREAM_HIGH_RISK_CYBER_ACTIVITY_ERROR",
  ]) {
    await assert.rejects(
      runFixtureWorker(prompt),
      (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
        error?.name === "Error" && isCodexCybersecurityPolicyRefusal(error),
    );
  }
}

async function testRateLimitPolicyFailureRemainsRetryable() {
  await assert.rejects(
    runFixtureWorker("RATE_LIMIT_CYBER_POLICY_ERROR"),
    (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
      error?.name === "Error" &&
      /429 Too Many Requests/.test(error?.message ?? ""),
  );
}

async function testMalformedCommandEventsRemainRetryable() {
  for (const output of [
    "ordinary source text",
    "config parser handles unknown keys",
    "authentication required",
    "Request blocked by cyberPolicy.",
    "This request has been flagged for possible cybersecurity risk.",
  ]) {
    await withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
      await writeFile(
        promptPath,
        `MALFORMED_COMMAND_EVENT\n${JSON.stringify(output)}\n`,
      );
      const onThreadId = mock.fn();
      await assert.rejects(
        runWorker(promptPath, workingDirectory, {
          onThreadStarted: onThreadId,
        }),
        (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
          error?.name === "Error" &&
          error.cause instanceof SyntaxError &&
          error.message.startsWith("Failed to parse item: ") &&
          error.message.includes('"id":"fixture-command"') &&
          error.message.includes(JSON.stringify(output)),
        `Malformed command output must remain retryable: ${output}`,
      );
      const threadId = onThreadId.mock.calls.at(-1)?.arguments[0];
      assert.equal(threadId, "fixture-thread-id");
    });
  }
}

async function testArtifactStartupTimeoutClassification() {
  for (const prompt of [
    "ARTIFACT_MCP_STARTUP_TIMEOUT",
    "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_SYNC_AUTH_WARNING",
    "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT_SYNC_AUTH_WARNING",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_BOTH_AUTH_WARNINGS",
    "LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT_BOTH_AUTH_WARNINGS",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_BOTH_AUTH_WARNINGS",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_WITH_MISSING_API_KEY",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_WITH_POLICY_REFUSAL",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING_WITH_MISSING_API_KEY",
    "ARTIFACT_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_BOTH_AUTH_WARNINGS_WITH_POLICY_REFUSAL",
    "OTHER_MCP_STARTUP_TIMEOUT",
    "OTHER_MCP_STARTUP_TIMEOUT_REQUEST_TIMED_OUT_SYNC_AUTH_WARNING",
    "CATALOG_AUTH_ONLY",
    "SYNC_AUTH_ONLY",
  ]) {
    await assert.rejects(
      runFixtureWorker(prompt),
      (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
        error?.name === "Error",
      `${prompt} should remain retryable`,
    );
  }
}

async function testMissingParentSandboxFailsBeforeWorkerLaunch() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    await assert.rejects(
      new CodexSdkWorkerExecutor().run(
        workerRequest(
          path.join(fixture.root, "missing-prompt.md"),
          path.join(fixture.root, "artifacts"),
        ),
      ),
      (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
        error?.name === "DeepScanNonRetryableError" &&
        /verified parent sandbox metadata/i.test(error.message),
    );
    await assert.rejects(
      readFile(fixture.markerPath, "utf8"),
      (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
        error?.code === "ENOENT",
    );
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

async function testDisallowedWorkerProfileFailsBeforeWorkerLaunch() {
  return withWorkerFixture(
    async (fixture, promptPath, workingDirectory) => {
      await writeFile(promptPath, "fixture blocked worker prompt\n");

      await assert.rejects(
        runWorker(promptPath, workingDirectory),
        (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
          error?.name === "DeepScanNonRetryableError" &&
          error.message.includes("codex_security_deep_scan_worker") &&
          error.message.includes("[allowed_permission_profiles]") &&
          error.message.includes("codex_security_deep_scan_worker = true") &&
          error.message.includes("Deep Scan did not run."),
      );
      await assert.rejects(
        readFile(fixture.markerPath, "utf8"),
        (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
          error?.code === "ENOENT",
      );
    },
    emptyWorkerPermissionProfile,
    false,
  );
}

async function testRuntimePermissionProfileFallbackStopsAndDiscards() {
  for (const marker of [
    "PERMISSION_PROFILE_FALLBACK_ITEM",
    "PERMISSION_PROFILE_FALLBACK_EVENT",
  ]) {
    await withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
      await writeFile(promptPath, `${marker}\n`);

      await assert.rejects(
        runWorker(promptPath, workingDirectory),
        (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
          error?.name === "DeepScanNonRetryableError" &&
          error.message.includes("worker was stopped") &&
          error.message.includes("results were discarded") &&
          !error.message.includes("did not run"),
      );
      const invocation = await readJson(fixture.markerPath);
      assert.equal(invocation.stdin, `${marker}\n`);
    });
  }
}

function runWorker(
  promptPath: string,
  workingDirectory: string,
  options: Partial<CodexWorkerRequest> = {},
) {
  return new CodexSdkWorkerExecutor({
    parentSandbox: trustedParentSandbox,
  }).run(workerRequest(promptPath, workingDirectory, options));
}

function workerRequest(
  promptPath: string,
  workingDirectory: string,
  options: Partial<CodexWorkerRequest> = {},
): CodexWorkerRequest {
  return {
    kind: "discovery",
    promptPath,
    workingDirectory,
    subagents: 0,
    signal: new AbortController().signal,
    ...options,
  };
}

async function runFixtureWorker(
  prompt: string,
  kind: DeepScanWorkerKind = "discovery",
  subagents = 0,
) {
  return withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
    await writeFile(promptPath, `${prompt}\n`);
    return await runWorker(promptPath, workingDirectory, { kind, subagents });
  });
}

async function fakeCodexFixture(
  preflightProfile = emptyWorkerPermissionProfile,
  preflightAllowed = true,
  accountResult: {
    account: { type: string } | null;
    requiresOpenaiAuth: boolean;
  } = { account: { type: "apiKey" }, requiresOpenaiAuth: true },
) {
  const root = await temporaryDirectories.create(
    "codex-security-sdk-executor-",
  );
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(
    scriptPath,
    `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const preflightProfile = ${JSON.stringify(preflightProfile)};
const preflightAllowed = ${JSON.stringify(preflightAllowed)};
const accountResult = ${JSON.stringify(accountResult)};
const preflightMarkerPath = process.env.FAKE_CODEX_PREFLIGHT_MARKER ?? ${JSON.stringify(preflightMarkerPath)};
if (process.argv.includes('app-server')) {
  const preflight = { cwd: process.cwd(), codexHome: process.env.CODEX_HOME, runnerTrackingId: process.env.RUNNER_TRACKING_ID, libraryPath: process.env.LD_LIBRARY_PATH, gitEnvironment: Object.fromEntries(['PATH', 'CODEX_SECURITY_GIT', 'GIT_SSH_COMMAND', 'GIT_CONFIG_GLOBAL'].map(name => [name, process.env[name]])), requests: [] };
  writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
  let buffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buffer += chunk;
    while (true) {
      const newline = buffer.indexOf('\\n');
      if (newline < 0) return;
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      if (message.method === 'initialized') continue;
      if (message.method === 'config/read' || message.method === 'permissionProfile/list') {
        preflight.requests.push({ method: message.method, cwd: message.params?.cwd });
        writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
      }
      let result;
      if (message.method === 'initialize') {
        result = { userAgent: 'fixture', codexHome: '/fixture', platformFamily: 'unix', platformOs: 'macos' };
      } else if (message.method === 'config/read') {
        result = { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: preflightProfile } }, origins: {}, layers: null };
      } else if (message.method === 'permissionProfile/list') {
        result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: preflightAllowed }], nextCursor: null };
      } else if (message.method === 'account/read') {
        result = accountResult;
      } else if (message.method === 'configRequirements/read') {
        result = { requirements: { allowedPermissionProfiles: { existing_profile: true } } };
      } else {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }) + '\\n');
        continue;
      }
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');
    }
  });
  process.stdin.on('end', () => process.exit(0));
} else {
const stdin = (await process.stdin.toArray()).join('');
const openaiAuthentication = stdin.includes('CAPTURE_SYNTHETIC_OPENAI_AUTH') ? { OPENAI_API_KEY: process.env.OPENAI_API_KEY, CODEX_API_KEY: process.env.CODEX_API_KEY } : undefined;
const bedrockAuthentication = stdin.includes('CAPTURE_SYNTHETIC_BEDROCK_AUTH') ? Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_BEDROCK_ENV_KEYS).map((name) => [name, process.env[name]])) : undefined;
const runtimeEnvironment = Object.fromEntries(['PATH', 'HOME', 'PYTHON', 'PYTHONUTF8', 'LD_LIBRARY_PATH', 'CODEX_SECURITY_STATE_DIR', 'RUNNER_TRACKING_ID'].map(name => [name, process.env[name]]));
const pythonProbe = stdin.includes('CAPTURE_SYNTHETIC_PYTHON') ? spawnSync(process.env.PYTHON, ['-I', '-c', 'import json,os,sys; print(json.dumps([sys.prefix,os.environ.get("LD_LIBRARY_PATH")]))'], { encoding: 'utf8' }) : undefined;
if (pythonProbe && pythonProbe.status !== 0) throw new Error(pythonProbe.stderr || String(pythonProbe.error));
const pythonRuntime = pythonProbe ? JSON.parse(pythonProbe.stdout) : undefined;
writeFileSync(process.env.FAKE_CODEX_MARKER, JSON.stringify({ argv: process.argv.slice(2), stdin, cwd: process.cwd(), codexHome: process.env.CODEX_HOME, gitEnvironment: Object.fromEntries(['PATH', 'CODEX_SECURITY_GIT', 'GIT_SSH_COMMAND', 'GIT_CONFIG_GLOBAL'].map(name => [name, process.env[name]])), configPath: process.env.CODEX_SECURITY_CONFIG_PATH, deepConfigPath: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH, python: process.env.PYTHON, pythonPrefix: pythonRuntime?.[0], pythonLibraryPath: pythonRuntime?.[1], runtimeEnvironment, providerKey: process.env.SYNTHETIC_GATEWAY_KEY, originator: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE, ...(stdin.includes('COMPLETE_THEN_HANG') ? { pid: process.pid } : {}), ...(openaiAuthentication ? { openaiAuthentication } : {}), ...(bedrockAuthentication ? { bedrockAuthentication } : {}) }));
if (stdin.includes('COMPLETE_THEN_HANG')) process.on('SIGTERM', () => setTimeout(() => process.exit(0), 100));
if (stdin.includes('THREAD_START_CONFIG_ERROR')) { console.error('Error: thread/start: thread/start failed: agents.max_threads cannot be set when features.multi_agent_v2 is enabled (code -32600)'); process.exit(1); }
if (stdin.includes('CONFIG_ERROR')) { console.error('failed to load configuration: invalid value'); process.exit(2); }
if (stdin.includes('MCP_STARTUP_TIMEOUT') || stdin.includes('CATALOG_AUTH_ONLY') || stdin.includes('SYNC_AUTH_ONLY')) {
  const syncWarning = stdin.includes('SYNC_AUTH_WARNING') || stdin.includes('SYNC_AUTH_ONLY');
  const bothWarnings = stdin.includes('BOTH_AUTH_WARNINGS');
  if (!syncWarning || bothWarnings) console.error('chatgpt authentication required for remote plugin catalog; api key auth is not supported');
  if (syncWarning || bothWarnings) console.error('chatgpt authentication required to sync remote plugins; api key auth is not supported');
  if (!stdin.includes('CATALOG_AUTH_ONLY') && !stdin.includes('SYNC_AUTH_ONLY')) {
    const serverName = stdin.includes('OTHER_MCP_STARTUP_TIMEOUT') ? 'other_server' : stdin.includes('LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT') ? 'codex_security_artifacts' : 'cs_artifacts';
    const timeout = stdin.includes('REQUEST_TIMED_OUT') ? 'request timed out' : 'timed out handshaking with MCP server after 30s';
    console.error('required MCP servers failed to initialize: ' + serverName + ': ' + timeout);
  }
  if (stdin.includes('WITH_MISSING_API_KEY')) console.error('missing API key');
  if (stdin.includes('WITH_POLICY_REFUSAL')) console.error('Request blocked by cyberPolicy.');
  process.exit(1);
}
const resumeIndex = process.argv.indexOf('resume');
const threadId = resumeIndex === -1 ? 'fixture-thread-id' : process.argv[resumeIndex + 1];
console.log(JSON.stringify({ type: 'thread.started', thread_id: threadId }));
if (stdin.includes('IPC_DIAGNOSTIC_EVENT')) console.log(stdin.split('\\n')[1]);
if (stdin.includes('MALFORMED_COMMAND_EVENT')) {
  const output = JSON.parse(stdin.split('\\n')[1]);
  const event = { type: 'item.completed', item: { id: 'fixture-command', type: 'command_execution', command: 'cat example.ts', aggregated_output: output, exit_code: 0, status: 'completed' } };
  console.log(JSON.stringify(event).slice(0, -1));
  process.exit(0);
}
const permissionProfileFallbackWarning = 'Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`codex_security_deep_scan_worker\` to required value \`:read-only\`.';
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_ITEM')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'warning-1', type: 'error', message: permissionProfileFallbackWarning } }));
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_EVENT')) console.log(JSON.stringify({ type: 'error', message: permissionProfileFallbackWarning }));
if (stdin.includes('BLOCK_AFTER_START')) await new Promise(() => {});
if (stdin.includes('RATE_LIMIT_CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: '429 Too Many Requests: Request blocked by cyberPolicy.' } })); process.exit(0); }
if (stdin.includes('CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by cyberPolicy.' } })); process.exit(0); }
if (stdin.includes('SAFETY_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by a safety policy violation.' } })); process.exit(0); }
if (stdin.includes('UPSTREAM_CYBERSECURITY_RISK_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This request has been flagged for possible cybersecurity risk.' } })); process.exit(0); }
if (stdin.includes('UPSTREAM_HIGH_RISK_CYBER_ACTIVITY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This request has been flagged for potentially high-risk cyber activity.' } })); process.exit(0); }
if (stdin.includes('CYBERSECURITY_RISK_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for possible cybersecurity risk.' } })); process.exit(0); }
if (stdin.includes('HIGH_RISK_CYBER_ACTIVITY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for potentially high-risk cyber activity.' } })); process.exit(0); }
if (stdin.includes('RETRYABLE_STREAM_ERROR')) console.log(JSON.stringify({ type: 'error', message: 'Reconnecting... 2/5 (stream disconnected before completion: websocket closed by server before response.completed)' }));
if (stdin.includes('INCOMPLETE_STREAM')) { console.log(JSON.stringify({ type: 'error', message: 'fixture stream interrupted' })); process.exit(0); }
if (stdin.includes('BWRAP_NAMESPACE_FAILURE')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'command-1', type: 'command_execution', command: 'super-secret-command', aggregated_output: 'private source text\\nbwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_user_namespaces exceeded (ENOSPC)', exit_code: 1, status: 'failed' } }));
if (stdin.includes('ARTIFACT_TOOL_')) {
  const server = stdin.includes('FOREIGN_ARTIFACT_TOOL_') ? 'untrusted_server' : stdin.includes('LEGACY_OWNED_ARTIFACT_TOOL_') ? 'codex_security_artifacts' : 'cs_artifacts';
  const tool = stdin.includes('ADDITIONAL_OWNED_ARTIFACT_TOOL_') ? 'additional_codex_security_worker_tool' : stdin.includes('DISCOVERY_OWNED_ARTIFACT_TOOL_') ? 'record_codex_security_discovery_candidates' : 'record_codex_security_deep_reduction';
  const item = { id: 'mcp-1', type: 'mcp_tool_call', server, tool, arguments: { secret: 'Bearer synthetic-secret', source: 'private source text' }, result: stdin.includes('REJECTED') ? { content: [{ type: 'text', text: 'private output sk-proj-synthetic-secret' }] } : null, error: stdin.includes('TRANSPORT_FAILED') ? { message: 'transport closed sk-proj-synthetic-secret /private/customer/path' } : null, status: 'failed' };
  console.log(JSON.stringify({ type: 'item.completed', item }));
}
console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture final response' } }));
console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
if (stdin.includes('COMPLETE_THEN_HANG')) { setInterval(() => {}, 1_000); await new Promise(() => {}); }
}
`,
  );
  await chmod(scriptPath, 0o755);
  process.env.FAKE_CODEX_MARKER = markerPath;
  return { root, markerPath, preflightMarkerPath, executablePath: scriptPath };
}

function assertReadOnlyWorkerPolicy(args: readonly string[]) {
  assert.equal(args.includes("--sandbox"), false);
  assert.equal(args.includes("--add-dir"), false);
  assert.deepEqual(
    args.filter((arg: string) => arg.startsWith("approval_policy=")),
    ['approval_policy="never"'],
  );
  assert.equal(
    args.some((arg: string) => arg.includes("network_access")),
    false,
  );
  const override = workerPermissionProfileOverride(args);
  assert.equal(override.includes('extends=":read-only"'), true);
  assert.equal(override.includes('":root"="read"'), true);
  assert.equal(override.includes("network={enabled=false}"), true);
  assert.equal(override.includes('"write"'), false);
}

function workerPermissionProfileOverride(args: readonly string[]) {
  assert.deepEqual(
    args.filter((arg: string) => arg.startsWith("default_permissions=")),
    ['default_permissions="codex_security_deep_scan_worker"'],
  );
  const overrides = args.filter((arg: string) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker="),
  );
  assert.equal(overrides.length, 1);
  return overrides[0];
}

function assertWorkerSubagentPolicy(
  args: readonly string[],
  subagents: number,
) {
  assertConfigOverrides(args, {
    "features.multi_agent_v2.enabled": false,
    "features.multi_agent_v2.max_concurrent_threads_per_session": subagents + 1,
    "features.multi_agent": undefined,
    "features.code_mode.excluded_tool_namespaces": undefined,
    ...(subagents === 0
      ? {
          "agents.max_threads": undefined,
          "features.enable_fanout": false,
          "features.code_mode.enabled": undefined,
        }
      : {
          "agents.max_threads": subagents,
          "features.enable_fanout": undefined,
        }),
  });
  assert.equal(args.includes("features.multi_agent_v2.enabled=true"), false);
}

function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function assertConfigOverrides(
  args: readonly string[],
  values: Record<string, string | number | boolean | undefined>,
) {
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) {
      assert.equal(
        args.some((arg) => arg.startsWith(`${key}=`)),
        false,
      );
    } else {
      assert.equal(args.includes(`${key}=${JSON.stringify(value)}`), true);
    }
  }
}

async function withWorkerFixture<Result>(
  action: (
    fixture: Awaited<ReturnType<typeof fakeCodexFixture>>,
    promptPath: string,
    workingDirectory: string,
  ) => Promise<Result>,
  ...options: Parameters<typeof fakeCodexFixture>
) {
  const fixture = await fakeCodexFixture(...options);
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    return await action(fixture, promptPath, workingDirectory);
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}
