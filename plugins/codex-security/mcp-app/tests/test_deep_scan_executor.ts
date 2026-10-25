import { testArtifactStartupTimeoutClassification } from "./deep_scan_startup_cases.ts";
import {
  workerGitEnvironment,
  workerScanEnvironment,
  expectedGitEnvironment,
  restoreEnv,
} from "./support/fake-codex-source.ts";
import { windowsAcl } from "./support/windows-output-fixture.ts";
import {
  createFakeCodexFixture,
  deniedWorkerPermissionProfile,
  emptyWorkerPermissionProfile,
  trustedParentSandbox,
  trustedParentSandboxWithDenials,
} from "./support/fake-codex-fixture.ts";
import { readJson, writeJson } from "./support/json.ts";
import { randomUUID } from "node:crypto";
import { loadWorkbenchProcess } from "./support/workbench-process.ts";
import { finding, workerDraft } from "./scan-draft-fixture.ts";
import {
  assertConfigOverrides,
  assertFlagPair,
  nativeConfigOverrides,
} from "./assertions.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { mock, test, type TestContext } from "node:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
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
  readdir,
  realpath,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { rootCertificates } from "node:tls";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

import type {
  CodexWorkerDiagnostic,
  CodexWorkerRequest,
  DeepScanWorkerKind,
} from "../src/deep-scan/types.js";
import { testConcurrentWorkerExecutableAliases } from "./deep_scan_executable_alias_cases.ts";
import { testDeepScanContextSnapshots } from "./deep_scan_context_snapshot_cases.ts";
import { workerTelemetryFixture } from "./deep_scan_worker_telemetry_fixture.ts";
import { testWorkerCyberAccessSettings } from "./deep_scan_worker_settings_cases.ts";

const executorSource = new URL("../src/deep-scan/executor.ts", import.meta.url);
const { bundledCodexSdkEnvironment } =
  process.platform === "win32"
    ? {}
    : await importModule({
        entryPoints: [
          fileURLToPath(
            new URL(
              "../../../../sdk/typescript/src/codex-sdk-environment.ts",
              import.meta.url,
            ),
          ),
        ],
      });

const {
  CodexSdkWorkerExecutor,
  resolveCodexPath,
  snapshotWorkerEnvironment,
  appendItemDiagnostic,
  classifyCodexWorkerError,
  codexWorkerTurnError,
  DeepScanNonRetryableError,
  isCodexCybersecurityPolicyRefusal,
  parseDeepScan,
} = await importModule({
  define: {
    "import.meta.url": JSON.stringify(executorSource.href),
  },
  stdin: {
    // Expose the environment snapshot only for tests.
    contents: `${await readFile(executorSource, "utf8")}
export { snapshotWorkerEnvironment, appendItemDiagnostic };
export * from "./errors.js";
export { parseDeepScan } from "./response.js";`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource),
  },
});

const temporaryDirectories = createTemporaryDirectories(true);
const fakeCodexFixture = createFakeCodexFixture.bind(
  null,
  temporaryDirectories,
);
const previousMarker = process.env.FAKE_CODEX_MARKER;
const ipcFrameError =
  "code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length 76008279 exceeds 67108864 bytes";

try {
  await test("Deep worker lifecycle", async (t) => {
    await check(t, testWorkerCancellation);
    await check(t, testWorkerTerminalEvents);
    await check(t, testCompletedWorkerSettlesWithoutWaitingForProcessExit);
    if (process.platform !== "win32") {
      await check(t, testStreamTerminationWithoutTerminalEventFails);
      await check(t, testAbortPropagation);
    }
  });

  await test("Deep worker runtime settings", async (t) => {
    await check(t, testLargeScopeTransport);
    await check(t, testOpenAiCredentialsReachWorker);
    await check(t, testWorkerRuntimeSettings);
    await check(t, testUnsupportedProviderSnapshotFailsBeforeLaunch);
    await check(
      t,
      () =>
        testWorkerCyberAccessSettings({
          CodexSdkWorkerExecutor,
          fakeCodexFixture,
          parentSandbox: trustedParentSandbox,
          workerRequest,
          assertConfigOverrides,
          assertReadOnlyWorkerPolicy,
          assertWorkerSubagentPolicy,
          restoreEnv,
        }),
      "cyber access settings",
    );
    if (process.platform !== "win32") {
      await check(
        t,
        () =>
          testDeepScanContextSnapshots({
            CodexSdkWorkerExecutor,
            fakeCodexFixture,
            parentSandbox: trustedParentSandbox,
          }),
        "isolated context snapshots",
      );
      await check(t, testMissingParentSandboxFailsBeforeWorkerLaunch);
      await check(t, testDisallowedWorkerProfileFailsBeforeWorkerLaunch);
      await check(t, testRuntimePermissionProfileFallbackStopsAndDiscards);
      await check(t, testSdkInvocationAndThreadCapture);
      await check(
        t,
        () => testBedrockCredentialsReachWorker(),
        "Bedrock credentials",
      );
      await check(
        t,
        () => testBedrockCredentialsReachWorker("oidc"),
        "Bedrock OIDC credentials",
      );
      await check(t, testExternalProviderCredentialsReachWorker);
      await check(t, testArtifactServerUsesExtendedStartupTimeout);
      await check(t, testReducerAttemptContext);
      await check(t, testZeroSubagentsPreservesHostRestrictions);
      await check(t, testSdkResumesExistingThread);
    }
  });

  await test("Deep worker executable selection", async (t) => {
    await check(t, testConfiguredExecutablePaths);
    if (process.platform !== "win32") {
      await check(t, testWorkerLaunchesWithoutGlobalCodex);
      await check(t, testPreflightBindsExecutableAndHomeBeforeChangingCwd);
      await check(
        t,
        () =>
          testConcurrentWorkerExecutableAliases({
            CodexSdkWorkerExecutor,
            fakeCodexFixture,
            parentSandbox: trustedParentSandbox,
            bundledCodexSdkEnvironment,
            assertReadOnlyWorkerPolicy,
          }),
        "concurrent executable aliases",
      );
    }
    await check(t, testWindowsAppsCodexFallsBackToRelocatedBinary);
    await check(
      t,
      () => testWindowsNpmPackageResolution(),
      "global Windows npm package resolution",
    );
    await check(
      t,
      () => testWindowsNpmPackageResolution("managed"),
      "managed Windows npm package resolution",
    );
    if (process.platform === "win32") {
      await check(t, testWindowsLongExecutableLaunches);
      await check(t, testWindowsRootRelativePathsStayBoundToOriginalDrive);
      await check(t, testWindowsWorkerEnvironmentPreservesMixedCaseKeys);
      await check(t, testWindowsLauncherSkipsExtensionlessNpmShim);
    }
  });

  await test("Deep worker diagnostics", async (t) => {
    await check(t, testCodeModeFrameDiagnosticBoundaries);
    await check(t, testUsageLimitClassification);
    await check(t, testOsErrorCodesRemainRetryable);
    await check(t, testTextualMissingPathErrorsRemainRetryable);
    await check(t, testWorkerErrorClassificationPreservesExplicitFailures);
    if (process.platform !== "win32") {
      await check(t, testRetryNotificationDoesNotInterruptTurn);
      await check(t, testSandboxNamespaceDiagnosticIsPreserved);
      await check(t, testOwnedArtifactToolFailureDiagnosticIsPreserved);
      await check(
        t,
        () => testArtifactDiagnosticSurvivesWorkerRetries("discovery:\0" + "0"),
        "artifact retry diagnostic: controls",
      );
      await check(
        t,
        () => testArtifactDiagnosticSurvivesWorkerRetries("😀".repeat(1300)),
        "artifact retry diagnostic: Unicode",
      );
      await check(t, testCodeModeFrameDiagnosticSurvivesSuccessfulTurn);
      await check(t, testUnstructuredConfigurationFailureRemainsRetryable);
      await check(t, testUnstructuredThreadStartFailureRemainsRetryable);
      await check(t, testPolicyFailuresRemainWorkerErrors);
      await check(t, testMalformedCommandEventsRemainRetryable);
      await check(t, testRateLimitPolicyFailureRemainsRetryable);
      await check(
        t,
        () => testArtifactStartupTimeoutClassification(runFixtureWorker),
        testArtifactStartupTimeoutClassification.name,
      );
    }
  });
} finally {
  restoreEnv("FAKE_CODEX_MARKER", previousMarker);
  await temporaryDirectories.cleanup();
}

async function check(
  t: TestContext,
  run: () => void | Promise<void>,
  name = run.name,
) {
  process.stdout.write(`Running ${t.name} / ${name}\n`);
  await t.test(name, run);
}

function testConfiguredExecutablePaths() {
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

// Only Windows launches the resolved path; the other hosts exercise lookup.
async function writeWindowsLaunchFixture(file: string) {
  if (process.platform === "win32") await copyFile(process.execPath, file);
  else await writeFile(file, "x", { mode: 0o755 });
}

async function testWindowsAppsCodexFallsBackToRelocatedBinary() {
  const root = await temporaryDirectories.create(
    "codex-security-windows-cache-",
  );
  const localAppData = path.join(root, "LocalAppData");
  const cachedBinary = (id: string) =>
    path.join(localAppData, "OpenAI", "Codex", "bin", id, "codex.exe");
  const olderBinary = cachedBinary("11111111");
  const currentBinary = cachedBinary("22222222");
  const emptyBinary = cachedBinary("33333333");
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
  await writeFile(olderBinary, "x", { mode: 0o755 });
  await writeWindowsLaunchFixture(currentBinary);
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
  await writeWindowsLaunchFixture(nativeBinary);

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
  const bundledTools = path.join(fixture.root, "codex-path");
  await mkdir(bundledTools);
  await writeFile(
    path.join(bundledTools, "rg"),
    "#!/bin/sh\nprintf 'synthetic bundled search\\n'\n",
    { mode: 0o755 },
  );
  await mkdir(homeTargetChild, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  assert.notEqual(workingDirectory, originalCwd);
  await writeFile(promptPath, "fixture bound worker executable and home\n");
  await writeFile(
    path.join(nonExecutableDirectory, "codex"),
    "not executable\n",
  );
  // A shell wrapper lets the OS select this file before Node loads the fixture.
  const shellArguments = [process.execPath, fixture.executablePath]
    .map((value) => `'${value.replaceAll("'", `'"'"'`)}'`)
    .join(" ");
  await writeFile(codexPath, `#!/bin/sh\nexec ${shellArguments} "$@"\n`, {
    mode: 0o755,
  });
  await mkdir(path.join(binaryDirectory, "child"));
  const executableLink = path.join(fixture.root, "executable-link");
  await symlink(path.join(binaryDirectory, "child"), executableLink, "dir");
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
    const defaultSearchPath = process.env.PATH;
    for (const [configured, expectedExecutable, searchPath] of [
      [
        path.relative(originalCwd, fixture.executablePath),
        fixture.executablePath,
      ],
      [undefined, codexPath],
      [`${binaryDirectory}/./codex`, codexPath],
      ["codex", codexPath],
      [`${executableLink}/../codex`, codexPath],
      [`${path.relative(originalCwd, executableLink)}/../codex`, codexPath],
      ...[
        `${executableLink}/..`,
        `${path.relative(originalCwd, executableLink)}/..`,
      ].flatMap(
        (entry) =>
          [
            [
              undefined,
              codexPath,
              `${entry}${path.delimiter}${path.dirname(process.execPath)}`,
            ],
            [
              "codex",
              codexPath,
              `${entry}${path.delimiter}${path.dirname(process.execPath)}`,
            ],
          ] as const,
      ),
    ] as const) {
      process.env.PATH = searchPath ?? defaultSearchPath;
      if (configured === undefined) delete process.env.CODEX_CLI_PATH;
      else process.env.CODEX_CLI_PATH = configured;
      const hasBundledTools = expectedExecutable === codexPath;
      if (hasBundledTools) {
        process.env.PATH = bundledCodexSdkEnvironment(resolveCodexPath(), {
          PATH: process.env.PATH,
        }).PATH;
      }
      await writeFile(
        promptPath,
        hasBundledTools
          ? "CAPTURE_SYNTHETIC_RG"
          : "fixture bound worker executable and home",
      );
      assert.equal(
        await realpath(resolveCodexPath()),
        await realpath(expectedExecutable),
      );
      for (const kind of ["discovery", "dedup"] as const)
        for (const resumeThreadId of [undefined, "resumed-thread"]) {
          const result = await runWorker(promptPath, workingDirectory, {
            kind,
            resumeThreadId,
          });

          assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
          const preflight = await readJson(fixture.preflightMarkerPath);
          const invocation = await readJson(fixture.markerPath);
          assert.equal(preflight.cwd, await realpath(workingDirectory));
          assert.equal(invocation.cwd, originalCwd);
          assert.equal(preflight.codexHome, expectedHome);
          assert.equal(invocation.codexHome, expectedHome);
          if (hasBundledTools) {
            assert.equal(
              invocation.runtimeEnvironment.PATH.split(path.delimiter)[0],
              bundledTools,
            );
            assert.equal(invocation.bundledTool, "synthetic bundled search");
            assert.equal(
              preflight.gitEnvironment.PATH,
              invocation.runtimeEnvironment.PATH,
            );
          }
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
          assertReadOnlyWorkerPolicy(invocation.argv);
        }
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
    assert.deepEqual(
      JSON.parse(
        JSON.stringify(
          parseToml(workerPermissionProfileOverride(invocation.argv))
            .permissions,
        ),
      ),
      { codex_security_deep_scan_worker: deniedWorkerPermissionProfile },
    );
    const preflight = await readJson(fixture.preflightMarkerPath);
    assert.deepEqual(
      nativeConfigOverrides(preflight.argv),
      nativeConfigOverrides(invocation.argv),
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
  const sdkRequire = createRequire(import.meta.resolve("@openai/codex-sdk"));
  const nativeLauncher = path.join(
    path.dirname(sdkRequire.resolve("@openai/codex/package.json")),
    "bin",
    "codex.js",
  );
  const cases: {
    openai?: string;
    codex?: string;
    expected?: string;
    accountResult?: {
      account: { type: string } | null;
      requiresOpenaiAuth: boolean;
    };
    nativeProvider?: string;
    configuration?: string;
  }[] = [
    { openai: "synthetic-openai-key", expected: "synthetic-openai-key" },
    {
      openai: "synthetic-openai-key",
      expected: "synthetic-openai-key",
      // Optional null auth is omitted from the SDK's private TOML snapshot.
      configuration: 'model_provider = "openai"\n[model_providers.openai]\n',
    },
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
      accountResult: { account: { type: "chatgpt" }, requiresOpenaiAuth: true },
    },
    {
      openai: "synthetic-provider-key",
      accountResult: { account: null, requiresOpenaiAuth: false },
    },
    {
      openai: "synthetic-openai-key",
      nativeProvider: "synthetic.gateway",
    },
    {
      openai: "synthetic-openai-key",
      nativeProvider: "openai",
      expected: "synthetic-openai-key",
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
      DYLD_LIBRARY_PATH: path.join(fixture.root, "dylibs"),
      DYLD_FALLBACK_LIBRARY_PATH: path.join(fixture.root, "fallback-libraries"),
      CODEX_SECURITY_STATE_DIR: path.join(fixture.root, "state"),
      RUNNER_TRACKING_ID: "synthetic-worker-job",
    };
    const previousEnvironment = [
      "OPENAI_API_KEY",
      "CODEX_API_KEY",
      "OPENAI_FEDERATION_RULE_ID",
      "OPENAI_IDENTITY_TOKEN_FILE",
      "CODEX_CLI_PATH",
      "CODEX_HOME",
      "CODEX_SECURITY_CONFIG_PATH",
      ...Object.keys(runtimeEnvironment),
    ].map((name) => [name, process.env[name]] as const);
    const originalSpawn = childProcess.spawn;
    try {
      restoreEnv("OPENAI_API_KEY", entry.openai);
      restoreEnv("CODEX_API_KEY", entry.codex);
      restoreEnv("OPENAI_FEDERATION_RULE_ID", undefined);
      restoreEnv("OPENAI_IDENTITY_TOKEN_FILE", undefined);
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = fixture.root;
      const configPath = path.join(fixture.root, "scan-settings.toml");
      await writeFile(configPath, entry.configuration ?? "");
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
      Object.assign(process.env, runtimeEnvironment);
      if (entry.nativeProvider !== undefined) {
        await writeFile(
          path.join(fixture.root, "config.toml"),
          `model_provider = ${JSON.stringify(entry.nativeProvider)}
cli_auth_credentials_store = "file"
[features]
plugins = false
api_key_model_discovery = false
[model_providers."synthetic.gateway"]
name = "Synthetic gateway"
wire_api = "responses"
base_url = "https://provider.example.test/v1"
requires_openai_auth = false
env_key = "CODEX_API_KEY"
`,
        );
      }
      let nativePreflight:
        | {
            codexHome: string | undefined;
            argv: readonly string[];
            runnerTrackingId: string | undefined;
            libraryPath: string | undefined;
          }
        | undefined;
      childProcess.spawn = ((
        command: string,
        args: readonly string[],
        options: SpawnOptions,
      ) => {
        const nodeExecutable =
          command === process.execPath ||
          command === path.toNamespacedPath(process.execPath);
        // Keep real account/config selection, while the existing fake exec
        // observes credentials without starting a model turn.
        if (
          nodeExecutable &&
          entry.nativeProvider !== undefined &&
          args.includes("app-server")
        ) {
          nativePreflight = {
            codexHome: options.env?.CODEX_HOME,
            runnerTrackingId: options.env?.RUNNER_TRACKING_ID,
            libraryPath: options.env?.LD_LIBRARY_PATH,
            argv: args,
          };
          return originalSpawn(command, [nativeLauncher, ...args], options);
        }
        return originalSpawn(
          command,
          nodeExecutable ? [fixture.executablePath, ...args] : args,
          options,
        );
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const promptPath = path.join(fixture.root, "prompt.md");
      await writeFile(
        promptPath,
        `CAPTURE_SYNTHETIC_OPENAI_AUTH\n${virtualenv === undefined ? "" : "CAPTURE_SYNTHETIC_PYTHON\n"}`,
      );
      const executor = new CodexSdkWorkerExecutor({
        model: "gpt-daybreak-blue-latest",
        parentSandbox: trustedParentSandbox,
      });
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resume"]) {
          await executor.run(
            workerRequest(promptPath, fixture.root, { kind, resumeThreadId }),
          );
          const preflight =
            entry.nativeProvider === undefined
              ? await readJson(fixture.preflightMarkerPath)
              : nativePreflight!;
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
          assertFlagPair(
            invocation.argv,
            "--model",
            "gpt-daybreak-blue-latest",
          );
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
          assert.equal(
            preflight.argv.some((arg: string) => arg.includes("synthetic-")),
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

async function testUnsupportedProviderSnapshotFailsBeforeLaunch() {
  const fixture = await fakeCodexFixture();
  const configPath = path.join(fixture.root, "config.toml");
  const deepPath = path.join(fixture.root, "deep.toml");
  const promptPath = path.join(fixture.root, "prompt.md");
  await writeFile(configPath, "");
  await writeFile(promptPath, "synthetic provider upgrade fixture");
  await writeFile(
    deepPath,
    stringifyToml({
      worker_runtime: {
        model_provider: "synthetic.gateway",
        model_providers: {
          "synthetic.gateway": {
            name: "Synthetic gateway",
            env_key: "SYNTHETIC_GATEWAY_KEY",
          },
        },
      },
    }),
  );
  const saved = [
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ].map((name) => [name, process.env[name]] as const);
  try {
    process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
    process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = deepPath;
    await assert.rejects(
      runWorker(promptPath, fixture.root),
      (error: Error) =>
        error.name === "DeepScanNonRetryableError" &&
        error.message.includes("Update the SDK and bundled plugin together"),
    );
    await assert.rejects(
      readFile(fixture.preflightMarkerPath),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
    for (const nativeProfile of ["../outside", "C:\\outside", "", "scan\n"]) {
      await writeFile(
        deepPath,
        stringifyToml({ worker_runtime: { native_profile: nativeProfile } }),
      );
      await assert.rejects(
        runWorker(promptPath, fixture.root),
        (error: Error) =>
          error.name === "DeepScanNonRetryableError" &&
          error.message.includes("invalid --profile value"),
      );
    }
    await assert.rejects(
      readFile(fixture.preflightMarkerPath),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
  } finally {
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}

async function testWorkerRuntimeSettings() {
  const cases: [string, string | undefined][] = [
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
    "CODEX_SECURITY_PYTHON_COMMAND",
    "PATH",
    "HOME",
    "NODE_OPTIONS",
    "NODE_DEBUG",
    "NODE_EXTRA_CA_CERTS",
    "CODEX_MCP_NODE_PATH",
    "CODEX_SECURITY_GIT",
    "GIT_SSH_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "CODEX_CLI_PATH",
    "CODEX_MCP_NODE_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_STATE_DIR",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_PLUGIN_ROOT",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "SYNTHETIC_GATEWAY_KEY",
    "SYNTHETIC_HEADER_VALUE",
    "CODEX_SQLITE_HOME",
    "XDG_CACHE_HOME",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "TEMP",
    "TMP",
  ].map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  try {
    process.env.CODEX_SECURITY_PYTHON_COMMAND = "stale-ambient-python";
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_API_KEY;
    delete process.env.SYNTHETIC_GATEWAY_KEY;
    delete process.env.SYNTHETIC_HEADER_VALUE;
    delete process.env.CODEX_SQLITE_HOME;
    for (const [configuration, expected] of cases) {
      for (const [name, value] of saved) {
        if (name === "TEMP" || name === "TMP") restoreEnv(name, value);
      }
      const fixture = await fakeCodexFixture(
        deniedWorkerPermissionProfile,
        true,
        { account: null, requiresOpenaiAuth: false },
        process.platform === "win32" && configuration === "",
      );
      const python = path.join(fixture.root, "selected venv", "bin", "python");
      const helperPython = path.join(
        fixture.root,
        "helper venv",
        "bin",
        "python",
      );
      process.env.PYTHON = python;
      const gitEnvironment = workerGitEnvironment(fixture.root);
      await writeFile(gitEnvironment.NODE_EXTRA_CA_CERTS, rootCertificates[0]!);
      Object.assign(process.env, gitEnvironment);
      const configPath = path.join(fixture.root, "active [scan] config.toml");
      const codexHome = path.join(
        fixture.root,
        process.platform === "win32" ? "scan [home]" : "scan [home] ",
      );
      const promptPath = path.join(fixture.root, "prompt.md");
      await mkdir(codexHome);
      await writeFile(
        path.join(codexHome, "config.toml"),
        `openai_base_url = "https://ambient.example.test/v1"
model = "fixture-inherited-model"
model_reasoning_effort = "medium"
model_provider = "synthetic"
[model_providers.synthetic]
name = "Synthetic gateway"
base_url = "https://gateway.example.test/v1"
wire_api = "responses"
env_key = "SYNTHETIC_GATEWAY_KEY"`,
      );
      const settings = [
        { model: "gpt-5.6-sol", reasoningEffort: "xhigh" },
        { model: "gpt-6-astra", reasoningEffort: "ultra" },
        { model: "gpt-6.1-sol", reasoningEffort: "max" },
        { model: "gpt-6-sol", reasoningEffort: "high" },
        {
          model: 'fixture-"future"\\模型',
          reasoningEffort: 'future-"effort"\\強度\u007f',
        },
        // Omitted settings preserve the model and effort in the Codex home.
        {},
      ];
      const providerKeys = settings.map((_, index) =>
        index === 0 ? undefined : ` synthetic-gateway-key-${index} `,
      );
      const providerHeaders = settings.map((_, index) =>
        index === 0 ? undefined : ` synthetic-header-${index}\t`,
      );
      const temporaryEnvironments = settings.map((_, index) => ({
        TEMP: path.join(fixture.root, `temp-${index}`),
        TMP: path.join(fixture.root, `tmp-${index}`),
      }));
      await Promise.all(
        temporaryEnvironments.flatMap((environment) =>
          Object.values(environment).map((directory) => mkdir(directory)),
        ),
      );
      const workerConfigurations = Array.from(
        { length: settings.length },
        (_, index) => {
          const parsedConfiguration = parseToml(configuration);
          const profiles = (parsedConfiguration.profiles ?? {}) as Record<
            string,
            Record<string, unknown>
          >;
          const noWorkerSnapshot = index === 0 && configuration !== "";
          const endpoint =
            index === 1 || noWorkerSnapshot
              ? undefined
              : `https://synthetic-user:synthetic-password@worker-${index}.example.test/v1?token=synthetic-${index}-token`;
          const serviceTier =
            index === 0 ? undefined : index === 3 ? "flex" : "fast";
          const instructionsFile =
            index === 0
              ? undefined
              : path.join(fixture.root, `instructions ${index}.md`);
          const verbosity = [undefined, "low", "medium", "high"][index];
          const windowsSandbox =
            index === 0
              ? undefined
              : index % 2 === 0
                ? "unelevated"
                : "elevated";
          const webSearch =
            index === 0 ? undefined : ["disabled", "cached", "live"][index % 3];
          const skills =
            index === 0 && configuration === ""
              ? undefined
              : {
                  config: [
                    {
                      path: path.join(
                        codexHome,
                        "plugins",
                        `scan-${index}`,
                        "skills",
                        "security-scan",
                        "SKILL.md",
                      ),
                      enabled: false,
                    },
                    {
                      path: path.join(
                        fixture.root,
                        "other skills",
                        `scan-${index}`,
                        "SKILL.md",
                      ),
                      enabled: true,
                    },
                  ],
                };
          const {
            mergeProfileTelemetry,
            telemetry,
            inheritedTelemetry,
            workerTelemetry,
          } = workerTelemetryFixture(index, configuration !== "");
          const features =
            index === 0
              ? undefined
              : {
                  goals: index % 2 === 0,
                  shell_tool: index % 2 === 0,
                  unified_exec: false,
                  view_image: index % 2 !== 0,
                  multi_agent_v2: {
                    enabled: true,
                    max_concurrent_threads_per_session: index + 2,
                  },
                  enable_fanout: true,
                };
          const entryPath = `${configPath}.${index}`;
          const deepPath = `${entryPath}.deep`;
          const nativeProfile =
            index === 0 ? undefined : `synthetic-scan-${index}`;
          const profilePath =
            nativeProfile === undefined
              ? undefined
              : path.join(codexHome, `${nativeProfile}.config.toml`);
          const literalDeniedPath = `/repo/literal.key"\\雪\u007f-${index}`;
          const parentSandbox = {
            filesystemDenies: [
              ...trustedParentSandboxWithDenials.filesystemDenies,
            ],
            literalFilesystemDenies: [
              ...trustedParentSandboxWithDenials.literalFilesystemDenies,
              deepPath,
              codexHome,
              literalDeniedPath,
            ],
            globScanMaxDepth: trustedParentSandboxWithDenials.globScanMaxDepth,
          };
          const provider = index === 0 ? undefined : "synthetic.gateway";
          const providerConfig =
            index === 0
              ? undefined
              : {
                  name: `Synthetic gateway ${index}`,
                  base_url: `https://gateway-${index}.example.test/v1`,
                  wire_api: "responses",
                  env_key: "SYNTHETIC_GATEWAY_KEY",
                  env_http_headers: { "X-Synthetic": "SYNTHETIC_HEADER_VALUE" },
                  aws: {
                    region: index % 2 === 0 ? "us-east-2" : "us-west-2",
                    profile: `synthetic-scan-${index}`,
                  },
                  ...(index === 3 ? {} : { requires_openai_auth: index === 2 }),
                  experimental_bearer_token: `synthetic-bearer-${index}`,
                  auth: {
                    type: "command",
                    command: "synthetic-auth",
                    cwd: path.join(
                      fixture.root,
                      `selected helper home ${index}`,
                    ),
                    args: [String(index)],
                    env: { CLIENT_SECRET: `synthetic-client-secret-${index}` },
                  },
                };
          const nativePaths = {
            experimental_compact_prompt_file: path.join(
              fixture.root,
              `compact-${index}.md`,
            ),
            sqlite_home: path.join(codexHome, `sqlite-${index}`),
          };
          return {
            nativePaths,
            knowledgePath: path.join(fixture.root, `knowledge-${index}`),
            knowledgeDocuments: {
              "1-architecture.md.txt": `Synthetic architecture for scan ${index}.`,
            },
            path: entryPath,
            deepPath,
            workerConfigPath: noWorkerSnapshot ? undefined : deepPath,
            nativeProfile,
            profilePath,
            parentSandbox,
            permissionProfile: {
              ...deniedWorkerPermissionProfile,
              filesystem: {
                ...deniedWorkerPermissionProfile.filesystem,
                [deepPath]: { ".": "deny" },
                [codexHome]: { ".": "deny" },
                [literalDeniedPath]: { ".": "deny" },
              },
            },
            provider,
            providerConfig,
            environment:
              index === 0
                ? undefined
                : {
                    ...workerScanEnvironment(fixture.root, index),
                    SYNTHETIC_GATEWAY_KEY: providerKeys[index],
                    SYNTHETIC_HEADER_VALUE: providerHeaders[index],
                    CODEX_SQLITE_HOME: path.join(
                      fixture.root,
                      `native-state-${index}`,
                    ),
                    ...(index === 1
                      ? { TMP: temporaryEnvironments[index].TEMP }
                      : {}),
                  },
            authentication:
              index === 0
                ? {}
                : {
                    cli_auth_credentials_store:
                      index % 2 ? "file" : "ephemeral",
                    forced_login_method: index % 2 ? "api" : "chatgpt",
                    forced_chatgpt_workspace_id: `synthetic-workspace-${index}`,
                  },
            endpoint,
            serviceTier,
            instructionsFile,
            verbosity,
            modelContextWindow: index === 0 ? undefined : 32_000 * (index + 1),
            autoCompactTokenLimit:
              index === 0 ? undefined : 24_000 * (index + 1),
            windowsSandbox,
            shellPolicy:
              index === 0
                ? undefined
                : {
                    inherit: index % 2 === 0 ? "core" : "none",
                    include_only: ["PATH", "SYNTHETIC_INCLUDED"],
                    exclude: ["SYNTHETIC_EXCLUDED"],
                    set: { SYNTHETIC_SHELL_MARKER: `scan-${index}` },
                  },
            webSearch,
            skills,
            features,
            telemetry,
            workerTelemetry,
            configuration: {
              ...parsedConfiguration,
              ...inheritedTelemetry,
              projects: { [fixture.root]: { trust_level: "trusted" } },
              ...Object.fromEntries(
                Object.entries(nativePaths).map(([key, value]) => [
                  key,
                  index === 0 ? value : "parent",
                ]),
              ),
              ...(skills === undefined
                ? {}
                : {
                    skills:
                      index === 1 || index === 4 || mergeProfileTelemetry
                        ? {
                            config: [
                              {
                                path: path.join(
                                  fixture.root,
                                  "overridden",
                                  "SKILL.md",
                                ),
                                enabled: false,
                              },
                            ],
                          }
                        : skills,
                  }),
              ...(index === 0
                ? {}
                : { service_tier: index === 2 ? "flex" : serviceTier }),
              ...(index === 2 ||
              index === 3 ||
              index === 4 ||
              mergeProfileTelemetry
                ? {
                    profile: "selected",
                    approval_policy: "never",
                    profiles: {
                      ...profiles,
                      selected: {
                        ...profiles.selected,
                        approval_policy: "on-request",
                        ...(index === 4 || mergeProfileTelemetry
                          ? { skills }
                          : {}),
                        ...(index === 2 ? { service_tier: serviceTier } : {}),
                        ...(index === 4 ? telemetry : {}),
                        ...(mergeProfileTelemetry
                          ? {
                              analytics: {},
                              otel: {
                                environment: "synthetic-scan-0",
                                exporter: {
                                  "otlp-http": {
                                    endpoint: "http://localhost:4318/v1/logs",
                                  },
                                },
                              },
                              responses_api_metadata: {
                                custom_tag: "synthetic-scan-0",
                                profile_only: "selected-profile",
                              },
                            }
                          : {}),
                      },
                      unselected: { service_tier: "fast" },
                    },
                  }
                : {}),
              ...(provider === undefined ? {} : { model_provider: provider }),
            },
          };
        },
      );
      await Promise.all(
        workerConfigurations.map((entry) =>
          Promise.all([
            mkdir(entry.knowledgePath).then(() =>
              Promise.all(
                Object.entries(entry.knowledgeDocuments).map(([name, text]) =>
                  writeFile(path.join(entry.knowledgePath, name), text),
                ),
              ),
            ),
            writeFile(entry.path, stringifyToml(entry.configuration)),
            ...(entry.environment === undefined
              ? []
              : [
                  writeFile(
                    entry.environment.NODE_EXTRA_CA_CERTS,
                    rootCertificates[0]!,
                  ),
                ]),
            writeFile(
              entry.deepPath,
              stringifyToml({
                worker_runtime: {
                  ...entry.authentication,
                  ...entry.workerTelemetry,
                  ...entry.nativePaths,
                  projects: { [fixture.root]: { trust_level: "untrusted" } },
                  approval_policy: "on-request",
                  default_permissions: "parent",
                  permissions: { parent: { filesystem: { ":root": "write" } } },
                  sandbox_mode: "danger-full-access",
                  sandbox_workspace_write: { network_access: true },
                  mcp_servers: { parent: { command: "synthetic-parent-tool" } },
                  ...(entry.skills === undefined
                    ? {}
                    : { skills: entry.skills }),
                  ...(entry.endpoint === undefined
                    ? {}
                    : { openai_base_url: entry.endpoint }),
                  ...(entry.provider === undefined
                    ? {}
                    : {
                        model_instructions_file: entry.instructionsFile,
                        model_verbosity: entry.verbosity,
                        model_context_window: entry.modelContextWindow,
                        model_auto_compact_token_limit:
                          entry.autoCompactTokenLimit,
                        web_search: entry.webSearch,
                        model_provider: entry.provider,
                        native_profile: entry.nativeProfile,
                        environment: entry.environment,
                        windows: { sandbox: entry.windowsSandbox },
                        shell_environment_policy: entry.shellPolicy,
                        features: entry.features,
                      }),
                },
              }),
            ),
            ...(entry.profilePath === undefined
              ? []
              : [
                  writeFile(
                    entry.profilePath,
                    stringifyToml({
                      model_provider: entry.provider,
                      model_providers: {
                        [entry.provider!]: entry.providerConfig,
                      },
                    }),
                  ),
                ]),
          ]),
        ),
      );
      await writeFile(promptPath, "synthetic worker configuration fixture");
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = codexHome;
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
      process.env.CODEX_SECURITY_PLUGIN_ROOT = path.join(
        fixture.root,
        "ambient-plugin",
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
          FAKE_CODEX_PREFLIGHT_PROFILE: JSON.stringify(
            workerConfigurations.find(
              (entry) => entry.path === options.env?.CODEX_SECURITY_CONFIG_PATH,
            )!.permissionProfile,
          ),
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
      const nodePaths = settings.map((_, index) =>
        path.join(fixture.root, `selected node ${index}`, "node"),
      );

      const executors = settings.map(
        (modelSettings, index) =>
          new CodexSdkWorkerExecutor({
            ...modelSettings,
            deepScanConfig: {
              workers: index + 1,
              subagents: index,
              stopAfterNoNew: 2,
              stopAfterConsecutiveErrors: 3,
              maxDiscoveryRuns: 9,
              maxTimeHours: index + 0.5,
            },
            parentSandbox: workerConfigurations[index].parentSandbox,
            artifactContext: {
              pluginRoot: path.join(fixture.root, `plugin-${index}`),
              repoRoot: fixture.root,
              scanId: `fixture-scan-${modelSettings.model ?? "inherited"}`,
              includePaths:
                index % 2 === 0
                  ? ["api", `background jobs ${index}`]
                  : undefined,
              filePaths: index % 2 === 0 ? [`background jobs ${index}`] : [],
              pythonCommand: `${helperPython}-${index} `,
            },
          }),
      );
      // A running coordinator retains its settings if the source file changes.
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
          launches.length = 0;
          await Promise.all(
            executors.map((executor, index) => {
              // Snapshot each scan environment independently.
              process.env.CODEX_MCP_NODE_PATH = nodePaths[index];
              Object.assign(process.env, temporaryEnvironments[index]);
              process.env.CODEX_SECURITY_STATE_DIR = path.join(
                fixture.root,
                `state-${index}`,
              );
              process.env.CODEX_SECURITY_CONFIG_PATH =
                workerConfigurations[index].path;
              process.env.CODEX_SECURITY_KNOWLEDGE_BASE =
                workerConfigurations[index].knowledgePath;
              process.env.XDG_CACHE_HOME = path.join(
                fixture.root,
                `cache-${index} `,
              );
              for (const name of [
                "LD_LIBRARY_PATH",
                "DYLD_LIBRARY_PATH",
                "DYLD_FALLBACK_LIBRARY_PATH",
              ]) {
                process.env[name] = path.join(
                  fixture.root,
                  `libraries-${index}`,
                );
              }
              restoreEnv(
                "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
                workerConfigurations[index].workerConfigPath,
              );
              return executor.run(
                workerRequest(promptPath, fixture.root, {
                  kind,
                  resumeThreadId,
                  ...(resumeThreadId
                    ? {
                        continuationPrompt:
                          "synthetic worker configuration fixture\nsynthetic resumed worker context",
                      }
                    : {}),
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
            const selectedProvider = workerConfigurations[index];
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
              workerLaunch.environment!.CODEX_SECURITY_PLUGIN_ROOT,
              path.join(fixture.root, "ambient-plugin"),
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_CONFIG_PATH,
              workerConfigurations[index].path,
            );
            const deepConfigPath =
              workerLaunch.environment!.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH!;
            assert.ok(path.isAbsolute(deepConfigPath));
            assert.notEqual(
              deepConfigPath,
              workerConfigurations[index].workerConfigPath,
            );
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(
                  parseToml(workerPermissionProfileOverride(workerLaunch.args)!)
                    .permissions,
                ),
              ),
              {
                codex_security_deep_scan_worker:
                  workerConfigurations[index].permissionProfile,
              },
            );
            assert.equal(
              workerLaunch.args.some((arg) =>
                arg.startsWith("permissions.codex_security_policy"),
              ),
              false,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_KNOWLEDGE_BASE,
              workerConfigurations[index].knowledgePath,
            );
            const invocation = await readJson(workerLaunch.markerPath);
            if (
              process.platform === "win32" &&
              configuration === "" &&
              index === 0
            ) {
              const acl = windowsAcl(workerLaunch.markerPath);
              assert.ok(!acl.includes(";;;WD)"));
              assertFlagPair(invocation.argv, "--cd", fixture.root);
            }
            for (const name of [
              "LD_LIBRARY_PATH",
              "DYLD_LIBRARY_PATH",
              "DYLD_FALLBACK_LIBRARY_PATH",
            ]) {
              assert.equal(
                workerLaunch.environment![name],
                path.join(fixture.root, `libraries-${index}`),
              );
              assert.equal(
                invocation.runtimeEnvironment[name],
                workerLaunch.environment![name],
              );
            }
            assert.equal(
              invocation.knowledgePath,
              workerConfigurations[index].knowledgePath,
            );
            assert.deepEqual(
              invocation.knowledgeDocuments,
              workerConfigurations[index].knowledgeDocuments,
            );
            assert.equal(invocation.codexHome, await realpath(codexHome));
            assert.deepEqual(invocation.temporaryEnvironment, {
              ...temporaryEnvironments[index],
              ...(index === 1
                ? { TMP: temporaryEnvironments[index].TEMP }
                : {}),
            });
            for (const name of ["TEMP", "TMP"] as const) {
              assert.equal(
                process.env[name],
                temporaryEnvironments.at(-1)![name],
              );
            }
            assert.equal(invocation.deepConfigPath, deepConfigPath);
            assert.deepEqual(
              { ...(parseToml(invocation.deepConfig).deep_scan as object) },
              {
                workers: index + 1,
                subagents: index,
                stop_after_no_new: 2,
                stop_after_consecutive_errors: 3,
                max_discovery_runs: 9,
                max_time_hours: index + 0.5,
              },
            );
            await assert.rejects(readFile(deepConfigPath), { code: "ENOENT" });
            assert.equal(
              invocation.runtimeEnvironment.CODEX_SECURITY_STATE_DIR,
              path.join(fixture.root, `state-${index}`),
            );
            assert.equal(invocation.providerKey, providerKeys[index]);
            assert.equal(
              invocation.mcpNodePath,
              selectedProvider.environment?.CODEX_MCP_NODE_PATH ??
                nodePaths[index],
            );
            assert.equal(process.env.CODEX_MCP_NODE_PATH, nodePaths.at(-1));
            assert.equal(invocation.providerHeader, providerHeaders[index]);

            assert.equal(workerLaunch.environment!.CODEX_API_KEY, undefined);
            assert.equal(
              workerLaunch.environment!.CODEX_SQLITE_HOME,
              workerConfigurations[index].environment?.CODEX_SQLITE_HOME,
            );
            assert.equal(process.env.SYNTHETIC_GATEWAY_KEY, undefined);
            assert.equal(process.env.SYNTHETIC_HEADER_VALUE, undefined);
            assertConfigOverrides(invocation.argv, {
              ...workerConfigurations[index].authentication,
              openai_base_url: workerConfigurations[index].endpoint,
              model_reasoning_summary: expected,
              service_tier: workerConfigurations[index].serviceTier,
              model_instructions_file:
                workerConfigurations[index].instructionsFile,
              model_verbosity: workerConfigurations[index].verbosity,
              model_context_window:
                workerConfigurations[index].modelContextWindow,
              model_auto_compact_token_limit:
                workerConfigurations[index].autoCompactTokenLimit,
              web_search: workerConfigurations[index].webSearch,
              "windows.sandbox": workerConfigurations[index].windowsSandbox,
            });
            assert.deepEqual(
              nativeConfigOverrides(invocation.argv).filter((override) =>
                /^projects[.=]/.test(override),
              ),
              [],
              "Patch project trust is not forwarded to discovery, reducer or resumed workers.",
            );
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(
                  parseToml(
                    nativeConfigOverrides(invocation.argv)
                      .filter((override) => /^skills[.=]/.test(override))
                      .join("\n"),
                  ),
                ),
              )["skills"],
              workerConfigurations[index].skills,
              "Discovery, reducer and resumed concurrent launches retain their own skill selection.",
            );
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(
                  parseToml(
                    nativeConfigOverrides(invocation.argv)
                      .filter((override) =>
                        /^(analytics|otel|responses_api_metadata)[.=]/.test(
                          override,
                        ),
                      )
                      .join("\n"),
                  ),
                ),
              ),
              {
                ...workerConfigurations[index].telemetry,
                responses_api_metadata: {
                  codex_security_surface: "plugin",
                  codex_security_command: "scan",
                  codex_security_scan_mode: "deep",
                  ...workerConfigurations[index].telemetry
                    .responses_api_metadata,
                  codex_security_worker_role: kind,
                },
              },
            );
            assert.equal(
              invocation.cacheDirectory,
              path.join(fixture.root, `cache-${index} `),
            );
            assert.deepEqual(
              nativeConfigOverrides(invocation.argv)
                .filter((override) =>
                  override.startsWith("model_reasoning_effort="),
                )
                .map((override) => parseToml(override).model_reasoning_effort),
              reasoningEffort === undefined ? [] : [reasoningEffort],
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
            assert.equal(
              invocation.configPath,
              workerConfigurations[index].path,
            );
            if (selectedProvider.provider === undefined) {
              assert.equal(
                invocation.argv.some(
                  (arg: string) =>
                    arg.startsWith("model_provider=") ||
                    arg.startsWith("model_providers="),
                ),
                false,
              );
            } else {
              assert.ok(
                invocation.argv.includes(
                  `model_provider=${JSON.stringify(selectedProvider.provider)}`,
                ),
              );
            }
            if (
              selectedProvider.provider !== undefined &&
              selectedProvider.providerConfig
            ) {
              assertFlagPair(
                invocation.argv,
                "--profile",
                selectedProvider.nativeProfile!,
              );
              assert.deepEqual(
                JSON.parse(
                  JSON.stringify(
                    parseToml(invocation.profileContents).model_providers,
                  ),
                ),
                {
                  [selectedProvider.provider]: selectedProvider.providerConfig,
                },
              );
            }
            assert.equal(
              invocation.argv.some(
                (arg: string) =>
                  arg.startsWith("model_providers=") ||
                  arg.includes("synthetic-gateway-key-") ||
                  arg.includes("synthetic-header-") ||
                  arg.includes("synthetic-bearer-") ||
                  arg.includes("synthetic-client-secret-"),
              ),
              false,
            );
            assert.ok(
              invocation.stdin.includes(
                JSON.stringify(
                  path.join(fixture.root, `plugin-${index}`, "skills"),
                ),
              ),
            );
            assert.ok(invocation.stdin.includes("<skill-name>/SKILL.md"));
            assert.ok(
              invocation.stdin.includes(
                resumeThreadId
                  ? "synthetic resumed worker context"
                  : "synthetic worker configuration fixture",
              ),
            );
            assert.equal(
              invocation.stdin.includes(
                JSON.stringify(
                  path.join(fixture.root, "ambient-plugin", "skills"),
                ),
              ),
              false,
            );
            assert.deepEqual(
              invocation.gitEnvironment,
              expectedGitEnvironment(
                gitEnvironment,
                nodePaths[index],
                selectedProvider.environment,
              ),
            );
            for (const [name, value] of Object.entries({
              ...gitEnvironment,
              CODEX_MCP_NODE_PATH: nodePaths.at(-1),
            })) {
              assert.equal(process.env[name], value);
            }
            assert.equal(invocation.python, python);
            assertConfigOverrides(invocation.argv, {
              "mcp_servers.cs_artifacts.command": process.execPath,
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_INCLUDE_PATHS_JSON":
                undefined,
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_PYTHON_COMMAND": `${helperPython}-${index} `,
              "mcp_servers.cs_artifacts.args.0": path.join(
                fixture.root,
                `plugin-${index}`,
                "mcp",
                "server.mjs",
              ),
              "mcp_servers.cs_artifacts.args.1": "--artifact-writer",
              "mcp_servers.cs_artifacts.args.2": "--stdio",
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_PLUGIN_ROOT":
                path.join(fixture.root, `plugin-${index}`),
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_ARTIFACT_LAYOUT":
                kind === "dedup" ? "reducer" : "worker",
            });
            const servers = nativeConfigOverrides(invocation.argv)
              .map((value) => parseToml(value))
              .find((value) => value["mcp_servers"])!["mcp_servers"] as Record<
              string,
              { env: Record<string, string> }
            >;
            const scopeFile =
              servers["cs_artifacts"]!.env["CODEX_SECURITY_INCLUDE_PATHS_FILE"];
            if (index % 2 === 0) {
              assert.ok(scopeFile && path.isAbsolute(scopeFile));
              assert.deepEqual(invocation.scopeInput.paths, [
                "api",
                `background jobs ${index}`,
              ]);
              assert.deepEqual(invocation.scopeInput.filePaths, [
                `background jobs ${index}`,
              ]);
              await assert.rejects(readFile(scopeFile), { code: "ENOENT" });
            } else assert.equal(scopeFile, undefined);
            assert.equal(process.env.PYTHON, python);
            assert.equal(invocation.deepConfigPath, deepConfigPath);
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(
                  parseToml(
                    invocation.argv
                      .filter((arg: string) =>
                        arg.startsWith("shell_environment_policy="),
                      )
                      .join("\n"),
                  ),
                ),
              ).shell_environment_policy,
              workerConfigurations[index].shellPolicy,
            );
            const workerFeatures = parseToml(
              invocation.argv
                .filter((arg: string) => /^features[.=]/.test(arg))
                .join("\n"),
            ).features;
            assert.deepEqual(JSON.parse(JSON.stringify(workerFeatures)), {
              ...workerConfigurations[index].features,
              multi_agent_v2: {
                enabled: false,
                max_concurrent_threads_per_session: 1,
              },
              enable_fanout: false,
            });
            assertConfigOverrides(invocation.argv, {
              ...selectedProvider.nativePaths,
              sandbox_mode: undefined,
              "mcp_servers.parent": undefined,
            });
            assertReadOnlyWorkerPolicy(invocation.argv);
            assertWorkerSubagentPolicy(invocation.argv, 0);
          }
          for (const launch of launches.filter(({ args }) =>
            args.includes("app-server"),
          )) {
            const preflight = await readJson(launch.markerPath);
            const selectedProvider = workerConfigurations.find(
              (entry) => preflight.configPath === entry.path,
            );
            assert.ok(
              selectedProvider,
              "worker preflight must use the same scan environment",
            );
            assert.deepEqual(
              preflight.gitEnvironment,
              expectedGitEnvironment(
                gitEnvironment,
                nodePaths[workerConfigurations.indexOf(selectedProvider)],
                selectedProvider.environment,
              ),
            );
            const index = workerConfigurations.indexOf(selectedProvider);
            assert.equal(preflight.codexHome, await realpath(codexHome));
            assert.equal(
              preflight.stateDirectory,
              path.join(fixture.root, `state-${index}`),
            );
            assert.deepEqual(preflight.temporaryEnvironment, {
              ...temporaryEnvironments[index],
              ...(index === 1
                ? { TMP: temporaryEnvironments[index].TEMP }
                : {}),
            });
            assert.equal(
              launch.environment!.CODEX_SECURITY_STATE_DIR,
              path.join(
                fixture.root,
                `state-${workerConfigurations.indexOf(selectedProvider)}`,
              ),
            );
            assert.equal(
              preflight.providerKey,
              selectedProvider.environment?.SYNTHETIC_GATEWAY_KEY,
            );
            assert.equal(
              preflight.providerHeader,
              selectedProvider.environment?.SYNTHETIC_HEADER_VALUE,
            );
            assertConfigOverrides(preflight.argv, {
              openai_base_url: selectedProvider.endpoint,
              model_instructions_file: selectedProvider.instructionsFile,
              ...selectedProvider.nativePaths,
              model_verbosity: selectedProvider.verbosity,
              model_context_window: selectedProvider.modelContextWindow,
              model_auto_compact_token_limit:
                selectedProvider.autoCompactTokenLimit,
              web_search: selectedProvider.webSearch,
              "windows.sandbox": selectedProvider.windowsSandbox,
            });
            assert.equal(
              preflight.cacheDirectory,
              path.join(
                fixture.root,
                `cache-${workerConfigurations.indexOf(selectedProvider)} `,
              ),
            );
            assert.deepEqual(
              preflight.argv.filter((arg: string) =>
                arg.startsWith("model_provider="),
              ),
              selectedProvider.provider === undefined
                ? []
                : [
                    `model_provider=${JSON.stringify(selectedProvider.provider)}`,
                  ],
            );
            const providerOverrides = preflight.argv.filter((arg: string) =>
              arg.startsWith("model_providers="),
            );
            const provider = selectedProvider.providerConfig;
            assert.equal(
              providerOverrides.length,
              provider === undefined ? 0 : 1,
            );
            if (provider !== undefined) {
              assert.deepEqual(
                JSON.parse(
                  JSON.stringify(
                    parseToml(providerOverrides[0]).model_providers,
                  ),
                ),
                {
                  [selectedProvider.provider!]: {
                    name: provider.name,
                    wire_api: "responses",
                    ...(provider.requires_openai_auth === undefined
                      ? {}
                      : {
                          requires_openai_auth: provider.requires_openai_auth,
                        }),
                  },
                },
              );
            }
            assert.equal(
              preflight.argv.some(
                (arg: string) =>
                  arg.includes("synthetic-gateway-key-") ||
                  arg.includes("synthetic-header-") ||
                  arg.includes("synthetic-bearer-") ||
                  arg.includes("synthetic-client-secret-"),
              ),
              false,
            );
            const execution = workerLaunches.find(
              (worker) =>
                worker.environment!.CODEX_SECURITY_CONFIG_PATH ===
                selectedProvider.path,
            )!;
            assert.deepEqual(
              nativeConfigOverrides(launch.args).filter(
                (override) => !override.startsWith("model_providers="),
              ),
              nativeConfigOverrides(execution.args),
            );
          }
          await Promise.all(
            workerConfigurations.map((entry) =>
              Promise.all([
                writeFile(
                  entry.path,
                  'sqlite_home = "changed"\nmodel_reasoning_summary = "detailed"\nservice_tier = "changed"\nmodel_provider = "changed"\n[analytics]\nenabled = false\n[responses_api_metadata]\ncustom_tag = "changed"\n',
                ),
                writeFile(
                  entry.deepPath,
                  '[worker_runtime.features]\nshell_tool = true\nunified_exec = true\nview_image = true\n[worker_runtime]\nsqlite_home = "changed"\nopenai_base_url = "https://changed-snapshot.example.test/v1"\nweb_search = "live"\nmodel_provider = "changed"\nnative_profile = "changed"\nmodel_instructions_file = "changed-instructions.md"\nmodel_verbosity = "changed"\nmodel_context_window = 999000\nmodel_auto_compact_token_limit = 888000\n[worker_runtime.shell_environment_policy]\ninherit = "all"\n[worker_runtime.shell_environment_policy.set]\nSYNTHETIC_SHELL_MARKER = "changed"\n[worker_runtime.windows]\nsandbox = "changed"\n[worker_runtime.environment]\nSYNTHETIC_GATEWAY_KEY = "changed"\nSYNTHETIC_HEADER_VALUE = "changed"\n[worker_runtime.analytics]\nenabled = false\n[worker_runtime.responses_api_metadata]\ncustom_tag = "changed"\n',
                ),
              ]),
            ),
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

async function testBedrockCredentialsReachWorker(
  credentials: "all" | "oidc" = "all",
) {
  const fixture = await fakeCodexFixture();
  const mcpConfig = await readJson(import.meta.dirname, "../../.mcp.json");
  const awsNames: string[] = mcpConfig.mcpServers[
    "codex-security"
  ].env_vars.filter((name: string) => name.startsWith("AWS_"));
  const oidcNames = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
  ];
  const awsEnvironment = Object.fromEntries(
    awsNames
      .filter((name) => credentials === "all" || oidcNames.includes(name))
      .map((name: string) => [name, `synthetic-bedrock-${name.toLowerCase()}`]),
  );
  if (credentials === "all") assert.ok(awsEnvironment.AWS_BEARER_TOKEN_BEDROCK);
  assert.ok(awsEnvironment.AWS_ACCESS_KEY_ID);
  assert.ok(awsEnvironment.AWS_SECRET_ACCESS_KEY);
  assert.ok(awsEnvironment.AWS_SESSION_TOKEN);
  const codexHome = path.join(fixture.root, "private profile home");
  const nativeProfile = `bedrock_${credentials}`;
  const providerConfig = {
    aws: {
      region: credentials === "all" ? "eu-west-1" : "eu-central-1",
      profile: `synthetic-bedrock-${credentials}`,
    },
  };
  await mkdir(codexHome);
  await writeFile(
    path.join(codexHome, `${nativeProfile}.config.toml`),
    stringifyToml({
      model_providers: { "amazon-bedrock": providerConfig },
    }),
  );
  const configPath = path.join(fixture.root, "bedrock.toml");
  await writeFile(
    configPath,
    'model_provider = "amazon-bedrock"\nmodel_reasoning_summary = "none"\n',
  );
  const deepConfigPath = path.join(fixture.root, "bedrock-workers.toml");
  await writeFile(
    deepConfigPath,
    stringifyToml({
      worker_runtime: {
        model_provider: "amazon-bedrock",
        model_reasoning_summary: "none",
        native_profile: nativeProfile,
      },
    }),
  );
  const environment = {
    ...Object.fromEntries(awsNames.map((name) => [name, awsEnvironment[name]])),
    OPENAI_API_KEY: undefined,
    CODEX_API_KEY: undefined,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_CONFIG_PATH: configPath,
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepConfigPath,
    CODEX_CLI_PATH: fixture.executablePath,
    FAKE_CODEX_BEDROCK_ENV_KEYS: JSON.stringify(awsNames),
  };
  const previousEnvironment = Object.keys(environment).map(
    (name) => [name, process.env[name]] as const,
  );
  for (const [name, value] of Object.entries(environment))
    restoreEnv(name, value);

  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(
      promptPath,
      "CAPTURE_SYNTHETIC_BEDROCK_AUTH\nCAPTURE_SYNTHETIC_OPENAI_AUTH\n",
    );
    const executor = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    });
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "fixture-bedrock-resume"]) {
        awsEnvironment[
          credentials === "oidc"
            ? "AWS_SESSION_TOKEN"
            : "AWS_BEARER_TOKEN_BEDROCK"
        ] = `synthetic-${kind}-${resumeThreadId ?? "fresh"}`;
        awsEnvironment.AWS_REGION = resumeThreadId ? "us-west-2" : "us-east-2";
        Object.assign(process.env, awsEnvironment);
        const result = await executor.run(
          workerRequest(promptPath, workingDirectory, { kind, resumeThreadId }),
        );
        assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
        const invocation = await readJson(fixture.markerPath);
        assert.deepEqual(invocation.bedrockAuthentication, awsEnvironment);
        assert.deepEqual(invocation.openaiAuthentication, {});
        assertFlagPair(invocation.argv, "--profile", nativeProfile);
        assert.deepEqual(
          JSON.parse(
            JSON.stringify(
              parseToml(invocation.profileContents).model_providers,
            ),
          ),
          { "amazon-bedrock": providerConfig },
        );
        assert.equal(
          invocation.argv.includes("resume"),
          resumeThreadId !== undefined,
        );
        assertConfigOverrides(invocation.argv, {
          "mcp_servers.codex-security.enabled": false,
          model_provider: "amazon-bedrock",
          model_reasoning_summary: "none",
        });
      }
    }
  } finally {
    for (const [name, value] of previousEnvironment) {
      restoreEnv(name, value);
    }
  }
}

async function testExternalProviderCredentialsReachWorker() {
  for (const [provider, key] of [
    ["openrouter", "OPENROUTER_API_KEY"],
    ["fireworks", "FIREWORKS_API_KEY"],
  ]) {
    await withWorkerFixture(async (fixture, promptPath, workingDirectory) => {
      const configPath = path.join(fixture.root, "provider.toml");
      const deepPath = path.join(fixture.root, "workers.toml");
      const profile = `scan-${provider}`;
      const selectedKey = `synthetic-${provider}-scan-key`;
      const settings = {
        model_provider: provider,
        native_profile: profile,
        environment: { [key]: selectedKey },
      };
      await writeFile(configPath, stringifyToml({ model_provider: provider }));
      await writeFile(deepPath, stringifyToml({ worker_runtime: settings }));
      await writeFile(
        path.join(fixture.root, `${profile}.config.toml`),
        stringifyToml({
          model_provider: provider,
          model_providers: {
            [provider]: {
              name: provider,
              base_url: `https://${provider}.example.test/v1`,
              wire_api: "responses",
              env_key: key,
            },
          },
        }),
      );
      await writeFile(promptPath, "synthetic provider credential fixture");
      const environment = {
        CODEX_HOME: fixture.root,
        CODEX_SECURITY_CONFIG_PATH: configPath,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepPath,
        OPENAI_API_KEY: undefined,
        CODEX_API_KEY: undefined,
        OPENROUTER_API_KEY: undefined,
        FIREWORKS_API_KEY: undefined,
      };
      const saved = Object.keys(environment).map(
        (name) => [name, process.env[name]] as const,
      );
      const originalSpawn = childProcess.spawn;
      const launches: {
        args: readonly string[];
        environment: NodeJS.ProcessEnv;
      }[] = [];
      try {
        for (const [name, value] of Object.entries(environment))
          restoreEnv(name, value);
        childProcess.spawn = ((
          command: string,
          args: readonly string[],
          options: SpawnOptions,
        ) => {
          if (args[0] === "exec")
            launches.push({ args, environment: { ...options.env } });
          return originalSpawn(command, args, options);
        }) as typeof childProcess.spawn;
        syncBuiltinESMExports();
        const executor = new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox,
        });
        for (const kind of ["discovery", "dedup"] as const)
          for (const resumeThreadId of [undefined, "fixture-provider-resume"]) {
            launches.length = 0;
            process.env[key] = "changed-ambient-key";
            await executor.run(
              workerRequest(promptPath, workingDirectory, {
                kind,
                resumeThreadId,
              }),
            );
            assert.equal(launches.length, 1);
            const launch = launches[0];
            assert.equal(launch.environment[key], selectedKey);
            assert.equal(launch.environment.OPENAI_API_KEY, undefined);
            assert.equal(launch.environment.CODEX_API_KEY, undefined);
            assertFlagPair(launch.args, "--profile", profile);
            assertConfigOverrides(launch.args, {
              model_provider: provider,
              "mcp_servers.codex-security.enabled": false,
            });
            assert.equal(
              launch.args.includes("resume"),
              resumeThreadId !== undefined,
            );
            await writeFile(
              deepPath,
              stringifyToml({
                worker_runtime: {
                  ...settings,
                  environment: { [key]: "changed-snapshot-key" },
                },
              }),
            );
          }
      } finally {
        childProcess.spawn = originalSpawn;
        syncBuiltinESMExports();
        for (const [name, value] of saved) restoreEnv(name, value);
      }
    });
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

async function testLargeScopeTransport() {
  const names = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "FAKE_CODEX_MARKER",
  ];
  const saved = names.map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  const fixture = await fakeCodexFixture();
  const scanIds = [randomUUID(), randomUUID()];
  try {
    process.env.CODEX_CLI_PATH = process.execPath;
    process.env.CODEX_HOME = fixture.root;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: SpawnOptions,
    ) =>
      originalSpawn(command, [fixture.executablePath, ...args], {
        ...options,
        env: {
          ...options.env,
          FAKE_CODEX_MARKER: path.join(
            String(options.cwd ?? args[args.indexOf("--cd") + 1]),
            "invocation.json",
          ),
          FAKE_CODEX_PREFLIGHT_MARKER: path.join(
            String(options.cwd),
            "preflight.json",
          ),
        },
      })) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        let control: number[] = [];
        for (const count of [2, 16384]) {
          const sizes = await Promise.all(
            scanIds.map(async (scanId, index) => {
              const workerRoot = path.join(
                fixture.root,
                `scan-${index} café`,
                `${kind}-${resumed}`,
              );
              const output = path.join(workerRoot, "output");
              const prompt = path.join(workerRoot, "prompt.md");
              await mkdir(output, { recursive: true });
              await writeFile(prompt, "CAPTURE_SCOPE_INPUT");
              const includePaths = Array.from(
                { length: count },
                (_, row) =>
                  `scan-${index}/background jobs/café-${row}-${"a".repeat(110)}`,
              );
              const filePaths = includePaths.filter(
                (_, index) => index % 2 === 0,
              );
              const run = parseDeepScan({
                deepScan: {
                  scanId,
                  status: "running",
                  targetPath: fixture.root,
                  scope: ".",
                  includePaths,
                  filePaths,
                  scanDir: workerRoot,
                  config: {
                    workers: 1,
                    subagents: 0,
                    stopAfterNoNew: 1,
                    maxDiscoveryRuns: 1,
                  },
                  dispatchedCount: 0,
                  noNewStreak: 0,
                },
              });
              const executor = new CodexSdkWorkerExecutor({
                parentSandbox: trustedParentSandbox,
                artifactContext: {
                  pluginRoot: fixture.root,
                  repoRoot: run.targetPath,
                  scanId: run.scanId,
                  scope: run.scope,
                  includePaths: run.includePaths,
                  filePaths: run.filePaths,
                },
              });
              await executor.run(
                workerRequest(prompt, output, {
                  kind,
                  ...(resumed
                    ? { resumeThreadId: `scope-thread-${index}` }
                    : {}),
                  artifactContext: {
                    root: output,
                    layout: kind === "dedup" ? "reducer" : "worker",
                    ...(kind === "dedup"
                      ? {
                          deepReducer: {
                            scanRoot: workerRoot,
                            claimedWorkers: [
                              {
                                id: "source-worker",
                                resultPath: path.join(
                                  workerRoot,
                                  "accepted.json",
                                ),
                              },
                            ],
                          },
                        }
                      : {}),
                  },
                }),
              );
              const invocation = await readJson(output, "invocation.json");
              assert.deepEqual(invocation.scopeInput.paths, includePaths);
              assert.deepEqual(invocation.scopeInput.filePaths, filePaths);
              assert.equal(path.isAbsolute(invocation.scopeInput.file), true);
              await assert.rejects(readFile(invocation.scopeInput.file), {
                code: "ENOENT",
              });
              assert.equal(invocation.argv.includes("resume"), resumed);
              const argument = nativeConfigOverrides(invocation.argv).find(
                (value) => value.startsWith("mcp_servers="),
              )!;
              assert.ok(argument);
              return Buffer.byteLength(argument);
            }),
          );
          if (count === 2) control = sizes;
          else
            assert.deepEqual(
              sizes,
              control,
              "scope size must not increase the native command arguments",
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

async function testReducerAttemptContext() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(promptPath, "fixture reducer prompt\n");
    const deepReducer = {
      scanRoot: path.join(fixture.root, "scans"),
      claimedWorkers: [
        {
          id: "worker-1",
          resultPath: path.join(fixture.root, "worker", "result.json"),
          attempt: 2,
        },
      ],
    };
    for (const resume of [false, true]) {
      await new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
        artifactContext: {
          pluginRoot: fixture.root,
          scanRoot: deepReducer.scanRoot,
          repoRoot: fixture.root,
          scanId: "fixture-scan-id",
        },
      }).run({
        kind: "dedup",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: new AbortController().signal,
        ...(resume
          ? {
              resumeThreadId: "fixture-existing-thread",
              continuationPrompt: "continue the reducer\n",
            }
          : {}),
        artifactContext: {
          root: workingDirectory,
          layout: "reducer",
          deepReducer,
        },
      });
      const invocation = JSON.parse(await readFile(fixture.markerPath, "utf8"));
      assertConfigOverrides(invocation.argv, {
        "mcp_servers.cs_artifacts.env.CODEX_SECURITY_REDUCER_CONTEXT_JSON":
          JSON.stringify(deepReducer),
      });
    }
  } finally {
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
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
    assert.deepEqual(result.diagnostics, [
      {
        code: "worker_error",
        message:
          "Reconnecting... 2/5 (stream disconnected before completion: websocket closed by server before response.completed)",
      },
    ]);
    const invocation = await readJson(fixture.markerPath);
    assert.equal(invocation.argv.includes("--model"), false);
    assertConfigOverrides(invocation.argv, {
      model_reasoning_effort: undefined,
    });
  });
}

async function testSandboxNamespaceDiagnosticIsPreserved() {
  const result = await runFixtureWorker(
    "BWRAP_NAMESPACE_FAILURE",
    "discovery",
    3,
  );
  assert.deepEqual(result.diagnostics, [
    {
      code: "sandbox_namespace_exhausted",
      message:
        "private source text\nbwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_user_namespaces exceeded (ENOSPC)",
    },
  ]);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /super-secret-command/);
}

async function testArtifactDiagnosticSurvivesWorkerRetries(reference: string) {
  const { executeWorkbench } = await loadWorkbenchProcess();
  const {
    WorkbenchDeepScanStore,
    DeepScanWorkerRunner,
    createDeepScanArtifacts,
    requireRegularFile,
    recordCodexSecurityDeepReduction,
  } = await importModule({
    stdin: {
      contents: `export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
export { DeepScanWorkerRunner } from "./src/deep-scan/worker-runner.ts";
export { createDeepScanArtifacts, requireRegularFile } from "./src/deep-scan/artifacts.ts";
export { recordCodexSecurityDeepReduction } from "./src/artifact-deep-reducer.ts";`,
      resolveDir: path.resolve(import.meta.dirname, ".."),
    },
    loader: { ".md": "text" },
  });
  await withWorkerFixture(async (fixture) => {
    const saved = [
      "CODEX_HOME",
      "CODEX_SECURITY_STATE_DIR",
      "FAKE_CODEX_ARTIFACT_EVENT",
    ].map((name) => [name, process.env[name]] as const);
    process.env.CODEX_HOME = fixture.root;
    process.env.CODEX_SECURITY_STATE_DIR = path.join(fixture.root, "state");
    try {
      const targetPath = path.join(fixture.root, "target");
      await mkdir(targetPath);
      await writeFile(
        path.join(targetPath, "fixture.py"),
        "print(1)\nprint(2)\n",
      );
      const store = new WorkbenchDeepScanStore(
        (args: string[], input?: string) =>
          executeWorkbench(
            process.env.PYTHON?.trim() || "python3",
            args,
            input,
          ),
      );
      const started = await store.begin({
        targetPath,
        threadId: "diagnostic-owner",
        scanRoot: path.join(fixture.root, "scans"),
      });
      assert.ok(
        (
          await stat(path.join(fixture.root, "state", "workbench.sqlite3"))
        ).isFile(),
      );
      const { run } = await store.claimCoordinator({
        scanId: started.scanId,
        threadId: "diagnostic-owner",
      });
      const artifacts = createDeepScanArtifacts(run.scanDir);
      const sourcePath = path.join(
        artifacts.workersRoot,
        "discovery/output/result.json",
      );
      const artifactDir = path.join(
        artifacts.dedupRoot,
        randomUUID(),
        "output",
      );
      const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
      await mkdir(path.dirname(sourcePath), { recursive: true });
      await mkdir(artifactDir, { recursive: true });
      await writeFile(promptPath, "Record the reducer result.");
      const sourceFinding = finding("fixture", "fixture.py");
      await writeJson(
        sourcePath,
        workerDraft([sourceFinding], { scanId: run.scanId }),
      );
      const workerIds = [randomUUID(), randomUUID()];
      for (const id of workerIds) {
        const worker = {
          id,
          scanId: run.scanId,
          kind: "discovery",
          promptPath,
          artifactDir: path.dirname(sourcePath),
          attempt: 1,
        };
        await store.updateWorker({ ...worker, status: "running" });
        await store.updateWorker({
          ...worker,
          status: "succeeded",
          resultManifestPath: sourcePath,
        });
      }
      const workerId = randomUUID();
      await store.claimDedup({
        id: workerId,
        scanId: run.scanId,
        workerIds,
        promptPath,
        artifactDir,
      });
      const deepReducer = {
        scanRoot: run.scanDir,
        claimedWorkers: [{ id: "discovery", resultPath: sourcePath }],
      };
      let message = "";
      await assert.rejects(
        () =>
          recordCodexSecurityDeepReduction(
            {
              root: artifactDir,
              repoRoot: targetPath,
              layout: "reducer",
              scanId: run.scanId,
              deepReducer,
            },
            {
              scanId: run.scanId,
              findings: [
                {
                  ...sourceFinding,
                  provenance: {
                    ...sourceFinding.provenance,
                    sourceFindingIds: [reference],
                  },
                },
              ],
            },
          ),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          message = error.message;
          return message.includes(reference);
        },
      );
      const persistedDiagnostic = message;
      process.env.FAKE_CODEX_ARTIFACT_EVENT = JSON.stringify({
        type: "item.completed",
        item: {
          id: "diagnostic",
          type: "mcp_tool_call",
          server: "cs_artifacts",
          tool: "record_codex_security_deep_reduction",
          status: "failed",
          error: null,
          result: { isError: true, content: [{ type: "text", text: message }] },
        },
      });
      let retries = 0;
      const runner = new DeepScanWorkerRunner({
        run,
        store,
        executor: new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox,
        }),
        artifacts,
        pluginRoot: path.resolve(import.meta.dirname, "../.."),
        clock: {
          now: () => new Date(),
          sleep: async () => {
            retries++;
            const state = await store.get(run.scanId, "diagnostic-owner");
            const worker = state.persistedWorkers.find(
              (worker: { id: string }) => worker.id === workerId,
            );
            assert.equal(worker.attempt, 1);
            assert.ok(worker.error.includes(persistedDiagnostic));
            assert.equal(
              (await readJson(fixture.markerPath)).argv.includes("resume"),
              false,
            );
          },
        },
        random: () => 0,
        log: () => {},
        retryDelaysMs: [0],
        signal: new AbortController().signal,
      });
      const outcome = await runner.runWorkerWithRetries({
        workerId,
        kind: "dedup",
        promptPath,
        promptRoot: path.join(path.dirname(artifactDir), "prompts"),
        artifactDir,
        artifactContext: { root: artifactDir, layout: "reducer", deepReducer },
        subagents: 0,
        validate: () =>
          requireRegularFile(
            path.join(artifactDir, "result.json"),
            artifactDir,
          ),
        beforeRetry: async () => {},
      });
      assert.equal(outcome.status, "failed");
      assert.equal(retries, 1);
      const state = await store.get(run.scanId, "diagnostic-owner");
      const worker = state.persistedWorkers.find(
        (worker: { id: string }) => worker.id === workerId,
      );
      assert.equal(worker.status, "failed");
      assert.equal(worker.attempt, 2);
      assert.ok(worker.error.includes(persistedDiagnostic));
      const invocation = await readJson(fixture.markerPath);
      assert.equal(
        invocation.argv[invocation.argv.indexOf("resume") + 1],
        "fixture-thread-id",
      );
    } finally {
      for (const [name, value] of saved) restoreEnv(name, value);
    }
  });
}

async function testOwnedArtifactToolFailureDiagnosticIsPreserved() {
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
          message: prompt.includes("TRANSPORT_FAILED")
            ? "--provider-error transport closed sk-proj-synthetic-secret /private/customer/path"
            : prompt.includes("REJECTED")
              ? "private output sk-proj-synthetic-secret"
              : `Codex worker artifact tool ${tool} ${reason}.`,
        },
      ]);
    } else {
      assert.equal(result.diagnostics, undefined);
    }
    assert.doesNotMatch(
      JSON.stringify(result),
      /Bearer synthetic-secret|private source text/i,
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
    {
      ...failedArtifactTool,
      server: "foreign_server",
      error: { message: ipcFrameError },
    },
    { ...failedArtifactTool, result: resultWithText(ipcFrameError) },
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendItemDiagnostic(diagnostics, failedArtifactTool);
    appendItemDiagnostic(diagnostics, item);
    appendItemDiagnostic(diagnostics, failedArtifactTool);
    assert.deepEqual(diagnostics, [
      {
        code: "artifact_tool_failed",
        message:
          "Codex worker artifact tool get_codex_security_deep_reducer_inputs failed.",
      },
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
    appendItemDiagnostic(diagnostics, { type: "error", message });
    appendItemDiagnostic(diagnostics, {
      ...failedArtifactTool,
      result: resultWithText(message),
    });
    assert.deepEqual(diagnostics, [
      { code: "worker_error", message },
      { code: "artifact_tool_failed", message },
    ]);
  }
  for (const item of [
    {
      ...failedArtifactTool,
      server: "foreign_server",
      result: resultWithText(ipcFrameError),
    },
    {
      ...failedArtifactTool,
      server: "foreign_server",
      error: { message: "Synthetic unrelated transport failure" },
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
    appendItemDiagnostic(diagnostics, item);
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
  await completedWorkerSettlesWithoutWaitingForProcessExit();
  for (const kind of ["discovery", "dedup"] as const) {
    for (const resumed of [false, true]) {
      await completedWorkerSettlesWithoutWaitingForProcessExit(kind, resumed);
    }
  }
}

async function completedWorkerSettlesWithoutWaitingForProcessExit(
  kind?: DeepScanWorkerKind,
  resumed = false,
) {
  const fixture = await fakeCodexFixture();
  const saved = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ].map((name) => [name, process.env[name]] as const);
  process.env.CODEX_CLI_PATH = process.execPath;
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) =>
    originalSpawn(
      command,
      command === process.execPath ||
        command === path.win32.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      options,
    )) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  if (kind !== undefined) {
    const home = path.join(fixture.root, "private profile home");
    await mkdir(home);
    const configPath = path.join(fixture.root, "preflight.toml");
    const workerConfigPath = path.join(home, "deep-scan-config.toml");
    await writeFile(configPath, "");
    await writeFile(
      workerConfigPath,
      '[worker_runtime]\nnative_profile = "completion_fixture"\n',
    );
    await writeFile(
      path.join(home, "completion_fixture.config.toml"),
      'model_provider = "openai"\n',
    );
    Object.assign(process.env, {
      CODEX_HOME: home,
      CODEX_SECURITY_CONFIG_PATH: configPath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfigPath,
    });
  }
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
    await writeFile(
      promptPath,
      kind === undefined
        ? "COMPLETE_THEN_HANG\n"
        : "COMPLETE_THEN_HANG_IGNORE_TERMINATION\n",
    );
    execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    }).run({
      kind: kind ?? "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: controller.signal,
      ...(resumed ? { resumeThreadId: "fixture-resumed-thread-id" } : {}),
      onThreadStarted: async () => {
        childPid = (await readJson(fixture.markerPath)).pid;
      },
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
    assert.equal(
      result.threadId,
      resumed ? "fixture-resumed-thread-id" : "fixture-thread-id",
    );
    const invocation = await readJson(fixture.markerPath);
    assert.equal(invocation.argv.includes("--profile"), kind !== undefined);
    assert.equal(invocation.argv.includes("resume"), resumed);

    controller.abort("coordinator immediately canceled its remaining workers");
    await new Promise((resolve) => setTimeout(resolve, 250));

    assert.deepEqual(unexpectedErrors, []);
    if (kind === undefined) {
      assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
    }
  } finally {
    clearTimeout(timeout);
    controller.abort("completed worker fixture cleanup");
    if (childPid) {
      try {
        process.kill(childPid, "SIGKILL");
      } catch {}
    }
    await execution?.catch(() => {});
    process.removeListener("uncaughtException", captureUnexpectedError);
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
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
  assertConfigOverrides(args, {
    "permissions.codex_security_deep_scan_worker.extends": ":read-only",
    "permissions.codex_security_deep_scan_worker.filesystem.:root": "read",
    "permissions.codex_security_deep_scan_worker.network.enabled": false,
  });
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

async function testWorkerCancellation() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  const originalSpawn = childProcess.spawn;
  let worker: ChildProcess | undefined;
  let workerSignal: AbortSignal | undefined;
  let cancelDuringCleanup: (() => void) | undefined;
  let timeout: NodeJS.Timeout | undefined;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const child = originalSpawn(
      command,
      command === process.execPath ||
        command === path.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      options,
    );
    if (args[0] === "exec") {
      assertFlagPair(args, "--thread-source", "security_scan");
      worker = child;
      workerSignal = options.signal;
      const kill = child.kill;
      child.kill = function (...args: Parameters<ChildProcess["kill"]>) {
        cancelDuringCleanup?.();
        return kill.apply(this, args);
      };
    }
    return child;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  process.env.CODEX_CLI_PATH = process.execPath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    const executor = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
      artifactContext: {
        pluginRoot: fixture.root,
        repoRoot: fixture.root,
        scanId: randomUUID(),
        includePaths: ["api"],
      },
    });
    const run = (controller: AbortController, onThreadStarted?: () => void) =>
      executor.run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: controller.signal,
        onThreadStarted,
        artifactContext: { root: workingDirectory, layout: "worker" },
      });
    const preAborted = new AbortController();
    const beforeStartup = new Error(
      "coordinator canceled before worker startup",
    );
    preAborted.abort(beforeStartup);
    await assert.rejects(
      run(preAborted),
      (error: Error) => error === beforeStartup,
    );
    assert.equal(worker, undefined);
    assert.equal(
      (await readdir(fixture.root)).some((name) => name.startsWith("scope-")),
      false,
    );
    await assert.rejects(readFile(fixture.preflightMarkerPath), {
      code: "ENOENT",
    });
    await assert.rejects(readFile(fixture.markerPath), { code: "ENOENT" });

    for (const prompt of [
      "BLOCK_AFTER_START",
      "COMPLETE_THEN_HANG",
      "FAIL_THEN_HANG",
    ]) {
      await writeFile(promptPath, `${prompt}\n`);
      const controller = new AbortController();
      const cancellation = new Error(
        "coordinator canceled its remaining workers",
      );
      // Exercise cancellation inside the real SDK's iterator cleanup, before kill returns.
      cancelDuringCleanup =
        prompt === "COMPLETE_THEN_HANG"
          ? () => controller.abort(cancellation)
          : undefined;
      const deadline = new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`${prompt} worker did not settle`)),
          10_000,
        );
      });
      const execution = Promise.race([
        run(controller, () => {
          if (prompt === "BLOCK_AFTER_START") controller.abort(cancellation);
        }),
        deadline,
      ]);
      if (prompt === "BLOCK_AFTER_START") {
        await assert.rejects(
          execution,
          (error: Error) =>
            error?.name === "AbortError" ||
            /abort|SIGTERM/i.test(error?.message ?? ""),
        );
        assert(workerSignal);
        assert.equal(workerSignal.aborted, true);
        assert.equal(workerSignal.reason, cancellation);
      } else {
        if (prompt === "FAIL_THEN_HANG") {
          await assert.rejects(execution, /fixture worker failed/);
          controller.abort(cancellation);
        } else {
          const result = await execution;
          assert.equal(result.threadId, "fixture-thread-id");
        }
        assert.equal(controller.signal.aborted, true);
        assert(workerSignal);
        assert.equal(workerSignal.aborted, false);
      }
      assert.equal(
        (await readdir(fixture.root)).some((name) => name.startsWith("scope-")),
        false,
      );
      assert.notEqual(workerSignal, controller.signal);
      const currentWorker = worker as ChildProcess | undefined;
      assert(currentWorker);
      assert.equal(currentWorker.killed, true);
      if (
        currentWorker.exitCode === null &&
        currentWorker.signalCode === null
      ) {
        await Promise.race([
          new Promise<void>((resolve) =>
            worker!.once("close", () => resolve()),
          ),
          deadline,
        ]);
      }
      clearTimeout(timeout);
      cancelDuringCleanup = undefined;
    }
  } finally {
    clearTimeout(timeout);
    cancelDuringCleanup = undefined;
    if (worker && worker.exitCode === null && worker.signalCode === null)
      worker.kill("SIGKILL");
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}

function testUsageLimitClassification() {
  for (const message of [
    "Quota exceeded. Check your plan and billing details.",
    "Your workspace is out of credits. Add credits to continue.",
    "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
    "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
    "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
    "You’ve hit your usage limit. Try again later.",
    "You’ve hit your usage limit for the selected model. Switch to another model to continue.",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.ok(error instanceof DeepScanNonRetryableError);
    assert.equal(error.message, message);
  }
  for (const message of [
    "429 Too Many Requests",
    "Command failed: Quota exceeded. Check your plan and billing details.",
  ]) {
    const error = codexWorkerTurnError(message);
    assert.equal(error.name, "Error");
    assert.equal(error.message, message);
  }
}

async function testWorkerTerminalEvents() {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
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
  process.env.CODEX_CLI_PATH = process.execPath;
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const quotaMessage = "Quota exceeded. Check your plan and billing details.";
    for (const event of [
      undefined,
      { type: "turn.failed", error: { message: quotaMessage } },
      { type: "turn.failed", error: { message: "429 Too Many Requests" } },
      { type: "error", message: quotaMessage },
      {
        type: "item.completed",
        item: { id: "quota-text", type: "agent_message", text: quotaMessage },
      },
    ] as const) {
      await writeFile(
        promptPath,
        event
          ? `IPC_DIAGNOSTIC_EVENT\n${JSON.stringify(event)}\n`
          : "NULL_USAGE\n",
      );
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
          const onNonRetryableError = mock.fn();
          const execution = new CodexSdkWorkerExecutor({
            parentSandbox: trustedParentSandbox,
          }).run({
            kind,
            promptPath,
            workingDirectory: fixture.root,
            subagents: 0,
            resumeThreadId,
            signal: new AbortController().signal,
            onNonRetryableError,
          });
          if (event?.type === "turn.failed") {
            const isQuota = event.error.message === quotaMessage;
            await assert.rejects(execution, {
              name: isQuota ? "DeepScanNonRetryableError" : "Error",
              message: event.error.message,
            });
            assert.deepEqual(
              onNonRetryableError.mock.calls.map(
                ({ arguments: [error] }) => error.message,
              ),
              isQuota ? [quotaMessage] : [],
            );
            continue;
          }
          const result = await execution;
          assert.equal(onNonRetryableError.mock.callCount(), 0);
          assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}
