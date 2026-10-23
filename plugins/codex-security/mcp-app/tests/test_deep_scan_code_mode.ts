import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { assertConfigOverrides, nativeConfigOverrides } from "./assertions.ts";
import { importSource } from "./import-module.ts";
import {
  createFakeCodexFixture,
  trustedParentSandbox,
} from "./support/fake-codex-fixture.ts";
import { readJson } from "./support/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { CodexSdkWorkerExecutor } = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/executor.ts"),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL("../src/deep-scan/executor.ts", import.meta.url).href,
      ),
    },
  },
);
const temporaryDirectories = createTemporaryDirectories(true);
const savedEnvironment = new Map(
  [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "FAKE_CODEX_MARKER",
  ].map((key) => [key, process.env[key]]),
);
const originalSpawn = childProcess.spawn;

try {
  delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
  await testNativeReducerSettings();
  for (const features of [
    {},
    {
      code_mode: {
        enabled: true,
        direct_only_tool_namespaces: ["fixture_direct"],
      },
      code_mode_host: { enabled: true },
    },
    { code_mode: { enabled: false } },
    { code_mode_host: { enabled: false } },
  ]) {
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "fixture-code-mode-resume"]) {
        const fixture = await createFakeCodexFixture(temporaryDirectories);
        const promptPath = path.join(fixture.root, "prompt.md");
        const configPath = path.join(fixture.root, "config.toml");
        const codexHome = path.join(fixture.root, "home");
        await mkdir(codexHome);
        await writeFile(promptPath, "synthetic worker prompt");
        await writeFile(configPath, stringifyToml({ features }));
        process.env.CODEX_HOME = codexHome;
        process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
        process.env.CODEX_CLI_PATH =
          process.platform === "win32"
            ? process.execPath
            : fixture.executablePath;
        childProcess.spawn = ((
          command: string,
          args: readonly string[] = [],
          options: SpawnOptions = {},
        ) =>
          originalSpawn(
            command,
            process.platform === "win32" &&
              (command === process.execPath ||
                command === path.toNamespacedPath(process.execPath))
              ? [fixture.executablePath, ...args]
              : args,
            options,
          )) as typeof childProcess.spawn;
        syncBuiltinESMExports();

        const execution = new CodexSdkWorkerExecutor({
          parentSandbox: trustedParentSandbox,
        }).run({
          kind,
          promptPath,
          workingDirectory: fixture.root,
          subagents: 0,
          signal: new AbortController().signal,
          resumeThreadId,
        });
        if (
          kind === "dedup" &&
          (features.code_mode?.enabled === false ||
            features.code_mode_host?.enabled === false)
        ) {
          await assert.rejects(execution, (error: Error) => {
            assert.equal(error.name, "DeepScanNonRetryableError");
            assert.match(error.message, /code.mode/i);
            return true;
          });
          await assert.rejects(readFile(fixture.markerPath), {
            code: "ENOENT",
          });
          continue;
        }

        await execution;
        const invocation = await readJson(fixture.markerPath);
        const preflight = await readJson(fixture.preflightMarkerPath);
        assert.deepEqual(
          nativeConfigOverrides(preflight.argv),
          nativeConfigOverrides(invocation.argv),
        );
        assertConfigOverrides(invocation.argv, {
          "features.code_mode.enabled":
            kind === "dedup" ? true : features.code_mode?.enabled,
          "features.code_mode_host.enabled":
            kind === "dedup" ? true : features.code_mode_host?.enabled,
        });
        if (features.code_mode?.direct_only_tool_namespaces) {
          const effective = nativeConfigOverrides(invocation.argv)
            .map((value) => parseToml(value))
            .findLast((value) => value.features)?.features as Record<
            string,
            Record<string, unknown>
          >;
          assert.deepEqual(effective.code_mode.direct_only_tool_namespaces, [
            "fixture_direct",
          ]);
        }
      }
    }
  }
} finally {
  childProcess.spawn = originalSpawn;
  syncBuiltinESMExports();
  for (const [name, value] of savedEnvironment) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  await temporaryDirectories.cleanup();
}

async function testNativeReducerSettings() {
  const sdkRequire = createRequire(import.meta.resolve("@openai/codex-sdk"));
  const nativeCli = sdkRequire.resolve("@openai/codex/bin/codex.js");
  for (const selected of [false, true]) {
    const fixture = await createFakeCodexFixture(temporaryDirectories);
    const codexHome = path.join(fixture.root, "home");
    await mkdir(codexHome);
    await writeFile(
      path.join(codexHome, "config.toml"),
      stringifyToml({ features: { code_mode: false } }),
    );
    process.env.CODEX_HOME = codexHome;
    process.env.CODEX_CLI_PATH = process.execPath;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    if (selected) {
      const configPath = path.join(fixture.root, "selected.toml");
      await writeFile(
        configPath,
        stringifyToml({ features: { code_mode: { enabled: true } } }),
      );
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
    }
    const promptPath = path.join(fixture.root, "prompt.md");
    await writeFile(promptPath, "synthetic reducer prompt");
    // Resolve user configuration with the packaged native CLI; only the model
    // execution is replaced with a controlled worker.
    childProcess.spawn = ((
      command: string,
      args: readonly string[] = [],
      options: SpawnOptions = {},
    ) =>
      originalSpawn(
        command,
        [
          args.includes("app-server") ? nativeCli : fixture.executablePath,
          ...args,
        ],
        options,
      )) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    const execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    }).run({
      kind: "dedup",
      promptPath,
      workingDirectory: fixture.root,
      subagents: 0,
      signal: new AbortController().signal,
      resumeThreadId: selected ? "fixture-resume" : undefined,
    });
    if (selected) {
      await execution;
      assertConfigOverrides((await readJson(fixture.markerPath)).argv, {
        "features.code_mode.enabled": true,
        "features.code_mode_host.enabled": true,
      });
    } else {
      await assert.rejects(execution, (error: Error) => {
        assert.equal(error.name, "DeepScanNonRetryableError");
        assert.match(error.message, /code.mode/i);
        return true;
      });
      await assert.rejects(readFile(fixture.markerPath), { code: "ENOENT" });
    }
  }
}
