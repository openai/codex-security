import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { importSource } from "./import-module.ts";
import {
  createFakeCodexFixture,
  trustedParentSandbox,
} from "./support/fake-codex-fixture.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { restoreEnv } from "./support/fake-codex-source.ts";
import {
  assertReadOnlyWorkerPolicy,
  workerPermissionProfileOverride,
} from "./support/worker-permissions.ts";

const executorSource = new URL("../src/deep-scan/executor.ts", import.meta.url);
const { CodexSdkWorkerExecutor } = await importSource(
  fileURLToPath(executorSource),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/server.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
);

test("Deep workers support first-use Codex homes", async (t) => {
  const temporaryDirectories = createTemporaryDirectories(true);
  const names = [
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "FAKE_CODEX_MARKER",
    "GIT_CONFIG_NOSYSTEM",
  ];
  const previous = names.map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  let previousUmask: number | undefined;
  try {
    for (const configured of [false, true]) {
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resume of [false, true]) {
          await t.test(
            `${configured ? "explicit" : "default"} home / ${kind} / ${resume ? "resumed" : "fresh"}`,
            async () => {
              if (previousUmask !== undefined) process.umask(previousUmask);
              previousUmask = undefined;
              const fixture =
                await createFakeCodexFixture(temporaryDirectories);
              const home = path.join(fixture.root, "home");
              await mkdir(home);
              const codexHome = path.join(
                home,
                configured ? "selected-codex-home" : ".codex",
              );
              await assert.rejects(access(codexHome), { code: "ENOENT" });
              for (const name of names) delete process.env[name];
              process.env.HOME = home;
              process.env.USERPROFILE = home;
              process.env.CODEX_CLI_PATH = fixture.executablePath;
              process.env.FAKE_CODEX_MARKER = fixture.markerPath;
              process.env.GIT_CONFIG_NOSYSTEM = "1";
              if (configured) process.env.CODEX_HOME = codexHome;
              const promptPath = path.join(fixture.root, "prompt.md");
              const workingDirectory = path.join(fixture.root, "artifacts");
              await mkdir(workingDirectory);
              await writeFile(promptPath, "fixture first-use home worker\n");
              const launched: { kind: string; file: string }[] = [];
              childProcess.spawn = ((
                command: string,
                args: readonly string[] = [],
                options: SpawnOptions = {},
              ) => {
                const childKind = args.includes("app-server")
                  ? "preflight"
                  : args.includes("exec")
                    ? "worker"
                    : undefined;
                if (childKind) {
                  const file = options.env?.CODEX_SECURITY_GIT_ENVIRONMENT_FILE;
                  assert.ok(file);
                  assert.equal(path.dirname(path.dirname(file)), codexHome);
                  assert.equal(
                    JSON.parse(readFileSync(file, "utf8")).GIT_CONFIG_NOSYSTEM,
                    "1",
                  );
                  if (process.platform !== "win32") {
                    assert.equal(statSync(codexHome).mode & 0o777, 0o700);
                    assert.equal(
                      statSync(path.dirname(file)).mode & 0o777,
                      0o700,
                    );
                    assert.equal(statSync(file).mode & 0o777, 0o600);
                  }
                  assert.equal(
                    options.env?.CODEX_HOME,
                    configured ? codexHome : undefined,
                  );
                  assertReadOnlyWorkerPolicy(args);
                  const profile = parseToml(
                    workerPermissionProfileOverride(args),
                  ) as {
                    permissions: {
                      codex_security_deep_scan_worker: {
                        filesystem: Record<string, unknown>;
                      };
                    };
                  };
                  assert.equal(
                    (
                      profile.permissions.codex_security_deep_scan_worker
                        .filesystem[path.dirname(file)] as Record<
                        string,
                        unknown
                      >
                    )["."],
                    "deny",
                  );
                  launched.push({ kind: childKind, file });
                  if (previousUmask !== undefined) {
                    process.umask(previousUmask);
                    previousUmask = undefined;
                  }
                }
                return originalSpawn(command, args, options);
              }) as typeof childProcess.spawn;
              syncBuiltinESMExports();
              if (process.platform !== "win32")
                previousUmask = process.umask(0o777);
              const result = await new CodexSdkWorkerExecutor({
                parentSandbox: trustedParentSandbox,
                artifactContext: {
                  pluginRoot: fixture.root,
                  repoRoot: fixture.root,
                  scanId: "fixture-scan-id",
                },
              }).run({
                kind,
                promptPath,
                workingDirectory,
                subagents: 0,
                signal: new AbortController().signal,
                ...(resume
                  ? {
                      resumeThreadId: "fixture-existing-thread",
                      continuationPrompt:
                        "Continue fixture first-use home worker\n",
                    }
                  : {}),
                artifactContext: {
                  root: workingDirectory,
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
              });
              assert.equal(
                result.threadId,
                resume ? "fixture-existing-thread" : "fixture-thread-id",
              );
              assert.deepEqual(
                launched.map((item) => item.kind),
                ["preflight", "worker"],
              );
              assert.equal(launched[0]!.file, launched[1]!.file);
              for (const { file } of launched)
                await assert.rejects(access(file), { code: "ENOENT" });
              assert.equal(await realpath(codexHome), codexHome);
              const invocation = JSON.parse(
                await readFile(fixture.markerPath, "utf8"),
              );
              assert.equal(
                invocation.codexHome,
                configured ? codexHome : undefined,
              );
              assert.equal(invocation.runtimeEnvironment.HOME, home);
            },
          );
        }
      }
    }
  } finally {
    if (previousUmask !== undefined) process.umask(previousUmask);
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of previous) restoreEnv(name, value);
    await temporaryDirectories.cleanup();
  }
});

test(
  "private home initialization preserves existing POSIX permissions",
  { skip: process.platform === "win32" },
  async () => {
    const { createPrivateDirectory } = await importSource(
      "src/helpers/private-directory.ts",
    );
    const temporaryDirectories = createTemporaryDirectories(true);
    const root = await temporaryDirectories.create(
      "codex-security-existing-home-",
    );
    const home = path.join(root, "home");
    await mkdir(home, { mode: 0o750 });
    await chmod(home, 0o750);
    const previousUmask = process.umask(0o777);
    try {
      createPrivateDirectory(home);
      assert.equal(statSync(home).mode & 0o777, 0o750);
    } finally {
      process.umask(previousUmask);
      await temporaryDirectories.cleanup();
    }
  },
);
