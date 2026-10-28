import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import {
  access,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { CodexSdkWorkerExecutor as Executor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { assertConfigOverrides, nativeConfigOverrides } from "./assertions.ts";
import { restoreEnv } from "./support/fake-codex-source.ts";
import { readJson } from "./support/json.ts";

export async function testWorkerGitConfiguration({
  CodexSdkWorkerExecutor,
  parentSandbox,
  withWorkerFixture,
  workerRequest,
}: {
  CodexSdkWorkerExecutor: typeof Executor;
  parentSandbox: DeepWorkerParentSandbox;
  withWorkerFixture: (
    action: (
      fixture: { root: string; markerPath: string },
      promptPath: string,
      workingDirectory: string,
    ) => Promise<void>,
  ) => Promise<void>;
  workerRequest: (
    promptPath: string,
    workingDirectory: string,
    options: Partial<CodexWorkerRequest>,
  ) => CodexWorkerRequest;
}) {
  const inherited = {
    GIT_CONFIG_GLOBAL: "inherited.gitconfig",
    GIT_CONFIG_SYSTEM: "system.gitconfig",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_PARAMETERS:
      "'diff.renames=true' 'http.extraHeader=synthetic-private-parameter-header'",
    GIT_CONFIG_COUNT: "2",
    GIT_CONFIG_KEY_0: "diff.renames",
    GIT_CONFIG_VALUE_0: "true",
    GIT_CONFIG_KEY_1: "http.https://example.test/.extraHeader",
    GIT_CONFIG_VALUE_1: "synthetic-private-indexed-header",
    GIT_CONFIG_KEY_1234567: "synthetic.unused",
    GIT_CONFIG_VALUE_1234567: "unused fixture value",
    GIT_ATTR_SOURCE: "fixture-attributes-revision",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_REPLACE_REF_BASE: "refs/fixture-replacements/",
    XDG_CONFIG_HOME: "selected-xdg-home",
  };
  const nativeSelectors = new Set([
    ...Object.keys(inherited),
    ...Object.keys(process.env).filter((name) =>
      /^(?:GIT_CONFIG_|GIT_ATTR_(?:SOURCE|NOSYSTEM)$|GIT_NO_REPLACE_OBJECTS$|GIT_REPLACE_REF_BASE$|XDG_CONFIG_HOME$)/iu.test(
        name,
      ),
    ),
  ]);
  const saved = [
    ...nativeSelectors,
    "CODEX_SECURITY_GIT_ENVIRONMENT",
    "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
    "CODEX_HOME",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
  ].map((name) => [name, process.env[name]] as const);
  const directory = await mkdtemp(
    path.join(tmpdir(), "worker-git-environment-"),
  );
  const inheritedFile = path.join(directory, "inherited.json");
  await writeFile(inheritedFile, JSON.stringify(inherited), { mode: 0o600 });
  process.env.CODEX_SECURITY_GIT_ENVIRONMENT_FILE = inheritedFile;
  process.env.CODEX_SECURITY_GIT_ENVIRONMENT =
    '{"GIT_CONFIG_GLOBAL":"obsolete.gitconfig"}';
  for (const name of nativeSelectors) delete process.env[name];
  process.env.GIT_CONFIG_SYSTEM = "";
  const originalSpawn = childProcess.spawn;
  const files = new Set<string>();
  let expectedBridge: Record<string, string> | undefined;
  let expectedSignal: AbortSignal;
  let configurationStarts = 0;
  let previousUmask: number | undefined;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const snapshot = options.env?.CODEX_SECURITY_GIT_ENVIRONMENT_FILE;
    if (
      snapshot !== undefined &&
      snapshot !== inheritedFile &&
      previousUmask !== undefined
    ) {
      assert.equal(statSync(path.dirname(snapshot)).mode & 0o777, 0o700);
      assert.equal(statSync(snapshot).mode & 0o777, 0o600);
      assert.ok(readFileSync(snapshot, "utf8"));
      process.umask(previousUmask);
      previousUmask = undefined;
    }
    if (args.includes("--no-includes")) {
      configurationStarts++;
      assert.equal(options.signal, expectedSignal);
    }
    if (args?.includes("exec")) {
      const file = options.env?.CODEX_SECURITY_GIT_ENVIRONMENT_FILE;
      assert.ok(file);
      files.add(file);
      assert.notEqual(file, inheritedFile);
      const projected = JSON.parse(readFileSync(file, "utf8"));
      assert.ok(!JSON.stringify(projected).includes("synthetic-private-"));
      if (expectedBridge!.GIT_CONFIG_PARAMETERS !== undefined) {
        assert.ok(
          projected.GIT_CONFIG_PARAMETERS.includes("diff.renames=true"),
        );
        expectedBridge!.GIT_CONFIG_PARAMETERS = projected.GIT_CONFIG_PARAMETERS;
      }
      assert.deepEqual(projected, expectedBridge);
      assert.equal(options.env?.CODEX_SECURITY_GIT_ENVIRONMENT, undefined);
      const permissions = parseToml(
        nativeConfigOverrides(args).find((value) =>
          value.startsWith("permissions.codex_security_deep_scan_worker="),
        )!,
      ).permissions as {
        codex_security_deep_scan_worker: {
          filesystem: Record<string, unknown>;
        };
      };
      assert.equal(
        (
          permissions.codex_security_deep_scan_worker.filesystem[
            path.dirname(file)
          ] as Record<string, unknown>
        )["."],
        "deny",
      );
    }
    return originalSpawn(command, args, options);
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resume of [false, true]) {
        await withWorkerFixture(
          async (fixture, promptPath, workingDirectory) => {
            process.env.CODEX_HOME = fixture.root;
            if (kind === "discovery" && resume) {
              const alias = path.join(fixture.root, "codex-home-alias");
              await symlink(
                fixture.root,
                alias,
                process.platform === "win32" ? "junction" : "dir",
              );
              process.env.CODEX_HOME = alias;
            }
            await writeFile(promptPath, "fixture Git configuration worker\n");
            const configPath = path.join(fixture.root, "worker-runtime.toml");
            const overrides = {
              GIT_CONFIG_GLOBAL: path.join(fixture.root, "selected.gitconfig"),
              GIT_CONFIG_VALUE_0: "false",
              GIT_ATTR_SOURCE: "",
              ...(kind === "dedup" && resume ? { CODEX_SECURITY_GIT: "" } : {}),
            };
            expectedBridge = {
              ...inherited,
              GIT_CONFIG_SYSTEM: "",
              ...overrides,
            };
            delete expectedBridge.GIT_CONFIG_KEY_1;
            delete expectedBridge.GIT_CONFIG_VALUE_1;
            expectedBridge.GIT_CONFIG_COUNT = "1";
            delete expectedBridge.CODEX_SECURITY_GIT;
            if (kind === "dedup" && resume) {
              for (const name of Object.keys(expectedBridge))
                if (
                  /^GIT_CONFIG_(?:COUNT|PARAMETERS|(?:KEY|VALUE)_\d+)$/u.test(
                    name,
                  )
                )
                  delete expectedBridge[name];
            }
            await writeFile(
              configPath,
              stringifyToml({ worker_runtime: { environment: overrides } }),
            );
            process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
            process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = configPath;
            expectedSignal = new AbortController().signal;
            configurationStarts = 0;
            const layout = kind === "dedup" ? "reducer" : "worker";
            if (process.platform !== "win32" && resume)
              previousUmask = process.umask(0o777);
            const result = await new CodexSdkWorkerExecutor({
              parentSandbox: parentSandbox,
              artifactContext: {
                pluginRoot: fixture.root,
                repoRoot: fixture.root,
                scanId: "fixture-scan-id",
              },
            }).run(
              workerRequest(promptPath, workingDirectory, {
                kind,
                signal: expectedSignal,
                ...(resume
                  ? {
                      resumeThreadId: "fixture-existing-thread",
                      continuationPrompt: "continue the Git fixture worker\n",
                    }
                  : {}),
                artifactContext: {
                  root: workingDirectory,
                  layout,
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
            assert.equal(
              configurationStarts > 0,
              !(kind === "dedup" && resume),
            );
            for (const file of files) await assert.rejects(access(file));
            assert.equal(
              result.threadId,
              resume ? "fixture-existing-thread" : "fixture-thread-id",
            );
            const invocation = await readJson(fixture.markerPath);
            assert.equal(invocation.codexHome, process.env.CODEX_HOME);
            assert.equal(
              path.dirname(path.dirname(invocation.gitEnvironmentFile)),
              await realpath(fixture.root),
            );
            const server = nativeConfigOverrides(invocation.argv)
              .map(
                (value) =>
                  parseToml(value) as {
                    mcp_servers?: {
                      cs_artifacts?: {
                        env_vars: string[];
                        env: Record<string, string>;
                      };
                    };
                  },
              )
              .findLast((value) => value.mcp_servers?.cs_artifacts)
              ?.mcp_servers?.cs_artifacts;
            assert.ok(server);
            const expected = expectedBridge!;
            assert.deepEqual(
              Object.fromEntries(
                Object.keys(expected).map((name) => [
                  name,
                  invocation.runtimeEnvironment[name],
                ]),
              ),
              expected,
            );
            assert.deepEqual(server.env_vars, [
              "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
            ]);
            assertConfigOverrides(invocation.argv, {
              "mcp_servers.codex-security.enabled": false,
            });
            assert.equal(server.env.CODEX_SECURITY_ARTIFACT_LAYOUT, layout);
          },
        );
      }
    }
  } finally {
    if (previousUmask !== undefined) process.umask(previousUmask);
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
    await rm(directory, { recursive: true, force: true });
  }
}
