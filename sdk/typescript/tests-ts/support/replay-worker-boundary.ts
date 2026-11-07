import assert from "node:assert/strict";
import * as childProcess from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, spyOn } from "bun:test";
import { parse } from "smol-toml";
import { fakeCodexSource } from "../../../../plugins/codex-security/mcp-app/tests/support/fake-codex-source.ts";
import { scanRuntimeCodexConfig } from "../../src/api.js";
import { deepMerge, type JsonObject } from "../../src/config.js";
import {
  createExecutionCodex,
  prepareDiscoveryExecution,
  prepareExecutionSource,
  prepareMergeExecution,
  type PreparedExecution,
} from "../../src/execution-preparation.js";
import { executablePathForSpawn } from "../../src/runtime.js";
import { preparedRuntime } from "./api-events.js";
import { fixtureSpawn } from "./codex-process.js";

export async function checkReplayWorkerSettings(
  root: string,
  config: JsonObject,
): Promise<number> {
  const home = join(root, "worker-home");
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(home, "config.toml"), "", { mode: 0o600 });
  const executable = join(root, "codex-replay.exe");
  const fake = join(root, "codex-replay.mjs");
  const environment = {
    CODEX_HOME: home,
    CODEX_CLI_PATH: executable,
    PATH: process.env["PATH"] ?? "",
    FAKE_CODEX_MARKER: join(root, "worker-invocation.json"),
  };
  const permissions = {
    filesystem: { ":root": "read" },
    network: { enabled: false },
  };
  const active = scanRuntimeCodexConfig(config, home, permissions);
  const profile = (active["permissions"] as JsonObject)["codex_security_scan"];
  await writeFile(
    fake,
    fakeCodexSource(
      profile,
      true,
      { account: null, requiresOpenaiAuth: false },
      join(root, "worker-preflight.json"),
    ),
  );
  const source = prepareExecutionSource({
    command: { command: executable },
    configuration: config,
    environment,
    preserveProviderEnvironment: true,
  });
  const session: PreparedExecution = {
    policy: "ordinary",
    source,
    inheritedPermissions: permissions,
    runtime: {
      ...preparedRuntime(home),
      environment,
      preserveCodexHomeConfig: true,
    },
    runtimeHome: home,
    effectiveConfig: config,
    preflightConfig: {},
    sessionConfig: active,
    authentication: source.authentication,
    approvalPolicy: "never",
    python: process.execPath,
    releaseCredentialHome: null,
  };
  const launches: { args: string[]; selected: JsonObject }[] = [];
  const spawn = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), fake, (_child, args) => {
      if (!args.includes("exec")) return;
      const profileIndex = args.indexOf("--profile");
      let selected =
        profileIndex < 0
          ? {}
          : (parse(
              readFileSync(
                join(home, args[profileIndex + 1] + ".config.toml"),
                "utf8",
              ),
            ) as JsonObject);
      for (let index = 0; index < args.length; index++) {
        if (args[index] === "-c" || args[index] === "--config")
          selected = deepMerge(selected, parse(args[++index]!) as JsonObject);
      }
      launches.push({ args, selected });
    }),
  );
  try {
    for (const worker of [
      prepareDiscoveryExecution(session),
      prepareMergeExecution(session, 2),
    ]) {
      const { codex } = await createExecutionCodex(
        { surface: "sdk", command: "scan", mode: "deep" },
        worker,
        {},
      );
      for (const resumed of [false, true]) {
        const thread = resumed
          ? codex.resumeThread!("replayed-thread", {
              workingDirectory: root,
              skipGitRepoCheck: true,
            })
          : codex.startThread({
              workingDirectory: root,
              skipGitRepoCheck: true,
            });
        const { events } = await thread.runStreamed(
          "Synthetic replay settings check.",
          {},
        );
        let completed = false;
        for await (const event of events) {
          if (event.type === "turn.completed") completed = true;
        }
        assert.ok(completed);
        const { args, selected } = launches.at(-1)!;
        for (const key of [
          "analytics",
          "shell_environment_policy",
          "otel",
          "skills",
          "model_catalog_json",
        ])
          expect(selected[key]).toEqual(config[key]);
        expect((selected["agents"] as JsonObject)["reviewer"]).toEqual(
          (config["agents"] as JsonObject)["reviewer"],
        );
        for (const key of ["view_image", "shell_tool"])
          assert.equal((selected["features"] as JsonObject)[key], false);
        assert.equal(selected["approval_policy"], "never");
        expect(
          (selected["permissions"] as JsonObject)[
            "codex_security_deep_scan_worker"
          ],
        ).toEqual(profile);
        assert.equal(args.includes("resume"), resumed);
      }
    }
    assert.equal(launches.length, 4);
    return launches.length;
  } finally {
    spawn.mockRestore();
  }
}
