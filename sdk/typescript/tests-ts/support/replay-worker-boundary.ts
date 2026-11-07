import assert from "node:assert/strict";
import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
import { createProviderProfile } from "../../src/provider-profile.js";
import { preparedRuntime } from "./api-events.js";
import { fixtureSpawn } from "./codex-process.js";

export async function checkReplayWorkerSettings(
  root: string,
  config: JsonObject,
): Promise<void> {
  const home = join(root, "worker-home");
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(home, "config.toml"), "", { mode: 0o600 });
  const executable = join(root, "codex-replay.exe");
  const fake = join(root, "codex-replay.mjs");
  const environment = {
    CODEX_HOME: home,
    CODEX_CLI_PATH: executable,
    PATH: process.env["PATH"] ?? "",
    SYNTHETIC_GATEWAY_KEY: "synthetic-worker-provider-key",
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
      "codex_security_scan",
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
      providerProfile: await createProviderProfile(home, config),
    },
    runtimeHome: home,
    runtimeConfig: scanRuntimeCodexConfig({}, home),
    effectiveConfig: config,
    preflightConfig: {},
    sessionConfig: active,
    authentication: source.authentication,
    approvalPolicy: "never",
    python: process.execPath,
    releaseCredentialHome: null,
  };
  const spawn = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), fake, () => {}),
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
          "CAPTURE_SYNTHETIC_CODEX_CONFIG",
          {},
        );
        let completed = false;
        for await (const event of events) {
          if (event.type === "turn.completed") completed = true;
        }
        assert.ok(completed);
        const marker = JSON.parse(
          await readFile(environment.FAKE_CODEX_MARKER, "utf8"),
        );
        const args = marker.argv as string[];
        let selected: JsonObject = {};
        for (let index = 0; index < args.length; index++) {
          if (args[index] === "-c" || args[index] === "--config")
            selected = deepMerge(selected, parse(args[++index]!) as JsonObject);
        }
        assert.equal(selected["model_provider"], config["model_provider"]);
        expect(
          (parse(marker.profileContents) as JsonObject)["model_providers"],
        ).toEqual(config["model_providers"]);
        assert.equal(marker.providerKey, environment.SYNTHETIC_GATEWAY_KEY);
        assert.equal(selected["model_providers"], undefined);
        const shared = parse(marker.codexConfig);
        assert.equal(shared["model_provider"], undefined);
        assert.equal(shared["model_providers"], undefined);
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
        const effective = deepMerge(
          parse(marker.profileContents) as JsonObject,
          selected,
        );
        expect((effective["features"] as JsonObject)["code_mode"]).toEqual(
          (config["features"] as JsonObject)["code_mode"],
        );
        const servers = effective["mcp_servers"] as JsonObject;
        expect(servers["codex_security"]).toEqual(
          (config["mcp_servers"] as JsonObject)["codex_security"],
        );
        expect(servers["codex-security"]).toEqual({
          command: "node",
          enabled: false,
        });
        assert.equal(selected["approval_policy"], "never");
        expect(
          (selected["permissions"] as JsonObject)["codex_security_scan"],
        ).toEqual(profile);
        assert.equal(args.includes("resume"), resumed);
      }
    }
  } finally {
    spawn.mockRestore();
  }
}
