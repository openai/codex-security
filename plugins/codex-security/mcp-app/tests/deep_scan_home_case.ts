import assert from "node:assert/strict";
import { mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { assertConfigOverrides } from "./assertions.ts";
import { readJson } from "./support/json.ts";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";

type Fixture = { root: string; executablePath: string; markerPath: string };

export async function testHome(
  Executor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor,
  capture: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings,
  restore: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings,
  load: typeof import("../src/deep-scan/recovery-settings.js").loadDeepScanExecutionSettings,
  withFixture: (
    action: (
      fixture: Fixture,
      promptPath: string,
      workingDirectory: string,
    ) => Promise<void>,
  ) => Promise<void>,
  sandbox: DeepWorkerParentSandbox,
) {
  return withFixture(async (fixture, promptPath, workingDirectory) => {
    const home = path.join(fixture.root, "selected-home");
    const child = path.join(home, "child");
    const link = path.join(fixture.root, "home-link");
    await mkdir(child, { recursive: true });
    await symlink(child, link, "dir");
    await writeFile(
      path.join(home, "config.toml"),
      'model_reasoning_summary = "none"\n',
    );
    await writeFile(
      path.join(fixture.root, "config.toml"),
      'model_reasoning_summary = "detailed"\n',
    );
    await writeFile(promptPath, "fixture captured home settings\n");

    for (const configuredHome of [
      `${path.relative(process.cwd(), link)}/..`,
      `${link}/..`,
    ]) {
      const captured = await capture({}, sandbox, {
        CODEX_CLI_PATH: fixture.executablePath,
        CODEX_HOME: configuredHome,
      });
      assert.equal(captured.reasoningSummary, "none");
      assert.equal(await realpath(captured.codexHome), await realpath(home));
      for (const saved of [captured, JSON.parse(JSON.stringify(captured))]) {
        const executor = new Executor(
          restore(saved, sandbox, () => ({
            ...process.env,
            CODEX_HOME: fixture.root,
          })),
        );
        for (const kind of ["discovery", "dedup"] as const) {
          for (const resumeThreadId of [undefined, "fixture-home-resume"]) {
            await executor.run({
              promptPath,
              workingDirectory,
              kind,
              resumeThreadId,
              subagents: 0,
              signal: new AbortController().signal,
            });
            const invocation = await readJson(fixture.markerPath);
            assert.equal(
              await realpath(invocation.codexHome),
              await realpath(home),
            );
            assertConfigOverrides(invocation.argv, {
              model_reasoning_summary: "none",
            });
            assert.equal(
              invocation.argv.includes("resume"),
              resumeThreadId !== undefined,
            );
          }
        }
      }
    }

    await writeFile(path.join(home, "config.toml"), "");
    const sessions = path.join(home, "sessions");
    await mkdir(sessions);
    const owner = {
      threadId: "fixture-history-owner",
      turnId: "history-turn",
      startedAt: "2026-01-01T00:01:00Z",
    };
    await writeFile(
      path.join(sessions, "history.jsonl"),
      [
        {
          type: "session_meta",
          timestamp: "2026-01-01T00:00:00Z",
          payload: {
            id: owner.threadId,
            cli_version: "0.162.0",
            model_provider: "openai",
          },
        },
        {
          type: "event_msg",
          timestamp: "2026-01-01T00:00:01Z",
          payload: {
            type: "thread_settings_applied",
            thread_id: owner.threadId,
            thread_settings: {
              model: "fixture-history-model",
              model_provider_id: "openai",
              reasoning_effort: "high",
              reasoning_summary: "concise",
              service_tier: "flex",
            },
          },
        },
      ]
        .map((value) => JSON.stringify(value))
        .join("\n") + "\n",
    );
    const captured = await capture({ usageOwner: owner }, sandbox, {
      CODEX_CLI_PATH: fixture.executablePath,
      CODEX_HOME: `${link}/..`,
    });
    const history = {
      model: "fixture-history-model",
      modelProvider: "openai",
      reasoningEffort: "high",
      reasoningSummary: "concise",
      serviceTier: "flex",
    };
    for (const [key, value] of Object.entries(history))
      assert.equal(captured[key as keyof typeof captured], value);
    const snapshot = JSON.parse(
      JSON.stringify({
        version: 1,
        settings: {
          codexPath: captured.codexPath,
          codexHome: captured.codexHome,
          parentSandbox: sandbox,
        },
      }),
    );
    const recovered = await load(fixture.root, {
      usageOwner: owner,
      createdAt: owner.startedAt,
      executionSettings: snapshot,
    });
    for (const saved of [captured, recovered]) {
      const executor = new Executor(
        restore(saved, sandbox, () => ({
          ...process.env,
          CODEX_HOME: fixture.root,
        })),
      );
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-history-resume"]) {
          await executor.run({
            promptPath,
            workingDirectory,
            kind,
            resumeThreadId,
            subagents: 0,
            signal: new AbortController().signal,
          });
          const invocation = await readJson(fixture.markerPath);
          assert.equal(
            await realpath(invocation.codexHome),
            await realpath(home),
          );
          assertConfigOverrides(invocation.argv, {
            model: history.model,
            model_provider: history.modelProvider,
            model_reasoning_effort: history.reasoningEffort,
            model_reasoning_summary: history.reasoningSummary,
            service_tier: history.serviceTier,
          });
          assert.equal(
            invocation.argv.includes("resume"),
            resumeThreadId !== undefined,
          );
        }
      }
    }
  });
}
