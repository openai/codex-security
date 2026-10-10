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
  });
}
