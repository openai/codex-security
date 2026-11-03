import assert from "node:assert/strict";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import { readJson } from "./support/json.ts";
import { assertConfigOverrides } from "./assertions.ts";

export async function testConcurrentWorkerExecutableAliases({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  parentSandbox,
  bundledCodexSdkEnvironment,
  assertReadOnlyWorkerPolicy,
}: {
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: () => Promise<{
    root: string;
    executablePath: string;
    markerPath: string;
    preflightMarkerPath: string;
  }>;
  parentSandbox: DeepWorkerParentSandbox;
  bundledCodexSdkEnvironment: (
    command: string,
    environment: Record<string, string>,
  ) => Record<string, string>;
  assertReadOnlyWorkerPolicy: (args: readonly string[]) => void;
}) {
  const saved = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "FAKE_CODEX_MARKER",
    "PATH",
  ].map((name) => [name, process.env[name]] as const);
  try {
    const scans = [];
    for (const index of [0, 1]) {
      const fixture = await fakeCodexFixture();
      const bin = path.join(fixture.root, "vendor", "bin");
      const tools = path.join(fixture.root, "vendor", "codex-path");
      const command = path.join(bin, "codex");
      const alias = path.join(fixture.root, "codex-alias");
      const launcherMarker = path.join(fixture.root, "launcher.txt");
      const promptPath = path.join(fixture.root, "prompt.md");
      const configPath = path.join(fixture.root, "config.toml");
      const summary = index === 0 ? "concise" : "none";
      await mkdir(bin, { recursive: true });
      await mkdir(tools);
      const quoted = [
        launcherMarker,
        process.execPath,
        fixture.executablePath,
      ].map((value) => `'${value.replaceAll("'", `'"'"'`)}'`);
      await writeFile(
        command,
        `#!/bin/sh\nprintf '%s' "$0" > ${quoted[0]}\nexec ${quoted[1]} ${quoted[2]} "$@"\n`,
        { mode: 0o755 },
      );
      await writeFile(
        path.join(tools, "rg"),
        `#!/bin/sh\nprintf 'synthetic search ${index}\\n'\n`,
        { mode: 0o755 },
      );
      await symlink(command, alias);
      await writeFile(promptPath, "CAPTURE_SYNTHETIC_RG");
      await writeFile(configPath, `model_reasoning_summary = "${summary}"\n`);
      scans.push({
        fixture,
        tools,
        alias,
        launcherMarker,
        promptPath,
        configPath,
        summary,
        executor: new CodexSdkWorkerExecutor({
          parentSandbox,
        }),
      });
    }
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "resumed-thread"]) {
        await Promise.all(
          scans.map((scan) => {
            Object.assign(
              process.env,
              bundledCodexSdkEnvironment(scan.alias, {
                PATH: "",
                CODEX_CLI_PATH: scan.alias,
                CODEX_HOME: scan.fixture.root,
                CODEX_SECURITY_CONFIG_PATH: scan.configPath,
                FAKE_CODEX_MARKER: scan.fixture.markerPath,
              }),
            );
            return scan.executor.run({
              promptPath: scan.promptPath,
              workingDirectory: scan.fixture.root,
              kind,
              resumeThreadId,
              subagents: 0,
              signal: new AbortController().signal,
            });
          }),
        );
        for (const [index, scan] of scans.entries()) {
          const preflight = await readJson(scan.fixture.preflightMarkerPath);
          const invocation = await readJson(scan.fixture.markerPath);
          assert.equal(await readFile(scan.launcherMarker, "utf8"), scan.alias);
          assert.equal(invocation.bundledTool, `synthetic search ${index}`);
          assert.equal(invocation.runtimeEnvironment.PATH, scan.tools);
          assert.equal(preflight.gitEnvironment.PATH, scan.tools);
          assert.equal(invocation.codexHome, scan.fixture.root);
          assert.equal(preflight.codexHome, scan.fixture.root);
          assert.equal(
            invocation.argv.includes("resume"),
            resumeThreadId !== undefined,
          );
          assertConfigOverrides(invocation.argv, {
            model_reasoning_summary: scan.summary,
          });
          assertReadOnlyWorkerPolicy(invocation.argv);
        }
      }
    }
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
