import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { SandboxUnavailableError } from "../src/index.js";
import { probeCodexSandbox } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";

const SANDBOX_DENIAL =
  "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-sandbox-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function syntheticPlugin(root: string): Promise<string> {
  const path = join(root, "plugin");
  await mkdir(join(path, ".codex-plugin"), { recursive: true });
  await writeFile(
    join(path, ".codex-plugin", "plugin.json"),
    JSON.stringify({ name: "codex-security", version: "1.2.3" }),
  );
  return path;
}

async function syntheticCodex(root: string, exitCode: number): Promise<string> {
  const command = join(root, "codex");
  await writeFile(
    command,
    [
      "#!/bin/sh",
      'if [ "$1" != sandbox ]; then exit 0; fi',
      `if [ ${exitCode} -ne 0 ]; then echo "${SANDBOX_DENIAL}" >&2; fi`,
      `exit ${exitCode}`,
      "",
    ].join("\n"),
  );
  await chmod(command, 0o700);
  return command;
}

describe("Codex sandbox probe", () => {
  test.skipIf(process.platform === "win32")(
    "reports what the sandbox said and how to reproduce it",
    async () => {
      const root = await temporaryDirectory();
      const command = await syntheticCodex(root, 1);
      const failure = await probeCodexSandbox({ command }, {}).then(
        () => null,
        (error: Error) => error,
      );
      expect(failure).toBeInstanceOf(SandboxUnavailableError);
      expect(failure?.message).toContain(SANDBOX_DENIAL);
      expect(failure?.message).toContain(`${command} sandbox -- true`);
    },
  );

  test.skipIf(process.platform === "win32")(
    "accepts a sandbox that runs the probe command",
    async () => {
      const root = await temporaryDirectory();
      await expect(
        probeCodexSandbox({ command: await syntheticCodex(root, 0) }, {}),
      ).resolves.toBeUndefined();
    },
  );

  test.skipIf(process.platform !== "win32")(
    "does not probe on Windows",
    async () => {
      const root = await temporaryDirectory();
      await expect(
        probeCodexSandbox({ command: join(root, "missing-codex.exe") }, {}),
      ).resolves.toBeUndefined();
    },
  );

  test.skipIf(process.platform === "win32")(
    "stops a scan before it starts a billed Codex thread",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const state = join(root, "state");
      const scanDir = join(root, "scan");
      await mkdir(repository, { mode: 0o700 });
      await mkdir(state, { mode: 0o700 });
      await mkdir(scanDir, { mode: 0o700 });
      await writeFile(join(repository, "app.py"), "print('synthetic')\n");
      const command = await syntheticCodex(root, 1);
      const client = new TestClient(
        { pluginPath: await syntheticPlugin(root) },
        {
          environment: {
            OPENAI_API_KEY: "synthetic-key",
            CODEX_SECURITY_STATE_DIR: state,
          },
          resolveCodexCommand: () => ({ command }),
          resolvePluginPython: async () => "/managed/python",
          prepareOutputDir: async () => scanDir,
          repositoryRevision: async () => "deadbeef",
        },
      );
      try {
        await expect(client.run(repository)).rejects.toMatchObject({
          name: SandboxUnavailableError.name,
          message: expect.stringContaining(SANDBOX_DENIAL),
        });
      } finally {
        await client.close();
      }
    },
  );
});
