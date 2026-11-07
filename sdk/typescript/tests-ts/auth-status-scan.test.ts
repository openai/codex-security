import { afterEach, expect, test } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { resolveCodexCommand, runCodexCommand } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { copyCredentialTestPlugin } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { chatGptTokens } from "./support/chatgpt-credentials.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each(["CLI", "SDK"] as const)(
  "%s status keeps a later scan authenticated after the ambient login file disappears",
  async (surface) => {
    const root = await temporaryDirectory();
    const ambientHome = join(root, "ambient-home");
    const state = join(root, "state");
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    for (const directory of [ambientHome, repository, scanDir])
      await mkdir(directory, { mode: 0o700 });
    const source = join(ambientHome, "auth.json");
    await writeFile(
      source,
      JSON.stringify({ auth_mode: "chatgpt", tokens: chatGptTokens }),
      { mode: 0o600 },
    );
    const environment = {
      PATH: process.env["PATH"],
      HOME: root,
      USERPROFILE: root,
      CODEX_HOME: ambientHome,
      CODEX_SECURITY_STATE_DIR: state,
    };

    if (surface === "CLI") {
      const stderr = capture();
      expect(
        await main(
          ["login", "status"],
          capture().stream,
          stderr.stream,
          dependencies({
            environment,
            onCodex: async (args, _output, childEnvironment) => {
              const result = await runCodexCommand(
                resolveCodexCommand(childEnvironment!),
                args,
                childEnvironment!,
              );
              return result.exitCode ?? 1;
            },
          }),
        ),
        stderr.text(),
      ).toBe(0);
    } else {
      await using client = TestClient.withDependencies({ environment });
      expect((await client.account()).authenticated).toBe(true);
    }

    await rm(source);
    await using scanner = new TestClient(
      { pluginPath: await copyCredentialTestPlugin(root) },
      {
        environment,
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => {
          expect(options.env?.["CODEX_HOME"]).toBe(join(state, "codex-home"));
          throw new Error("authenticated scan reached execution");
        },
      },
    );
    await expect(scanner.run(repository, { auth: "chatgpt" })).rejects.toThrow(
      "authenticated scan reached execution",
    );
  },
  60_000,
);
