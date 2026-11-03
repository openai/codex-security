import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, toNamespacedPath } from "node:path";
import { fileURLToPath } from "node:url";
import { syncBuiltinESMExports } from "node:module";
import { parse, stringify } from "smol-toml";
import type { JsonObject } from "../../src/config.js";
import { fakeCodexSource } from "../../../../plugins/codex-security/mcp-app/tests/support/fake-codex-source.ts";
const { importModule } = await import(
  new URL(
    "../../../../plugins/codex-security/mcp-app/tests/import-module.ts",
    import.meta.url,
  ).href
);

const executorSource = new URL(
  "../../../../plugins/codex-security/mcp-app/src/deep-scan/executor.ts",
  import.meta.url,
);
const { CodexSdkWorkerExecutor } = await importModule({
  entryPoints: [fileURLToPath(executorSource)],
  define: { "import.meta.url": JSON.stringify(executorSource.href) },
});
const { deepMerge } = await importModule({
  entryPoints: [fileURLToPath(new URL("../../src/config.ts", import.meta.url))],
});
const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
await assertWorkerReplay(
  process.argv[2]!,
  JSON.parse(Buffer.concat(chunks).toString()),
);
process.stdout.write(JSON.stringify({ launches: 4 }));

async function assertWorkerReplay(
  root: string,
  config: JsonObject,
): Promise<void> {
  const home = join(root, "worker-home");
  await mkdir(home);
  await writeFile(join(home, "config.toml"), "");
  const workerConfig = join(root, "worker-runtime.toml");
  await writeFile(workerConfig, stringify({ worker_runtime: config }));
  const marker = join(root, "worker-invocation.json");
  const fake = join(root, "worker-codex.mjs");
  const profile = {
    extends: ":read-only",
    filesystem: { ":root": "read" },
    network: { enabled: false },
  };
  await writeFile(
    fake,
    fakeCodexSource(
      profile,
      true,
      { account: null, requiresOpenaiAuth: false },
      join(root, "worker-preflight.json"),
    ),
  );
  const prompt = join(root, "worker-prompt.md");
  await writeFile(prompt, "Synthetic replay settings check.");
  const node = process.execPath;
  const environment = {
    CODEX_CLI_PATH: node,
    CODEX_HOME: home,
    CODEX_SECURITY_CONFIG_PATH: join(home, "config.toml"),
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfig,
    CODEX_SECURITY_SCAN_DIR: join(root, "scan"),
    FAKE_CODEX_MARKER: marker,
    OPENAI_API_KEY: undefined,
    CODEX_API_KEY: undefined,
  };
  const previous = Object.fromEntries(
    Object.keys(environment).map((name) => [name, process.env[name]]),
  );
  const spawn = childProcess.spawn;
  try {
    for (const [key, value] of Object.entries(environment)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: SpawnOptions,
    ) =>
      spawn(
        command,
        command === node || command === toNamespacedPath(node)
          ? [fake, ...args]
          : args,
        options,
      )) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    const executor = new CodexSdkWorkerExecutor({
      parentSandbox: { filesystemDenies: [] },
    });
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "replayed-thread"]) {
        const result = await executor.run({
          kind,
          promptPath: prompt,
          workingDirectory: root,
          subagents: 0,
          resumeThreadId,
          signal: new AbortController().signal,
        });
        assert.equal(result.threadId, resumeThreadId ?? "fixture-thread-id");
        const { argv } = JSON.parse(await readFile(marker, "utf8")) as {
          argv: string[];
        };
        let selected: JsonObject = {};
        for (let index = 0; index < argv.length; index++)
          if (argv[index] === "-c" || argv[index] === "--config")
            selected = deepMerge(selected, parse(argv[++index]!) as JsonObject);
        for (const key of [
          "analytics",
          "shell_environment_policy",
          "otel",
          "skills",
          "model_catalog_json",
        ])
          assert.deepEqual(selected[key], config[key]);
        assert.deepEqual(
          (selected["agents"] as JsonObject)["reviewer"],
          (config["agents"] as JsonObject)["reviewer"],
        );
        assert.equal((selected["features"] as JsonObject)["view_image"], false);
        assert.equal((selected["features"] as JsonObject)["shell_tool"], false);
        assert.equal(selected["approval_policy"], "never");
        assert.deepEqual(
          (selected["permissions"] as JsonObject)[
            "codex_security_deep_scan_worker"
          ],
          profile,
        );
        assert.equal(argv.includes("resume"), resumeThreadId !== undefined);
        // Existing coordinators retain their launch snapshot when a source file changes.
        await writeFile(
          workerConfig,
          "[worker_runtime.analytics]\nenabled=true\n",
        );
      }
    }
  } finally {
    childProcess.spawn = spawn;
    syncBuiltinESMExports();
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}
