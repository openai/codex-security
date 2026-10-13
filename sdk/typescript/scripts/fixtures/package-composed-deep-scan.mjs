import assert from "node:assert/strict";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [installedRoot, consumer] = process.argv.slice(2);
const sdk = await import(
  pathToFileURL(join(installedRoot, "dist", "index.js")).href
);
const { runWorkbench } = await import(
  pathToFileURL(join(installedRoot, "dist", "runtime.js")).href
);
const pluginRoot = join(installedRoot, "_bundled_plugin");
const pluginManifest = JSON.parse(
  await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
);
const repository = join(consumer, "composed-deep-repository");
const codexHome = join(consumer, "composed-deep-runtime");
const bootstrapWorkspace = join(consumer, "composed-deep-bootstrap");
await mkdir(repository, { mode: 0o700 });
await mkdir(codexHome, { mode: 0o700 });
await mkdir(bootstrapWorkspace, { mode: 0o700 });
await writeFile(join(repository, "README.md"), "# Synthetic repository\n");
const environment = {
  ...Object.fromEntries(
    [
      "PATH",
      "Path",
      "SystemRoot",
      "WINDIR",
      "ComSpec",
      "PATHEXT",
      "TMP",
      "TEMP",
      "TMPDIR",
    ]
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  ),
  HOME: codexHome,
  USERPROFILE: codexHome,
  CODEX_HOME: codexHome,
  CODEX_SECURITY_STATE_DIR: join(consumer, "composed-deep-state"),
  OPENAI_API_KEY: "synthetic-package-composed-deep-key",
};

async function writeCompletedScan(env) {
  const directory = env.CODEX_SECURITY_SCAN_DIR;
  await cp(join(pluginRoot, "examples", "completed-scan"), directory, {
    recursive: true,
  });
  const manifest = JSON.parse(
    await readFile(join(directory, "scan-manifest.json"), "utf8"),
  );
  manifest.scan.id = env.CODEX_SECURITY_SCAN_ID;
  manifest.scan.producer.version = pluginManifest.version;
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  manifest.scan.target = {
    kind: env.CODEX_SECURITY_TARGET_KIND,
    targetId: env.CODEX_SECURITY_TARGET_ID,
    displayName: env.CODEX_SECURITY_TARGET_DISPLAY_NAME,
    snapshotDigest: env.CODEX_SECURITY_TARGET_SNAPSHOT_DIGEST,
  };
  for (const name of ["findings.json", "coverage.json"]) {
    const path = join(directory, name);
    const document = JSON.parse(await readFile(path, "utf8"));
    document.scanId = manifest.scan.id;
    for (const finding of document.findings ?? []) {
      delete finding.findingId;
      delete finding.occurrenceId;
      delete finding.fingerprints;
    }
    await writeFile(path, `${JSON.stringify(document)}\n`);
  }
  await writeFile(
    join(directory, "scan-manifest.json"),
    `${JSON.stringify(manifest)}\n`,
  );
}

const { ScanTransportClosedError } = await import(
  pathToFileURL(join(installedRoot, "dist", "scan-execution.js")).href
);
const records = new Map();
const launches = [];
const controller = new AbortController();
const interruption = new ScanTransportClosedError(
  "Synthetic stop after sealing",
);
let stopAfterSealing = true;
let parentId;
const makeClient = () =>
  new sdk.CodexSecurity(
    { pythonPath: process.env.PYTHON },
    {
      environment,
      prepareRuntime: async () => ({
        codexHome,
        environment,
        credentialsAvailable: true,
        plugin: {
          pluginRoot,
          marketplaceRoot: pluginRoot,
          installedRoot: pluginRoot,
          marketplaceName: "codex-security-sdk",
          name: pluginManifest.name,
          version: pluginManifest.version,
        },
      }),
      runWorkbench: async (options, args, input) => {
        if (
          stopAfterSealing &&
          args[0] === "complete-scan" &&
          args[2] === parentId
        ) {
          stopAfterSealing = false;
          controller.abort(interruption);
          throw interruption;
        }
        const result = await runWorkbench(options, args, input);
        if (args[0] === "register-cli-scan") {
          const registration = JSON.parse(input);
          records.set(result.scanId, {
            mode: registration.recipe.mode,
            options,
          });
          if (registration.recipe.mode === "deep") parentId = result.scanId;
        }
        return result;
      },
      createCodex({ env }) {
        const makeThread = (threadOptions, id = null) => ({
          id,
          async runStreamed(prompt) {
            const scanId = env.CODEX_SECURITY_SCAN_ID;
            const record = records.get(scanId);
            assert.ok(
              record,
              "Every model launch must belong to a registered scan",
            );
            launches.push({
              scanId,
              mode: record.mode,
              cwd: threadOptions.workingDirectory,
            });
            this.id ??= `composed-package-${launches.length}`;
            const threadId = this.id;
            return {
              events: (async function* () {
                yield { type: "thread.started", thread_id: threadId };
                let response = "Synthetic scan completed";
                if (record.mode === "standard") await writeCompletedScan(env);
                else {
                  assert.ok(prompt.startsWith("Compare every finding"));
                  response = JSON.stringify({
                    matches: [],
                    uncertain: [],
                    related: [],
                    request: null,
                  });
                }
                yield {
                  type: "item.completed",
                  item: {
                    id: "response",
                    type: "agent_message",
                    text: response,
                  },
                };
                yield {
                  type: "turn.completed",
                  usage: {
                    input_tokens: 10,
                    cached_input_tokens: 0,
                    output_tokens: 3,
                  },
                };
              })(),
            };
          },
        });
        return {
          startThread: (options) => makeThread(options),
          resumeThread: (id, options) => makeThread(options, id),
        };
      },
    },
  );
const options = {
  signal: controller.signal,
  mode: "deep",
  workers: 1,
  subagents: 0,
  maxDiscoveryRuns: 2,
  outputDir: join(consumer, "composed-deep-output"),
};
const first = makeClient();
try {
  await assert.rejects(
    first.run(repository, options),
    (error) => error === interruption,
  );
} finally {
  await first.close();
}
assert.equal(launches.filter((launch) => launch.mode === "standard").length, 2);
assert.ok(
  launches.some((launch) => launch.mode === "deep"),
  "Installed composition must run its reducer",
);
const beforeResume = launches.length;
const resumed = makeClient();
try {
  const result = await resumed.run(repository, {
    ...options,
    resumeScanId: parentId,
    signal: undefined,
  });
  assert.equal(result.manifest.scan.status, "completed");
  assert.equal(result.coverage.mode, "deep_repository");
  assert.ok(result.findings.findings.length > 0);
  assert.equal(
    launches.length,
    beforeResume,
    "Sealed recovery must not repeat child or reducer work",
  );
  assert.equal(
    result.turnResult.finalResponse,
    await readFile(result.reportPath, "utf8"),
  );
  const parent = records.get(parentId);
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  assert.equal(saved.scan.progress.status, "complete");
  assert.equal(
    launches.filter((launch) => launch.scanId === parentId).length,
    1,
  );
} finally {
  await resumed.close();
}
console.log(
  "Validated installed composed Deep Scan: ordinary children, reducer, sealed recovery, and completed reports.",
);
