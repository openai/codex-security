import assert from "node:assert/strict";
import { cp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { pathToFileURL } from "node:url";

const [installedRoot, consumer] = process.argv.slice(2);
const sdk = await import(
  pathToFileURL(join(installedRoot, "dist", "index.js")).href
);
const { runWorkbench } = await import(
  pathToFileURL(join(installedRoot, "dist", "runtime.js")).href
);
const { main } = await import(
  pathToFileURL(join(installedRoot, "dist", "cli.js")).href
);
const pluginRoot = join(installedRoot, "_bundled_plugin");
const pluginManifest = JSON.parse(
  await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
);
const repository = join(consumer, "behavior-repository");
const codexHome = join(consumer, "behavior-runtime");
await mkdir(repository, { mode: 0o700 });
await mkdir(codexHome, { mode: 0o700 });
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
  CODEX_SECURITY_STATE_DIR: join(consumer, "behavior-state"),
  OPENAI_API_KEY: "synthetic-package-behavior-key",
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

const turns = [];
const finished = new Set();
// Replace model output and runtime installation only. The installed SDK still
// prepares output, registers scans, validates artifacts, and updates real SQLite.
const client = new sdk.CodexSecurity(
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
    createCodex({ env }) {
      const index = turns.push(env) - 1;
      return {
        startThread() {
          return {
            id: null,
            async runStreamed(_prompt, { signal }) {
              return {
                events: (async function* () {
                  try {
                    yield {
                      type: "thread.started",
                      thread_id: `fixture-${index}`,
                    };
                    if (index === 0) {
                      await writeCompletedScan(env);
                      yield {
                        type: "turn.completed",
                        usage: {
                          input_tokens: 10,
                          cached_input_tokens: 0,
                          output_tokens: 3,
                        },
                      };
                    } else {
                      if (!signal.aborted) {
                        await new Promise((resolve) =>
                          signal.addEventListener("abort", resolve, {
                            once: true,
                          }),
                        );
                      }
                      signal.throwIfAborted();
                    }
                  } finally {
                    finished.add(index);
                  }
                })(),
              };
            },
          };
        },
      };
    },
  },
);

async function savedScan(index) {
  const env = turns[index];
  return (
    await runWorkbench({ python: env.PYTHON, pluginRoot, environment: env }, [
      "get-scan",
      "--scan-id",
      env.CODEX_SECURITY_SCAN_ID,
    ])
  ).scan;
}

let completed;
try {
  completed = await client.run(repository, {
    outputDir: join(consumer, "behavior-complete"),
  });
  assert.equal(completed.manifest.scan.status, "completed");
  assert.equal(completed.threadId, "fixture-0");
  assert.equal(completed.findings.findings.length, 1);
  assert.equal((await savedScan(0)).progress.status, "complete");
  assert.equal(finished.has(0), true);

  const controller = new AbortController();
  await assert.rejects(
    client.run(repository, {
      outputDir: join(consumer, "behavior-cancel"),
      signal: controller.signal,
      onScanStarted: () => controller.abort(),
    }),
    sdk.ScanInterruptedError,
  );
  assert.equal((await savedScan(1)).progress.status, "failed");
  assert.equal(finished.has(1), true);

  let closing;
  await assert.rejects(
    client.run(repository, {
      outputDir: join(consumer, "behavior-close"),
      onScanStarted: () => {
        closing = client.close();
      },
    }),
    /CodexSecurity is closed/u,
  );
  assert.ok(closing);
  await closing;
  assert.equal((await savedScan(2)).progress.status, "failed");
  assert.equal(finished.has(2), true);
  assert.equal(turns.length, 3);
  await assert.rejects(client.run(repository), /CodexSecurity is closed/u);
  await assert.rejects(stat(codexHome), { code: "ENOENT" });
  assert.equal(
    (await stat(join(completed.scanDir, "report.md"))).isFile(),
    true,
  );
} finally {
  await client.close();
}

function capture() {
  let text = "";
  return {
    stream: new Writable({
      write(chunk, _encoding, callback) {
        text += chunk.toString();
        callback();
      },
    }),
    text: () => text,
  };
}

const output = capture();
const errors = capture();
const signalCounts = ["SIGINT", "SIGTERM"].map((signal) =>
  process.listenerCount(signal),
);
const created = [
  {
    issueIdentifier: "\u001b[31mSEC-400\u001b[0m\n\u009fsafe",
    url: "javascript:alert(1)",
  },
  {
    issueIdentifier: "SEC-401",
    url: "https://linear.app/example/issue/SEC-401",
  },
  {
    issueIdentifier: "SEC-402",
    url: "https://user:synthetic-password@linear.app/example/issue/SEC-402",
  },
  {
    issueIdentifier: "SEC-403",
    url: "https://linear.app/example/issue/SEC-403?token=synthetic-token",
  },
].map((issue, index) => ({
  findingId: `finding-${index}`,
  occurrenceId: `occurrence-${index}`,
  ...issue,
}));
assert.equal(
  await main(
    [
      "publish",
      "scan",
      completed.scanDir,
      "--to",
      "linear",
      "--linear-team",
      "example-team",
    ],
    output.stream,
    errors.stream,
    {
      environment: {},
      currentDirectory: () => consumer,
      addSignalListener: (signal, listener) => process.on(signal, listener),
      removeSignalListener: (signal, listener) => process.off(signal, listener),
      // The publisher is controlled; this contract never creates external issues.
      publishScan: async () => ({
        scanId: completed.manifest.scan.id,
        uploadId: completed.manifest.scan.id,
        destination: { type: "linear", teamId: "example-team" },
        created,
        failed: [],
        counts: {
          findings: created.length,
          created: created.length,
          failed: 0,
        },
      }),
    },
  ),
  0,
  errors.text(),
);
assert.equal(errors.text(), "");
assert.match(output.text(), /\n {2}SEC-400 safe\n/u);
assert.ok(output.text().includes("https://linear.app/example/issue/SEC-401"));
assert.doesNotMatch(
  output.text(),
  /[\u001b\u009f]|javascript:|synthetic-password|synthetic-token/u,
);
assert.deepEqual(
  ["SIGINT", "SIGTERM"].map((signal) => process.listenerCount(signal)),
  signalCounts,
);
console.log("Native Node package lifecycle and terminal contracts passed.");
