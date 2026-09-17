import assert from "node:assert/strict";
import { cp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [installedRoot, consumer, selectedPlugin] = process.argv.slice(2);
const { CodexSecurity } = await import(
  pathToFileURL(join(installedRoot, "dist", "index.js")).href
);
const { runWorkbench } = await import(
  pathToFileURL(join(installedRoot, "dist", "runtime.js")).href
);
const repository = join(consumer, "compatibility-repository");
const home = join(consumer, "compatibility-home");
await mkdir(repository, { mode: 0o700 });
await mkdir(home, { mode: 0o700 });
await writeFile(join(repository, "example.py"), "print('synthetic fixture')\n");
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
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  ),
  HOME: home,
  USERPROFILE: home,
  CODEX_HOME: home,
  CODEX_SECURITY_STATE_DIR: join(consumer, "compatibility-state"),
  OPENAI_API_KEY: "synthetic-compatibility-key",
};
const postScanPrompt = "Summarize the completed synthetic scan.";
const turns = [];
let scanEnvironment;
// Only model execution is replaced. Plugin selection, bootstrap, admission,
// finalization, report generation and workbench completion use the installed SDK.
const client = new CodexSecurity(
  { pythonPath: process.env.PYTHON, pluginPath: selectedPlugin },
  {
    environment,
    createCodex({ env }) {
      scanEnvironment = env;
      return {
        startThread() {
          return {
            id: "compatibility-thread",
            async runStreamed(prompt) {
              turns.push(prompt);
              return {
                events: (async function* () {
                  if (turns.length === 1) {
                    const plugin = env.CODEX_SECURITY_PLUGIN_ROOT;
                    const scanDir = env.CODEX_SECURITY_SCAN_DIR;
                    await cp(
                      join(plugin, "examples", "completed-scan"),
                      scanDir,
                      { recursive: true },
                    );
                    const manifestPath = join(scanDir, "scan-manifest.json");
                    const manifest = JSON.parse(
                      await readFile(manifestPath, "utf8"),
                    );
                    const metadata = JSON.parse(
                      await readFile(
                        join(plugin, ".codex-plugin", "plugin.json"),
                        "utf8",
                      ),
                    );
                    manifest.scan.id = env.CODEX_SECURITY_SCAN_ID;
                    manifest.scan.producer.version = metadata.version;
                    delete manifest.scan.sealedAt;
                    delete manifest.scan.artifacts;
                    manifest.scan.scope.context = " ";
                    manifest.scan.threatModel = {
                      summary: "Archive input",
                      assumptions: [" "],
                    };
                    manifest.scan.target = {
                      kind: env.CODEX_SECURITY_TARGET_KIND,
                      targetId: env.CODEX_SECURITY_TARGET_ID,
                      displayName: env.CODEX_SECURITY_TARGET_DISPLAY_NAME,
                      snapshotDigest: env.CODEX_SECURITY_TARGET_SNAPSHOT_DIGEST,
                    };
                    for (const name of ["findings.json", "coverage.json"]) {
                      const file = join(scanDir, name);
                      const document = JSON.parse(await readFile(file, "utf8"));
                      document.scanId = manifest.scan.id;
                      for (const finding of document.findings ?? []) {
                        delete finding.findingId;
                        delete finding.occurrenceId;
                        delete finding.fingerprints;
                        finding.locations[0].path = "src/./extract.py";
                        finding.locations[0].role = " ";
                      }
                      if (name === "coverage.json") {
                        document.openQuestions = [
                          "What deployment controls apply?",
                        ];
                        document.surfaces = ["HTTP API", "ArchiveSurface"].map(
                          (id) => ({
                            ...document.surfaces[0],
                            id,
                            notes: " ",
                            riskArea: " ",
                          }),
                        );
                        delete document.surfaces[1].receiptRefs;
                        document.surfaces.push({
                          label: "Unidentified surface",
                          disposition: "reported",
                        });
                        document.completeness = "partial";
                        document.deferred = [
                          { reason: "Deployment review remains." },
                        ];
                      }
                      await writeFile(file, JSON.stringify(document));
                    }
                    await writeFile(manifestPath, JSON.stringify(manifest));
                  } else {
                    assert.equal(prompt, postScanPrompt);
                    const manifest = JSON.parse(
                      await readFile(
                        join(env.CODEX_SECURITY_SCAN_DIR, "scan-manifest.json"),
                        "utf8",
                      ),
                    );
                    assert.equal(manifest.scan.status, "completed");
                    assert.ok(manifest.scan.sealedAt);
                    assert.ok(
                      (
                        await stat(
                          join(env.CODEX_SECURITY_SCAN_DIR, "report.md"),
                        )
                      ).isFile(),
                    );
                  }
                  yield {
                    type: "thread.started",
                    thread_id: "compatibility-thread",
                  };
                  yield { type: "turn.completed", usage: null };
                })(),
              };
            },
          };
        },
      };
    },
  },
);
try {
  const result = await client.run(repository, {
    outputDir: join(consumer, "compatibility-output"),
    postScanPrompt,
  });
  assert.equal(result.manifest.scan.status, "completed");
  assert.ok(result.manifest.scan.sealedAt);
  assert.deepEqual(
    result.coverage.surfaces.map((surface) => surface.id),
    ["HTTP API", "ArchiveSurface"],
  );
  assert.equal(turns.length, 2);
  assert.equal(result.findings.findings.length, 1);
  assert.equal(
    result.findings.findings[0].locations[0].path,
    "src/./extract.py",
  );
  assert.equal(result.findings.findings[0].locations[0].role, " ");
  assert.equal(result.coverage.surfaces[0].notes, " ");
  assert.equal(result.coverage.surfaces[0].riskArea, " ");
  assert.equal(result.coverage.completeness, "partial");
  assert.equal(result.coverage.surfaces[1].disposition, "needs_follow_up");
  assert.deepEqual(result.coverage.surfaces[1].receiptRefs, []);
  assert.deepEqual(result.coverage.deferred, []);
  assert.ok(
    result.coverage.openQuestions.length > 0 &&
      result.coverage.openQuestions.every(
        (entry) => entry.question === "What deployment controls apply?",
      ),
  );
  assert.equal(result.manifest.scan.scope.context, " ");
  assert.deepEqual(result.manifest.scan.threatModel.assumptions, [" "]);
  const saved = await runWorkbench(
    {
      python: scanEnvironment.PYTHON,
      pluginRoot: scanEnvironment.CODEX_SECURITY_PLUGIN_ROOT,
      environment: scanEnvironment,
    },
    ["get-scan", "--scan-id", result.manifest.scan.id],
  );
  assert.equal(saved.scan.progress.status, "complete");
  assert.equal(process.exitCode ?? 0, 0);
  console.log(
    JSON.stringify({
      selectedPlugin,
      installedPlugin: scanEnvironment.CODEX_SECURITY_PLUGIN_ROOT,
      scanId: result.manifest.scan.id,
      scanDir: result.scanDir,
      turns: turns.length,
      status: saved.scan.progress.status,
      coverageIds: result.coverage.surfaces.map((surface) => surface.id),
    }),
  );
} finally {
  await client.close();
}
