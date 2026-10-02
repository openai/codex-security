import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, watch } from "node:fs/promises";
import { EventEmitter } from "node:events";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const bundled = await build({
  stdin: {
    contents:
      'export * from "./artifact-scan-draft.ts"; export { saveThreatModelDocument } from "./threat-model-document.ts";',
    resolveDir: join(pluginRoot, "mcp-app/src"),
  },
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
});
const {
  recordCodexSecurityWorkerScanDraft,
  saveThreatModelDocument,
  scanDraftInputSchema,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
);
const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
const coverage = {
  completeness: "partial",
  surfaces: [],
  explicitExclusions: [],
  deferred: [],
};
const markdown =
  "# Example model\n\n| Boundary | Control |\n| --- | --- |\n| API | Login |\n\n```text\nexact  spacing\n```\n";
const threatModel = {
  format: "markdown",
  content: markdown,
  origin: "provided",
  scope: { includePaths: ["services/api"] },
};

test("model-only worker checkpoints save Markdown before findings and retain it on retry", async () => {
  const root = await mkdtemp(join(tmpdir(), "threatmodel-worker-"));
  try {
    const context = {
      root,
      repoRoot: root,
      layout: "worker",
      scanId,
      pluginRoot,
      scope: ".",
    };
    const checkpoint = {
      scanId,
      complete: false,
      threatModel,
      findings: [],
      coverage,
    };
    assert.deepEqual(
      scanDraftInputSchema.parse(checkpoint).threatModel,
      threatModel,
    );
    for (const content of ["", " \n\t"]) {
      assert.equal(
        scanDraftInputSchema.safeParse({
          ...checkpoint,
          threatModel: { format: "markdown", content },
        }).success,
        false,
      );
    }
    const legacyModel = {
      summary: "Existing structured model.",
      format: "markdown",
      content: " \n",
    };
    assert.deepEqual(
      scanDraftInputSchema.parse({ ...checkpoint, threatModel: legacyModel })
        .threatModel,
      legacyModel,
    );
    const result = await recordCodexSecurityWorkerScanDraft(
      context,
      checkpoint,
    );
    assert.equal(result.warnings, undefined);
    const contents = await readFile(join(root, "threatmodel.md"), "utf8");
    assert.ok(contents.startsWith(markdown));
    assert.match(contents, /Model scope: services\/api/);
    assert.match(contents, /provisional/);
    assert.equal((await readdir(join(root, "checkpoints"))).length, 1);
    await recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: false,
      findings: [],
      coverage,
    });
    const saved = JSON.parse(await readFile(join(root, "result.json"), "utf8"));
    assert.deepEqual(saved.threatModel, threatModel);
    assert.equal(
      await readFile(join(root, "threatmodel.md"), "utf8"),
      contents,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a convenience-document failure preserves the worker result and reports a warning", async () => {
  const root = await mkdtemp(join(tmpdir(), "threatmodel-write-failure-"));
  try {
    await mkdir(join(root, "threatmodel.md"));
    const result = await recordCodexSecurityWorkerScanDraft(
      { root, repoRoot: root, layout: "worker", scanId, pluginRoot },
      { scanId, complete: false, threatModel, findings: [], coverage },
    );
    assert.match(result.warnings[0], /threatmodel\.md could not be written/);
    assert.deepEqual(
      JSON.parse(await readFile(join(root, "result.json"), "utf8")).threatModel,
      threatModel,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the configured worker interpreter is honored without losing the canonical model on failure", async () => {
  const root = await mkdtemp(join(tmpdir(), "threatmodel-python-"));
  try {
    const result = await recordCodexSecurityWorkerScanDraft(
      {
        root,
        repoRoot: root,
        layout: "worker",
        scanId,
        pluginRoot,
        pythonCommand: join(root, "missing-interpreter"),
      },
      { scanId, complete: false, threatModel, findings: [], coverage },
    );
    assert.match(result.warnings[0], /missing-interpreter/);
    assert.deepEqual(
      JSON.parse(await readFile(join(root, "result.json"), "utf8")).threatModel,
      threatModel,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("overlapping draft projections retain the latest committed model", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "threatmodel-concurrent-"));
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const firstStarted = Promise.withResolvers();
  let releaseFirst;
  let activeRenderers = 0;
  let maximumRenderers = 0;
  let renderCount = 0;
  t.mock.method(childProcess, "spawn", (command, args) => {
    assert.equal(command, "fixture-python");
    assert.deepEqual(args, [
      "-I",
      "-X",
      "utf8",
      join(pluginRoot, "scripts", "threat_model_projection.py"),
      "--input-json-stdin",
    ]);
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let contents = "";
    child.stdin = new Writable({
      write(chunk, _encoding, callback) {
        contents += chunk.toString("utf8");
        callback();
      },
      final(callback) {
        const input = JSON.parse(contents);
        activeRenderers += 1;
        maximumRenderers = Math.max(maximumRenderers, activeRenderers);
        const finish = () => {
          child.stdout.end(input.threatModel.content);
          activeRenderers -= 1;
          child.emit("close", 0, null);
        };
        if (renderCount++ === 0) {
          releaseFirst = finish;
          firstStarted.resolve(input);
        } else {
          finish();
        }
        callback();
      },
    });
    return child;
  });
  syncBuiltinESMExports();
  const context = {
    root,
    repoRoot: root,
    layout: "worker",
    scanId,
    pluginRoot,
    pythonCommand: "fixture-python",
    targetRevision: "example-revision",
    targetSnapshotDigest: "example-snapshot",
  };
  const firstModel = { format: "markdown", content: "# First model\n" };
  const latestModel = { format: "markdown", content: "# Latest model\n" };
  const events = watch(root);
  const latestCommitted = (async () => {
    for await (const event of events) {
      if (event.filename !== "result.json") continue;
      const value = JSON.parse(
        await readFile(join(root, "result.json"), "utf8"),
      );
      if (value.threatModel.content === latestModel.content) return;
    }
  })();
  try {
    const first = recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: false,
      threatModel: firstModel,
      findings: [],
      coverage,
    });
    const input = await firstStarted.promise;
    assert.equal(input.provenance.revision, context.targetRevision);
    assert.equal(input.provenance.snapshotDigest, context.targetSnapshotDigest);
    const latest = recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: false,
      threatModel: latestModel,
      findings: [],
      coverage,
    });
    await latestCommitted;
    releaseFirst();
    const results = await Promise.all([first, latest]);
    assert.deepEqual(
      results.map((result) => result.warnings),
      [undefined, undefined],
    );
    assert.equal(maximumRenderers, 1);
    assert.equal(
      await readFile(join(root, "threatmodel.md"), "utf8"),
      latestModel.content,
    );
    // A caller queued with older input must reread the saved canonical result.
    await saveThreatModelDocument(context, firstModel);
    assert.equal(
      await readFile(join(root, "threatmodel.md"), "utf8"),
      latestModel.content,
    );
    assert.deepEqual(
      JSON.parse(await readFile(join(root, "result.json"), "utf8")).threatModel,
      latestModel,
    );
  } finally {
    await events.return();
    t.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
});
