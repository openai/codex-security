import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson } from "./support/json.ts";
import assert from "node:assert/strict";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  watch,
  writeFile,
} from "node:fs/promises";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { importModule } from "./import-module.ts";
import {
  draftFixture,
  recordCodexSecurityScanDraft,
} from "./scan-draft-recovery-fixture.ts";

const pluginRoot = join(import.meta.dirname, "../../");
const {
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  saveThreatModelDocument,
  scanDraftInputSchema,
} = await importModule({
  stdin: {
    contents:
      'export * from "./artifact-scan-draft.ts"; export { saveThreatModelDocument } from "./threat-model-document.ts";',
    resolveDir: join(pluginRoot, "mcp-app/src"),
  },
});
const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
const coverage = {
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

for (const complete of [true, undefined]) {
  test(`terminal Deep drafts retain an omitted model (${complete})`, async () => {
    const root = await temporaryDirectory("threatmodel-deep-final-");
    try {
      const { context, draft } = draftFixture(root, "deep");
      context.pluginRoot = pluginRoot;
      const target = context.targetContract!.target as Record<string, unknown>;
      target.requiredSnapshotDigest =
        "codex-security-snapshot/v1:sha256:" + "a".repeat(64);
      await recordCodexSecurityScanDraft(context, {
        ...draft({ deferred: [{ reason: "Earlier unfinished review." }] }),
        threatModel,
      });
      assert.ok(
        (await readFile(join(root, "threatmodel.md"), "utf8")).includes(
          `Snapshot: ${target.requiredSnapshotDigest}`,
        ),
      );
      // A final Deep result replaces old review documents without parsing them.
      await writeFile(join(root, "findings.json"), "unfinished findings");
      await writeFile(join(root, "coverage.json"), "unfinished coverage");
      const replacement = {
        format: "markdown",
        content: "# Replacement model\n",
      };
      for (const model of [undefined, replacement]) {
        const terminal = draft({}, true);
        if (complete === undefined) delete terminal.complete;
        if (model !== undefined) terminal.threatModel = model;
        const expectedModel = model ?? threatModel;
        const before = new Set(await readdir(join(root, "checkpoints")));
        await recordCodexSecurityScanDraft(context, terminal);
        const manifest = await readJson(root, "scan-manifest.json");
        assert.deepEqual(manifest.scan.threatModel, expectedModel);
        const checkpoints = await Promise.all(
          (await readdir(join(root, "checkpoints")))
            .filter((name) => !before.has(name))
            .map(async (name) => await readJson(root, "checkpoints", name)),
        );
        assert.ok(checkpoints.length > 0);
        for (const checkpoint of checkpoints) {
          assert.notEqual(checkpoint.complete, false);
          assert.deepEqual(checkpoint.threatModel, expectedModel);
          assert.deepEqual(checkpoint.coverage.deferred, []);
        }
        const savedCoverage = await readJson(root, "coverage.json");
        assert.deepEqual(savedCoverage.deferred, []);
        assert.ok(
          (await readFile(join(root, "threatmodel.md"), "utf8")).startsWith(
            expectedModel.content,
          ),
        );
        assert.deepEqual((await readJson(root, "findings.json")).findings, []);
        assert.equal(terminal.threatModel, model);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const kind of ["working_tree", "commit", "range"]) {
  test(`diff threat model includes its saved ${kind} snapshot`, async () => {
    const root = await temporaryDirectory("threatmodel-diff-");
    try {
      const { context, draft } = draftFixture(root, "diff");
      context.pluginRoot = pluginRoot;
      const target = context.targetContract!.target as Record<string, unknown>;
      const diffTarget = context.targetContract!.diffTarget as Record<
        string,
        unknown
      >;
      delete target.requiredSnapshotDigest;
      diffTarget.kind = kind;
      if (kind === "working_tree")
        diffTarget.contentDigest =
          "codex-security-snapshot/v1:sha256:" + "c".repeat(64);
      await recordCodexSecurityScanDraft(context, { ...draft(), threatModel });
      const manifest = await readJson(root, "scan-manifest.json");
      const digest = manifest.scan.target.snapshotDigest;
      assert.match(
        digest,
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
      );
      const document = await readFile(join(root, "threatmodel.md"), "utf8");
      assert.ok(document.includes(`Snapshot: ${digest}`), document);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

test("terminal Deep model inheritance retries a changed canonical draft", async () => {
  const root = await temporaryDirectory("threatmodel-deep-retry-");
  try {
    const { context, draft } = draftFixture(root, "deep");
    context.pluginRoot = pluginRoot;
    await recordCodexSecurityScanDraft(context, { ...draft(), threatModel });
    const replacement = { format: "markdown", content: "# Concurrent model\n" };
    const digests: (string | undefined)[] = [];
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      draft({}, true),
      async (args: string[]) => {
        const staged = await readJson(args[args.indexOf("--draft-path") + 1]);
        assert.ok(args.includes("--expected-draft-digest"));
        digests.push(args[args.indexOf("--expected-draft-digest") + 1]);
        if (digests.length === 1) {
          assert.deepEqual(staged.manifest.scan.threatModel, threatModel);
          const manifestPath = join(root, "scan-manifest.json");
          const manifest = await readJson(manifestPath);
          manifest.scan.threatModel = replacement;
          await writeFile(manifestPath, JSON.stringify(manifest));
          throw new Error(
            "scan_draft_conflict: canonical scan results changed",
          );
        }
        assert.deepEqual(staged.manifest.scan.threatModel, replacement);
      },
    );
    assert.equal(digests.length, 2);
    assert.notEqual(digests[0], digests[1]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("model-only worker checkpoints save Markdown before findings and retain it on retry", async () => {
  const root = await temporaryDirectory("threatmodel-worker-");
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
    const saved = await readJson(root, "result.json");
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
  const root = await temporaryDirectory("threatmodel-write-failure-");
  try {
    await mkdir(join(root, "threatmodel.md"));
    const result = await recordCodexSecurityWorkerScanDraft(
      { root, repoRoot: root, layout: "worker", scanId, pluginRoot },
      { scanId, complete: false, threatModel, findings: [], coverage },
    );
    assert.match(result.warnings[0], /threatmodel\.md could not be written/);
    assert.deepEqual(
      (await readJson(root, "result.json")).threatModel,
      threatModel,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a renderer failure preserves saved canonical bytes and reports a warning", async () => {
  const root = await temporaryDirectory("threatmodel-render-failure-");
  try {
    const resultPath = join(root, "result.json");
    const canonical = Buffer.from(
      JSON.stringify(
        {
          scanId,
          complete: false,
          threatModel: { summary: "" },
          findings: [],
          coverage,
        },
        null,
        2,
      ) + "\n",
    );
    await writeFile(resultPath, canonical);
    const warning = await saveThreatModelDocument(
      { root, repoRoot: root, layout: "worker", scanId, pluginRoot },
      threatModel,
    );
    assert.equal(
      warning,
      "The threat model was saved, but threatmodel.md could not be written: threatModel.summary: expected a non-empty string",
    );
    assert.deepEqual(await readFile(resultPath), canonical);
    await assert.rejects(readFile(join(root, "threatmodel.md")), {
      code: "ENOENT",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("saved-model rendering does not require the worker's Python interpreter", async () => {
  const root = await temporaryDirectory("threatmodel-python-");
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
    assert.equal(result.warnings, undefined);
    assert.ok(
      (await readFile(join(root, "threatmodel.md"), "utf8")).startsWith(
        markdown,
      ),
    );
    assert.deepEqual(
      (await readJson(root, "result.json")).threatModel,
      threatModel,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("overlapping draft projections retain the latest committed model", async (t) => {
  const root = await temporaryDirectory("threatmodel-concurrent-", true);
  const firstStarted = Promise.withResolvers<string>();
  const releaseFirst = Promise.withResolvers<void>();
  const originalRename = fs.rename;
  let firstProjection = true;
  let activeRenderers = 0;
  let maximumRenderers = 0;
  t.mock.method(
    fs,
    "rename",
    async (...[source, destination]: Parameters<typeof fs.rename>) => {
      if (destination !== join(root, "threatmodel.md"))
        return originalRename(source, destination);
      activeRenderers += 1;
      maximumRenderers = Math.max(maximumRenderers, activeRenderers);
      try {
        if (firstProjection) {
          firstProjection = false;
          firstStarted.resolve(await readFile(source, "utf8"));
          await releaseFirst.promise;
        }
        return await originalRename(source, destination);
      } finally {
        activeRenderers -= 1;
      }
    },
  );
  const context = {
    root,
    repoRoot: root,
    layout: "worker",
    scanId,
    pluginRoot,
    pythonCommand: "fixture-python",
    targetRevision: "example-revision",
    targetContract: { target: { requiredSnapshotDigest: "example-snapshot" } },
  };
  const firstModel = { format: "markdown", content: "# First model\n" };
  const latestModel = { format: "markdown", content: "# Latest model\n" };
  const events = watch(root);
  const latestCommitted = (async () => {
    for await (const event of events) {
      if (event.filename !== "result.json") continue;
      const value = await readJson(root, "result.json");
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
    const firstDocument = await firstStarted.promise;
    assert.ok(firstDocument.includes(`Revision: ${context.targetRevision}`));
    assert.ok(
      firstDocument.includes(
        `Snapshot: ${context.targetContract.target.requiredSnapshotDigest}`,
      ),
    );
    const latest = recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: false,
      threatModel: latestModel,
      findings: [],
      coverage,
    });
    await latestCommitted;
    releaseFirst.resolve();
    const results = await Promise.all([first, latest]);
    assert.deepEqual(
      results.map((result) => result.warnings),
      [undefined, undefined],
    );
    assert.equal(maximumRenderers, 1);
    const latestDocument = await readFile(join(root, "threatmodel.md"), "utf8");
    assert.ok(latestDocument.startsWith(latestModel.content));
    // A caller queued with older input must reread the saved canonical result.
    await saveThreatModelDocument(context, firstModel);
    assert.equal(
      await readFile(join(root, "threatmodel.md"), "utf8"),
      latestDocument,
    );
    assert.deepEqual(
      (await readJson(root, "result.json")).threatModel,
      latestModel,
    );
  } finally {
    releaseFirst.resolve();
    await events.return!();
    t.mock.restoreAll();
    await rm(root, { recursive: true, force: true });
  }
});
