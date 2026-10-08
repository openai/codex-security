import { readJson } from "./support/json.ts";
import { workerDraft, finding as draftFinding } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type { ArtifactContext } from "../src/artifact-io.js";
import type {
  DeepReducerPageInput,
  DeepReducerPage,
} from "../src/artifact-deep-reducer-pages.js";
import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { importModule } from "./import-module.ts";

type SourceFinding = { id: string; finding: unknown };

const {
  deepReducerInputsInputSchema,
  deepReducerPageResponse,
  getCodexSecurityDeepReducerInputs,
  getCodexSecurityDeepReducerInputsPage,
  recordCodexSecurityDeepReduction,
} = await importModule({
  stdin: {
    contents: `
      export * from "./artifact-deep-reducer-pages.ts";
      export * from "./artifact-deep-reducer.ts";
    `,
    resolveDir: new URL("../src/", import.meta.url).pathname,
  },
});

for (const maxBytes of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  assert.equal(
    deepReducerInputsInputSchema.safeParse({ maxBytes }).success,
    false,
  );
}
assert.equal(
  deepReducerInputsInputSchema.safeParse({ maxBytes: Number.MAX_SAFE_INTEGER })
    .success,
  true,
);
assert.equal(
  deepReducerInputsInputSchema.safeParse({ maxBytes: 256, cursor: "-1" })
    .success,
  false,
);

const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const root = await temporaryDirectory("reducer-pages-", true);
try {
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "workers",
    "one",
    "output",
  );
  const previousRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "dedup",
    "previous",
    "output",
  );
  const outputRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "dedup",
    "current",
    "output",
  );
  for (const directory of [workerRoot, previousRoot, outputRoot]) {
    await mkdir(directory, { recursive: true });
  }
  const largeText =
    'Quoted "text" with \\ newline\n and Unicode 😀é\u0000'.repeat(2048);
  const fresh = finding("fresh", {
    summary: largeText,
    provenance: {
      source: "local_plugin",
      previousFindings: [{ summary: "retained worker history" }],
      originalCandidates: [{ summary: "retained candidate details" }],
    },
  });
  const original = finding("old", { summary: "original evidence" });
  const canonical = finding("old", {
    summary: "current synthesized evidence",
    provenance: {
      source: "local_plugin",
      sourceFindingIds: ["original-worker:0"],
      sourceFindings: [{ id: "original-worker:0", finding: original }],
      previousFindings: [{ summary: largeText }],
    },
  });
  const legacyOriginal = finding("legacy-source", {
    summary: "legacy original differs from current aggregate zero",
  });
  const legacyCanonical = finding("legacy-source", {
    provenance: {
      source: "local_plugin",
      sourceFindings: [{ id: "previous:0", finding: legacyOriginal }],
    },
  });
  const noRefs = finding("legacy-without-refs");
  const worker = {
    scanId,
    findings: [fresh],
    scope: { summary: largeText },
    coverage: workerDraft([]).coverage,
  };
  const previous = {
    scanId,
    findings: [canonical, legacyCanonical, noRefs],
    threatModel: { summary: largeText },
  };
  const workerPath = path.join(workerRoot, "result.json");
  const previousPath = path.join(previousRoot, "result.json");
  await writeFile(workerPath, JSON.stringify(worker));
  await writeFile(previousPath, JSON.stringify(previous));
  const context = {
    root: outputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer" as const,
    deepReducer: {
      scanRoot,
      claimedWorkers: [{ id: "worker-one", resultPath: workerPath }],
      previousReducerResultPath: previousPath,
    },
  };

  const full = await getCodexSecurityDeepReducerInputs(context);
  const projected = await readDocument(context);
  assert.equal(projected.discoveries[0].result.findings[0].summary, largeText);
  assert.deepEqual(projected.discoveries[0].result.scope, worker.scope);
  assert.deepEqual(projected.previous.threatModel, previous.threatModel);
  assert.deepEqual(
    projected.previous.findings.map(
      (entry: { provenance: { sourceFindingIds: string[] } }) =>
        entry.provenance.sourceFindingIds,
    ),
    [["original-worker:0"], ["previous:0"], ["previous:2"]],
  );
  for (const entry of [
    ...projected.discoveries[0].result.findings,
    ...projected.previous.findings,
  ]) {
    for (const field of [
      "sourceFindings",
      "previousFindings",
      "originalCandidates",
    ])
      assert.equal(field in entry.provenance, false);
  }
  assert.deepEqual(
    await readDocument(context, { findingRef: "source:worker-one:0" }),
    full.discoveries[0].result.findings[0],
  );
  assert.deepEqual(
    await readDocument(context, { findingRef: "source:original-worker:0" }),
    original,
  );
  assert.deepEqual(
    await readDocument(context, { findingRef: "previous:0" }),
    canonical,
  );
  assert.deepEqual(
    await readDocument(context, { findingRef: "source:previous:0" }),
    legacyOriginal,
  );
  assert.deepEqual(
    await readDocument(context, { findingRef: "source:previous:2" }),
    noRefs,
  );

  // Changing files cannot change the already-bound page stream or its references.
  await writeFile(workerPath, "unreadable replacement");
  assert.deepEqual(await readDocument(context), projected);
  assert.deepEqual(
    await readDocument(context, { findingRef: "source:worker-one:0" }),
    full.discoveries[0].result.findings[0],
  );
  const recoveredContext = { ...context };
  await assert.rejects(
    getCodexSecurityDeepReducerInputsPage(recoveredContext, { maxBytes: 4096 }),
  );
  await writeFile(workerPath, JSON.stringify(worker));
  assert.deepEqual(
    await readDocument(recoveredContext),
    projected,
    "a failed input read must not poison later retries",
  );

  const firstPage = await getCodexSecurityDeepReducerInputsPage(context, {
    maxBytes: 4096,
  });
  const smaller = await getCodexSecurityDeepReducerInputsPage(context, {
    maxBytes: 1024,
  });
  assert.ok(smaller.json.length < firstPage.json.length);
  assert.ok(firstPage.json.startsWith(smaller.json));
  assert.deepEqual(await readDocument(context, { maxBytes: 1024 }), projected);
  await assert.rejects(
    getCodexSecurityDeepReducerInputsPage(context, { maxBytes: 1 }),
    /Increase maxBytes and retry the same cursor/,
  );
  await assert.rejects(
    getCodexSecurityDeepReducerInputsPage(context, {
      maxBytes: 4096,
      cursor: String(Number.MAX_SAFE_INTEGER),
    }),
    /cursor is outside/,
  );
  await assert.rejects(
    getCodexSecurityDeepReducerInputsPage(context, {
      maxBytes: 4096,
      findingRef: "source:unassigned:0",
    }),
    /not assigned/,
  );

  // Submitting only the projection still preserves complete originals and history.
  await recordCodexSecurityDeepReduction(context, {
    scanId,
    findings: [
      ...projected.discoveries[0].result.findings,
      ...projected.previous.findings,
    ],
    scope: projected.discoveries[0].result.scope,
    threatModel: projected.previous.threatModel,
  });
  const saved = await readJson(outputRoot, "result.json");
  const allSources: SourceFinding[] = saved.findings.flatMap(
    (entry: { provenance: { sourceFindings: SourceFinding[] } }) =>
      entry.provenance.sourceFindings,
  );
  assert.deepEqual(allSources.map((source) => source.id).sort(), [
    "original-worker:0",
    "previous:0",
    "previous:2",
    "worker-one:0",
  ]);
  assert.deepEqual(
    allSources.find((source) => source.id === "worker-one:0")!.finding,
    fresh,
  );
  assert.deepEqual(
    allSources.find((source) => source.id === "original-worker:0")!.finding,
    original,
  );
  assert.deepEqual(
    saved.findings.find(
      (entry: { identity: { anchor: string } }) =>
        entry.identity.anchor === "old",
    ).provenance.previousFindings,
    canonical.provenance.previousFindings,
  );
  console.log("deep reducer paging tests passed");
} finally {
  await rm(root, { recursive: true, force: true });
}

async function readDocument(
  context: ArtifactContext,
  options: Partial<DeepReducerPageInput> = {},
) {
  const maxBytes = options.maxBytes ?? 4096;
  let cursor: string | undefined;
  const fragments = [];
  do {
    const page: DeepReducerPage = await getCodexSecurityDeepReducerInputsPage(
      context,
      {
        ...options,
        maxBytes,
        ...(cursor === undefined ? {} : { cursor }),
      },
    );
    const response = deepReducerPageResponse(page);
    assert.deepEqual(Object.keys(response), ["content"]);
    assert.ok(Buffer.byteLength(JSON.stringify(response), "utf8") <= maxBytes);
    assert.deepEqual(JSON.parse(response.content[0].text), page);
    assert.equal(page.json.isWellFormed(), true);
    if (page.nextCursor !== undefined)
      assert.ok(Number(page.nextCursor) > Number(cursor ?? "0"));
    fragments.push(page.json);
    cursor = page.nextCursor;
  } while (cursor !== undefined);
  return JSON.parse(fragments.join(""));
}

function finding<Extra extends object = object>(
  id: string,
  extra: Extra = {} as Extra,
) {
  return {
    ...draftFinding(id, `src/${id}.ts`),
    ...extra,
  };
}
