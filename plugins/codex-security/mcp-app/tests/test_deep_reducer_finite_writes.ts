import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import {
  completedFinding as finding,
  scanId,
  workerDraft,
} from "./scan-draft-fixture.ts";

const reducer = await importSource("src/artifact-deep-reducer.ts");
const validation = await importSource("src/deep-scan/artifact-validation.ts");
const { createDeepScanArtifacts } = await importSource(
  "src/deep-scan/artifacts.ts",
);
const marker = "overflow-number";
const finiteError = {
  name: "TypeError",
  message: "Stored finding JSON cannot contain non-finite numbers.",
};
const sourceFinding = () => finding("shared", "api/source.py");
const draft = () => ({ scanId, findings: [sourceFinding()] });
const wire = (value: unknown) =>
  JSON.stringify(value).replaceAll(JSON.stringify(marker), "1e400");

async function fixture(
  t: TestContext,
  route: "mcp" | "file",
  historical?: "discovery" | "previous",
) {
  const root = await mkdtemp(join(tmpdir(), "reducer-finite-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = createDeepScanArtifacts(join(root, "scan"));
  const output = join(artifacts.dedupRoot, "reducer-001", "output");
  const resultPath = join(output, "result.json");
  const workerPath = join(
    artifacts.workersRoot,
    "worker-001",
    "output",
    "result.json",
  );
  const legacy = {
    scanId,
    findings: [{ ...sourceFinding(), extensions: { measurement: marker } }],
    threatModel: { summary: "API model", measurement: marker },
  };
  await mkdir(dirname(workerPath), { recursive: true });
  await mkdir(output, { recursive: true });
  await writeFile(
    workerPath,
    wire(
      historical === "discovery"
        ? workerDraft(legacy.findings, { threatModel: legacy.threatModel })
        : workerDraft(historical === "previous" ? [] : [sourceFinding()]),
    ),
  );
  const previousReducerResultPath =
    historical === "previous"
      ? join(artifacts.dedupRoot, "previous.json")
      : undefined;
  if (previousReducerResultPath)
    await writeFile(previousReducerResultPath, wire(legacy));
  const context = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot: artifacts.scanDir,
      claimedWorkers: [{ id: "worker-001", resultPath: workerPath }],
      previousReducerResultPath,
    },
  };
  const sources = await reducer.getCodexSecurityDeepReducerInputs(context);
  const admission = {
    artifacts,
    artifactDir: output,
    resultPath,
    reducerId: "reducer-001",
    sources,
  };
  return {
    output,
    resultPath,
    admission,
    async write(value: unknown) {
      const raw = wire(value);
      if (route === "file") {
        await writeFile(resultPath, raw);
        return validation.validateReducerArtifacts(admission, scanId);
      }
      const input = JSON.parse(raw);
      const before = structuredClone(input);
      try {
        return await reducer.recordCodexSecurityDeepReduction(context, input);
      } finally {
        assert.deepEqual(input, before);
      }
    },
  };
}

async function storedDrafts(output: string) {
  const checkpoints = await readdir(join(output, "checkpoints"));
  assert.ok(checkpoints.length > 0);
  return Promise.all(
    [
      "result.json",
      ...checkpoints.map((name) => join("checkpoints", name)),
    ].map(async (name) =>
      JSON.parse(await readFile(join(output, name), "utf8")),
    ),
  );
}

for (const route of ["mcp", "file"] as const) {
  for (const field of [
    "threatModel",
    "extensions",
    "previousFindings",
    "originalCandidates",
  ]) {
    test(`${route} reducer rejects retained ${field} overflow before checkpointing`, async (t) => {
      const f = await fixture(t, route);
      const input = draft();
      if (field === "threatModel")
        Object.assign(input, {
          threatModel: { summary: "API model", measurement: marker },
        });
      else if (field === "extensions")
        Object.assign(input.findings[0], {
          extensions: { measurement: marker },
        });
      else
        Object.assign(input.findings[0].provenance, {
          [field]: [{ measurement: marker }],
        });
      await assert.rejects(f.write(input), finiteError);
      assert.deepEqual(
        await readdir(f.output),
        route === "file" ? ["result.json"] : [],
      );
      if (route === "file")
        assert.equal(await readFile(f.resultPath, "utf8"), wire(input));
    });
  }

  test(`${route} reducer replaces submitted source payloads before retaining them`, async (t) => {
    const f = await fixture(t, route);
    const input = draft();
    Object.assign(input.findings[0].provenance, {
      sourceFindings: [{ id: "discarded", finding: { measurement: marker } }],
    });
    await f.write(input);
    for (const saved of await storedDrafts(f.output)) {
      const sources = saved.findings[0].provenance.sourceFindings;
      assert.equal(sources.length, 1);
      assert.deepEqual(sources[0].finding, sourceFinding());
    }
  });

  for (const historical of ["discovery", "previous"] as const) {
    test(`${route} reducer retains historical ${historical} payloads without fresh validation`, async (t) => {
      const f = await fixture(t, route, historical);
      await f.write(draft());
      for (const saved of await storedDrafts(f.output)) {
        assert.equal(saved.threatModel.measurement, null);
        assert.equal(
          saved.findings[0].provenance.sourceFindings[0].finding.extensions
            .measurement,
          null,
        );
      }
    });
  }
}

test("historical reducer validation reads overflow without rewriting the artifact", async (t) => {
  const f = await fixture(t, "file");
  const input = {
    ...draft(),
    threatModel: { summary: "API model", measurement: marker },
  };
  await writeFile(f.resultPath, wire(input));
  const { sources: _sources, ...historical } = f.admission;
  const validated = await validation.validateReducerArtifacts(
    historical,
    scanId,
  );
  assert.equal(validated.result.threatModel.measurement, Infinity);
  assert.equal(await readFile(f.resultPath, "utf8"), wire(input));
  assert.deepEqual(await readdir(f.output), ["result.json"]);
});

test("reference retention copies historical payloads without treating them as fresh model output", async (t) => {
  const f = await fixture(t, "mcp", "previous");
  await f.write({ scanId, findings: [], retainedFindingRefs: ["previous:0"] });
  for (const saved of await storedDrafts(f.output)) {
    assert.equal(saved.findings[0].extensions.measurement, null);
    assert.equal(saved.threatModel.measurement, null);
  }
});
