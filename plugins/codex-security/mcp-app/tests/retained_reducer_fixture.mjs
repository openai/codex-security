import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const [scanDir, workerPath, reducerPath, countArg, secondArg, scanId] =
  process.argv.slice(2);
import { importSource } from "./import-module.ts";
const { parsePersistedScanDraft } = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { projectDiscoveryCoverage, validateReducerArtifacts } =
  await importSource(
    fileURLToPath(
      new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
    ),
  );
const root = path.dirname(workerPath);
const source = {
  scanId,
  complete: true,
  findings: [],
  coverage: {
    completeness: "partial",
    surfaces: Array.from({ length: Number(countArg) }, (_, i) => ({
      id: "shared",
      label: `Independent saved surface ${i + 1}`,
      disposition: "needs_follow_up",
      receiptRefs: [],
    })),
    explicitExclusions: [],
    deferred: [
      {
        id: "task",
        reason: "Retained accepted proof remains.",
        surfaceIds: ["shared"],
      },
      ...(secondArg === "true"
        ? [
            {
              id: "other",
              reason: "Independent second proof remains.",
              surfaceIds: ["shared"],
            },
          ]
        : []),
    ],
  },
};
// This is historical saved input accepted by the existing persisted reader;
// the host projection and accepted reducer checkpoint use current producers.
const parsed = parsePersistedScanDraft(source);
assert.equal(parsed.coverage.surfaces.length, Number(countArg));
await fs.writeFile(workerPath, JSON.stringify(source));
const originalWorkerBytes = await fs.readFile(workerPath);
const projected = projectDiscoveryCoverage(
  parsed.coverage,
  { id: path.basename(root), attempt: 1 },
  path.relative(scanDir, root).split(path.sep).join("/"),
);
assert.equal(projected.deferred[0].surfaceIds.length, Number(countArg));
const artifactDir = path.dirname(reducerPath);
const originalReducerBytes = await fs.readFile(reducerPath);
await fs.mkdir(path.join(artifactDir, "checkpoints"), { mode: 0o700 });
await fs.chmod(artifactDir, 0o500);
let failure;
try {
  await validateReducerArtifacts(
    {
      artifacts: {
        scanDir,
        workersRoot: path.join(scanDir, "workers"),
        dedupRoot: path.join(scanDir, "workers"),
      },
      artifactDir,
      resultPath: reducerPath,
      reducerId: path.basename(artifactDir),
      sources: {
        discoveries: [
          {
            workerId: path.basename(root),
            result: parsed,
            coverage: projected,
          },
        ],
        previous: null,
      },
      persistSourceCoverage: true,
    },
    scanId,
  );
} catch (error) {
  failure = error;
} finally {
  await fs.chmod(artifactDir, 0o700);
}
assert.equal(failure?.code, "EACCES");
assert.deepEqual(await fs.readFile(workerPath), originalWorkerBytes);
assert.deepEqual(await fs.readFile(reducerPath), originalReducerBytes);
const entries = await fs.readdir(path.join(artifactDir, "checkpoints"));
assert.equal(entries.length, 1);
const accepted = JSON.parse(
  await fs.readFile(path.join(artifactDir, "checkpoints", entries[0]), "utf8"),
);
assert.equal(accepted.sourceCoverage.surfaces.length, Number(countArg));
assert.equal(
  accepted.sourceCoverage.deferred.length,
  secondArg === "true" ? 2 : 1,
);
console.log(
  JSON.stringify({
    historicalParserAccepted: true,
    hostProjectorExpandedLinks: true,
    acceptedReducerCheckpoint: true,
    resultReplacement: "EACCES",
    expectedDeferred: accepted.sourceCoverage.deferred,
    expectedSurfaceIds: accepted.sourceCoverage.surfaces.map((row) => row.id),
  }),
);
