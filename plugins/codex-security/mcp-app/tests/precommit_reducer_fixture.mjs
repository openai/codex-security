import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
const [scanDir, discoveryPath, reducerPath, variant, scanId] =
  process.argv.slice(2);
const { recordCodexSecurityWorkerScanDraft } = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { validateReducerArtifacts, projectDiscoveryCoverage } =
  await importSource(
    fileURLToPath(
      new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
    ),
  );
const root = path.dirname(discoveryPath);
const context = { root, repoRoot: scanDir, scanId, layout: "worker" };
const surface = {
  id: "review",
  label: "Same synthetic review",
  disposition: "needs_follow_up",
  receiptRefs: [],
};
const initial = {
  scanId,
  complete: true,
  findings: [],
  coverage: {
    completeness: "partial",
    surfaces: [surface],
    explicitExclusions: [],
    deferred: [],
  },
};
await recordCodexSecurityWorkerScanDraft(context, initial);
const old = JSON.parse(await fs.readFile(discoveryPath, "utf8"));
const oldBytes = await fs.readFile(discoveryPath);
const oldHead = await fs.readFile(path.join(root, "checkpoint-head.json"));
const next = structuredClone(initial);
if (variant === "changed")
  next.coverage.surfaces[0].label = "New synthetic review";
if (variant === "additional")
  next.coverage.surfaces.push({
    ...surface,
    id: "extra",
    label: "Unreviewed extra surface",
  });
next.coverage.deferred = [
  {
    id: "pending",
    reason: "Accepted later review remains.",
    surfaceIds: variant === "additional" ? ["review", "extra"] : ["review"],
  },
];
const rename = fs.rename;
let workerFailure;
fs.rename = async function (from, to) {
  const value = await rename.call(this, from, to);
  if (String(to) === path.join(root, "checkpoint-head.json"))
    await fs.chmod(root, 0o500);
  return value;
};
try {
  await recordCodexSecurityWorkerScanDraft(context, next);
} catch (error) {
  workerFailure = error;
} finally {
  fs.rename = rename;
  await fs.chmod(root, 0o700);
}
assert.equal(workerFailure?.code, "EACCES");
assert.deepEqual(await fs.readFile(discoveryPath), oldBytes);
const acceptedHead = await fs.readFile(path.join(root, "checkpoint-head.json"));
assert.notDeepEqual(
  acceptedHead,
  oldHead,
  "the real writer accepted a newer checkpoint before replacement failed",
);
const projected = projectDiscoveryCoverage(
  old.coverage,
  { id: path.basename(root), attempt: 1 },
  path.relative(scanDir, root).split(path.sep).join("/"),
);
const artifactDir = path.dirname(reducerPath);
const raw = await fs.readFile(reducerPath);
await fs.mkdir(path.join(artifactDir, "checkpoints"), { mode: 0o700 });
await fs.chmod(artifactDir, 0o500);
let reducerFailure;
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
          { workerId: path.basename(root), result: old, coverage: projected },
        ],
        previous: null,
      },
      persistSourceCoverage: true,
    },
    scanId,
  );
} catch (error) {
  reducerFailure = error;
} finally {
  await fs.chmod(artifactDir, 0o700);
}
assert.equal(reducerFailure?.code, "EACCES");
assert.deepEqual(await fs.readFile(reducerPath), raw);
const checkpoints = await fs.readdir(path.join(artifactDir, "checkpoints"));
assert.equal(checkpoints.length, 1);
const accepted = JSON.parse(
  await fs.readFile(
    path.join(artifactDir, "checkpoints", checkpoints[0]),
    "utf8",
  ),
);
assert.equal(accepted.sourceCoverage.surfaces.length, 1);
assert.equal(accepted.sourceCoverage.deferred.length, 0);
console.log(
  JSON.stringify({
    workerCheckpointAccepted: true,
    workerResultReplacement: "EACCES",
    reducerCheckpointAccepted: true,
    reducerResultReplacement: "EACCES",
    variant,
    retainedHostSurface: accepted.sourceCoverage.surfaces[0].id,
  }),
);
