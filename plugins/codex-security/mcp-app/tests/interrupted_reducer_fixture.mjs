import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mock } from "node:test";
import { importSource } from "./import-module.ts";

const { validateReducerArtifacts, projectDiscoveryCoverage } =
  await importSource(
    fileURLToPath(
      new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
    ),
  );
const { createDeepScanArtifacts: artifactsForScan } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);
const [scanDir, discoveryPath, reducerPath, interrupted] =
  process.argv.slice(2);
const original = await fs.readFile(reducerPath, "utf8");
const discovery = JSON.parse(await fs.readFile(discoveryPath, "utf8"));
const workerId = path.basename(path.dirname(discoveryPath));
const { coverage, ...result } = discovery;
const rename = fs.rename;
const failure = mock.method(fs, "rename", async (source, destination) => {
  if (interrupted === "true" && destination === reducerPath)
    throw new Error("Synthetic reducer result replacement failure.");
  return rename(source, destination);
});
try {
  const validate = () =>
    validateReducerArtifacts(
      {
        artifacts: artifactsForScan(scanDir),
        artifactDir: path.dirname(reducerPath),
        resultPath: reducerPath,
        reducerId: path.basename(path.dirname(reducerPath)),
        sources: {
          discoveries: [
            {
              workerId,
              attempt: 1,
              result,
              coverage: projectDiscoveryCoverage(
                coverage,
                { id: workerId, attempt: 1 },
                path
                  .relative(scanDir, path.dirname(discoveryPath))
                  .split(path.sep)
                  .join("/"),
              ),
            },
          ],
          previous: null,
        },
        persistSourceCoverage: true,
      },
      discovery.scanId,
    );
  if (interrupted === "true") {
    await assert.rejects(
      validate(),
      /Synthetic reducer result replacement failure/,
    );
    assert.equal(await fs.readFile(reducerPath, "utf8"), original);
  } else {
    await validate();
  }
  const names = await fs.readdir(
    path.join(path.dirname(reducerPath), "checkpoints"),
  );
  assert.equal(names.length, 1);
  const checkpoint = JSON.parse(
    await fs.readFile(
      path.join(path.dirname(reducerPath), "checkpoints", names[0]),
      "utf8",
    ),
  );
  assert.equal(checkpoint.sourceCoverage.reviews[0].workerId, workerId);
  assert.equal(checkpoint.sourceCoverage.reviews[0].attempt, 1);
} finally {
  failure.mock.restore();
}
