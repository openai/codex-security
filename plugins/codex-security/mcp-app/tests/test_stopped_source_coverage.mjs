import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  const root = await mkdtemp(path.join(tmpdir(), "stopped-source-coverage-"));
  try {
    const { scanDir } = await publishCoverageFixture(root, "partial", { resume, stopAfterDraft: true });
    const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
    assert.equal(coverage.reviews.length, 3);
    assert.equal(coverage.surfaces.length, 3);
    assert.deepEqual(coverage.deferred.filter((item) => item.id !== "scan-stopped").map((item) => item.reason), [
      "Verify entry boundaries.", "Verify symbolic links.",
    ]);
    for (const surface of coverage.surfaces) {
      assert.equal(surface.receiptRefs.length, 1);
      assert.equal(await readFile(path.join(scanDir, surface.receiptRefs[0]), "utf8"), "Synthetic review evidence.\n");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
