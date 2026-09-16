import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const stopAfterDraft of [false, true]) {
    test(`archived receipt survives ${resume ? "reconstruction" : "live retry"} and ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
      try {
        await publishCoverageFixture(root, "complete", { receiptRetry: true, stopAfterDraft, resume });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
