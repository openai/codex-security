import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const retryPending of [false, true]) {
      test(`archived receipt and pending records survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${retryPending ? "an updated gap" : "a clean retry"}`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            retryPending,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}
