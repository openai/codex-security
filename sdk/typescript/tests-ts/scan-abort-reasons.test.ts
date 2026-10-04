import { expect, test } from "bun:test";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScanCostTrackingError } from "../src/deep-scan.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { completedEvents, runEvents } from "./support/api-events.js";

test("streamed cancellation preserves cost and transport reasons", async () => {
  const scanDir = await realpath(
    await mkdtemp(join(tmpdir(), "scan-abort-reasons-")),
  );
  try {
    for (const reason of [
      new ScanCostTrackingError("Synthetic missing receipt", scanDir),
      new ScanTransportClosedError("Synthetic host interruption"),
    ]) {
      const abortController = new AbortController();
      async function* events() {
        yield* completedEvents();
        abortController.abort(reason);
      }
      await expect(
        runEvents(scanDir, events(), { abortController }),
      ).rejects.toBe(reason);
    }
  } finally {
    await rm(scanDir, { recursive: true, force: true });
  }
});
