import { afterEach, expect, test } from "bun:test";
import { estimateScanCost, type ScanUsageMeasurement } from "../src/cost.js";
import { ScanInterruptedError } from "../src/errors.js";
import { completedUsageFixture } from "./support/completed-usage.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-patch-usage-",
);
afterEach(cleanup);

const receipt = {
  input_tokens: 100,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 10,
  reasoning_output_tokens: 0,
};
const noChange = {
  status: "no_change",
  changedFiles: [],
  verificationReport: "The synthetic finding is already safe.",
  reason: null,
};

test.each([
  "invalid JSON",
  "invalid schema",
  "valid no_change",
  "canceled after completion",
  "canceled on completion",
  "nonzero exit after completion",
  "nonzero exit before completion",
  "null usage",
  "absent usage",
] as const)("preserves completed SDK patch usage with %s", async (ending) => {
  const response =
    ending === "invalid JSON"
      ? "not JSON"
      : JSON.stringify(
          ending === "invalid schema"
            ? { ...noChange, verificationReport: " " }
            : noChange,
        );
  const fixture = await completedUsageFixture(
    await temporaryDirectory(),
    "patch",
    ending,
    response,
    receipt,
  );
  await using client = fixture.client;
  const { model, usage, canceled, failedExit } = fixture;
  const measurements: Readonly<ScanUsageMeasurement>[] = [];
  const pending = client.patch({
    ...fixture.request,
    onMeasurement: (measurement) => measurements.push(measurement),
  });
  const invalid = ending === "invalid JSON" || ending === "invalid schema";
  if (canceled) {
    await expect(pending).rejects.toBeInstanceOf(ScanInterruptedError);
  } else if (failedExit) {
    await expect(pending).rejects.toThrow(
      "Codex Exec exited with code 17: Synthetic patch child exit diagnostic.",
    );
  } else if (invalid) {
    await expect(pending).rejects.toThrow(
      "Finding patch returned an invalid result.",
    );
  } else {
    expect(await pending).toMatchObject({
      status: "no_change",
      threadId: "patch-usage-thread",
      cost: estimateScanCost(model, usage),
    });
  }
  const terminal = await fixture.readTerminalEvent();
  expect(terminal.outcome).toBe(
    canceled ? "canceled" : invalid || failedExit ? "failed" : "completed",
  );
  expect(terminal.measurement).toEqual(measurements.at(-1));
  expect(terminal.measurement).toMatchObject({
    usage:
      usage == null
        ? null
        : { input_tokens: 100, output_tokens: 10, total_tokens: 110 },
    coverage: usage == null ? "unavailable" : "complete",
    cost: estimateScanCost(model, usage),
  });
});
