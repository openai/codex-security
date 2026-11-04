import assert from "node:assert/strict";
import { setImmediate } from "node:timers/promises";
import { test } from "node:test";
import type { DeepScanLogEvent } from "../src/deep-scan/types.js";
import {
  coordinatorFixture,
  createCoordinator,
  FakeExecutor,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

try {
  for (const failure of ["throwing", "rejecting"] as const) {
    const fail = () => {
      const error = new Error("optional log sink unavailable");
      if (failure === "throwing") throw error;
      return Promise.reject(error);
    };

    await test(`a ${failure} logger does not stop the scan loop`, async () => {
      const { fixture, store } = await coordinatorFixture();
      const executor = new FakeExecutor({
        discoveryCandidateId: "candidate-1",
      });
      const events: DeepScanLogEvent[] = [];
      const terminal = await runCoordinator(fixture, store, executor, {
        log(event) {
          events.push(event);
          return fail();
        },
      });
      await setImmediate();
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.equal(executor.discoveryCalls, 1);
      assert.equal(store.iterations.length, 1);
      for (const event of [
        "coordinator_started",
        "discovery_accepted",
        "progress_updated",
        "coordinator_terminal",
      ]) {
        assert.ok(events.some((entry) => entry.event === event));
      }
    });

    await test(`a ${failure} logger does not stop cancellation or cleanup`, async () => {
      const { fixture, store } = await coordinatorFixture();
      const gate = Promise.withResolvers<void>();
      const executor = new FakeExecutor({
        discoveryGates: { "discovery-0001": gate.promise },
      });
      let workerSignal: AbortSignal | undefined;
      const events: DeepScanLogEvent[] = [];
      const coordinator = createCoordinator(
        fixture,
        store,
        {
          run(request) {
            workerSignal = request.signal;
            return executor.run(request);
          },
        },
        {
          log(event) {
            events.push(event);
            if (
              event.event === "coordinator_cancel_requested" ||
              event.event === "coordinator_cleanup_settled"
            )
              return fail();
          },
        },
      );
      coordinator.start();
      await executor.discoveryStarted.promise;
      const reason = "fixture cancellation\nwith diagnostic detail";
      try {
        assert.doesNotThrow(() => coordinator.cancel(reason));
        assert.equal(workerSignal?.aborted, true);
        assert.equal(workerSignal?.reason, reason);
      } finally {
        gate.resolve();
        await coordinator.wait(undefined, 5_000);
      }
      await setImmediate();
      assert.equal(coordinator.snapshot().status, "canceled");
      assert.equal(executor.runningDiscovery, 0);
      assert.equal(
        events.find((entry) => entry.event === "coordinator_cancel_requested")
          ?.reason,
        reason,
      );
      assert.ok(
        events.some((entry) => entry.event === "coordinator_cleanup_settled"),
      );
    });
  }
} finally {
  await temporaryDirectories.cleanup();
}
