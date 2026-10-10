import assert from "node:assert/strict";
import type {
  DeepScanRunState,
  DeepScanLogEvent,
} from "../src/deep-scan/types.js";
import {
  fixtureRun,
  FakeStore,
  DeepScanCoordinator,
} from "./deep_scan_coordinator_fixture.ts";

export async function testSelectedFinalizationOwner() {
  for (const failure of [
    undefined,
    "draft",
    "finish",
    "parent",
    "replacement",
  ] as const) {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 1,
      maxDiscoveryRuns: 1,
    });
    fixture.run.workflowVersion = "deep-security-scan/v2";
    fixture.run.coordinatorGeneration = 3;
    fixture.run.finalizationInput = {
      version: 1,
      resultPath: null,
      resultSha256: null,
      terminalReason: "capped",
      omittedWorkerIds: [],
      selectedAt: "2026-01-01T00:00:00Z",
    };
    const store = new FakeStore(fixture.run);
    const finishStarted = Promise.withResolvers<void>();
    const releaseFinish = Promise.withResolvers<void>();
    const parentStarted = Promise.withResolvers<void>();
    const releaseParent = Promise.withResolvers<void>();
    const calls: string[] = [];
    const events: DeepScanLogEvent[] = [];
    store.finish = async () => {
      calls.push("finish");
      finishStarted.resolve();
      await releaseFinish.promise;
      if (failure === "finish")
        throw new Error("injected selected finish failure");
      if (failure === "replacement") {
        store.run = {
          ...store.run,
          status: "succeeded",
          coordinatorGeneration: 4,
        };
        throw new Error("Deep Scan coordinator generation is stale.");
      }
      store.run = {
        ...store.run,
        status: "succeeded",
        terminalReason: "capped",
      };
      return structuredClone(store.run);
    };
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      pluginRoot: fixture.pluginRoot,
      executor: {
        run: async () =>
          assert.fail("Selected finalization cannot start model work"),
      },
      threadId: "selected-owner",
      log: (event: DeepScanLogEvent) => events.push(event),
      onComplete: async () => {
        calls.push("draft");
        if (failure === "draft")
          throw new Error("injected selected draft failure");
      },
      onFinalized: async (run: DeepScanRunState) => {
        calls.push("parent");
        assert.equal(run.status, "succeeded");
        assert.equal(run.coordinatorGeneration, 3);
        parentStarted.resolve();
        await releaseParent.promise;
        if (failure === "parent")
          throw new Error("injected selected parent failure");
      },
    });
    // Rejections stay observed even when the user detaches their only waiter.
    const settled = coordinator.settled();
    settled.catch(() => {});
    const observer = new AbortController();
    coordinator.start();
    const detached = coordinator.wait(observer.signal);
    observer.abort();
    await assert.rejects(detached, { name: "AbortError" });
    if (failure !== "draft") {
      await finishStarted.promise;
      assert.deepEqual(calls, ["draft", "finish"]);
      assert.equal(await coordinator.wait(undefined, 10), undefined);
      releaseFinish.resolve();
    }
    if (failure === undefined || failure === "parent") {
      await parentStarted.promise;
      assert.equal(
        await coordinator.wait(undefined, 10),
        undefined,
        "wait includes enclosing completion",
      );
      releaseParent.resolve();
    }
    if (failure && failure !== "replacement") {
      await assert.rejects(
        settled,
        new RegExp(`injected selected ${failure} failure`),
      );
      assert.equal(
        store.failureMessages.length,
        0,
        "publication errors retain the original selected stop",
      );
      assert.equal(
        events.some(
          (event) => event.event === "coordinator_publication_pending",
        ),
        true,
      );
      assert.equal(
        store.run.status,
        failure === "parent" ? "succeeded" : "running",
      );
    } else {
      assert.equal((await settled).status, "succeeded");
    }
    assert.deepEqual(
      calls,
      failure === "draft"
        ? ["draft"]
        : failure === "finish" || failure === "replacement"
          ? ["draft", "finish"]
          : ["draft", "finish", "parent"],
    );
    assert.deepEqual(
      store.run.finalizationInput,
      fixture.run.finalizationInput,
    );
  }
}
