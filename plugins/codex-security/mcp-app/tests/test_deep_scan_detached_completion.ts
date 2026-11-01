import assert from "node:assert/strict";
import { after, test } from "node:test";
import type { DeepScanRunState } from "../src/deep-scan/types.ts";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.ts";
import {
  DeepScanCoordinatorRegistry,
  DeepScanRemoteCoordinator,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  immediateClock,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

after(() => temporaryDirectories.cleanup());

test("an adopted coordinator retains its completion observer after the RPC waiter detaches", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore({
    ...fixture.run,
    coordinatorGeneration: 1,
    updatedAt: "2000-01-01T00:00:00Z",
  });
  store.claimCoordinator = async () => {
    store.run = { ...store.run, coordinatorGeneration: 2 };
    return { run: store.run, acquired: true };
  };
  const request = new AbortController();
  let completion: Promise<DeepScanRunState> | undefined;
  let starts = 0;
  const options: Omit<CoordinatorOptions, "run"> = {
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "synthetic-owner",
    onStart: (coordinator) => {
      starts += 1;
      completion = coordinator.settled();
      request.abort(new Error("synthetic RPC waiter detached"));
    },
  };
  const observer = new DeepScanRemoteCoordinator({
    run: store.run,
    registry: new DeepScanCoordinatorRegistry(),
    options,
  });
  observer.nextClaimAt = 0;

  await assert.rejects(observer.wait(request.signal), { name: "AbortError" });
  assert.equal(starts, 1);
  assert.ok(completion);
  const terminal = await completion;
  assert.equal(terminal.status, "succeeded");
  assert.equal(terminal.coordinatorGeneration, 2);
});
