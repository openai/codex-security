import assert from "node:assert/strict";
import { after, test } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import {
  coordinatorFixture,
  FakeExecutor,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

after(() => temporaryDirectories.cleanup());

class RetainedExecutor extends FakeExecutor {
  released: string[] = [];
  previous = new Map<string, string>();

  async run(request: CodexWorkerRequest) {
    const previous = this.previous.get(request.workingDirectory);
    if (request.resumeThreadId) {
      assert.equal(this.released.includes(request.resumeThreadId), false);
    } else if (previous) {
      assert.ok(
        this.released.includes(previous),
        "abandoned sessions must be released before replacement",
      );
    }
    const result = await super.run({
      ...request,
      onThreadStarted: async (threadId) => {
        this.previous.set(request.workingDirectory, threadId);
        await request.onThreadStarted?.(threadId);
      },
    });
    return result;
  }

  async releaseSession(threadId: string) {
    assert.equal(
      this.released.includes(threadId),
      false,
      "a session is released once",
    );
    this.released.push(threadId);
  }
}

for (const [label, options, sessions] of [
  [
    "missing output resumes the retained session",
    { invalidDiscoveryAttempts: 1 },
    1,
  ],
  [
    "invalid output releases before starting a replacement",
    { malformedDiscoveryAttempts: 1 },
    2,
  ],
] as const) {
  test(label, async () => {
    const { fixture, store } = await coordinatorFixture({
      workers: 1,
      subagents: 3,
      stopAfterNoNew: 1,
      maxDiscoveryRuns: 1,
    });
    const executor = new RetainedExecutor(options);
    const terminal = await runCoordinator(fixture, store, executor, {
      retryDelaysMs: [0],
      random: () => 0,
    });
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(executor.discoveryCalls, 2);
    assert.equal(executor.released.length, sessions);
  });
}
