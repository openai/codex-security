import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { importSource } from "./import-module.ts";

const { HostedDeepScanExecutor } = await importSource(
  "src/deep-scan/hosted-executor.ts",
);

class Channel extends EventEmitter {
  messages: { id?: string; method: string; params: Record<string, any> }[] = [];
  send(message: any, callback: (error: Error | null) => void) {
    this.messages.push(message);
    callback(null);
  }
  result(id: string | undefined, result: object) {
    this.emit("message", { id, result });
  }
  started(id: string | undefined, sessionId: string) {
    this.emit("message", {
      method: "execution.progress",
      params: { requestId: id, event: { type: "session.started", sessionId } },
    });
  }
}

async function until(predicate: () => boolean) {
  for (let attempts = 0; attempts < 200; attempts++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("host request did not arrive");
}

test("hosted discovery isolates workers and retains a session across continuation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "hosted-deep-executor-"));
  const channel = new Channel();
  const executor = new HostedDeepScanExecutor(channel);
  try {
    const promptPath = join(directory, "prompt.md");
    await writeFile(promptPath, "prepared discovery prompt");
    const signal = new AbortController().signal;
    const attributed: string[] = [];
    const request: CodexWorkerRequest = {
      kind: "discovery",
      promptPath,
      workingDirectory: directory,
      subagents: 3,
      signal,
      artifactContext: { root: join(directory, "first"), layout: "worker" },
      onThreadStarted: async (sessionId) => {
        attributed.push(sessionId);
      },
    };
    const first = executor.run(request);
    const second = executor.run({
      ...request,
      artifactContext: { root: join(directory, "second"), layout: "worker" },
    });
    await until(() => channel.messages.length === 2);
    const [one, two] = channel.messages;
    assert.notEqual(one.params.workerId, two.params.workerId);
    assert.equal(one.params.subagents, 3);
    assert.equal(one.params.prompt, "prepared discovery prompt");
    channel.started(two.id, "session-two");
    channel.result(two.id, {
      status: "completed",
      sessionId: "session-two",
      turnId: "turn-two",
    });
    channel.started(one.id, "session-one");
    channel.result(one.id, {
      status: "completed",
      sessionId: "session-one",
      turnId: "turn-one",
    });
    const results = await Promise.all([first, second]);
    assert.deepEqual(
      results.map((result) => result.threadId),
      ["session-one", "session-two"],
    );
    assert.deepEqual(attributed, ["session-two", "session-one"]);
    const resumed = executor.run({
      ...request,
      resumeThreadId: "session-one",
      continuationPrompt: "finish the existing review",
    });
    await until(() => channel.messages.length === 3);
    const continuation = channel.messages[2];
    assert.equal(continuation.params.workerId, one.params.workerId);
    assert.equal(continuation.params.resumeSessionId, "session-one");
    assert.equal(continuation.params.prompt, "finish the existing review");
    channel.result(continuation.id, {
      status: "completed",
      sessionId: "session-one",
      turnId: "turn-three",
    });
    assert.equal((await resumed).threadId, "session-one");
    const release = executor.releaseSession("session-one");
    await until(() => channel.messages.length === 4);
    assert.equal(channel.messages[3].method, "execution.release");
    channel.result(channel.messages[3].id, {
      status: "completed",
      sessionId: "session-one",
    });
    await release;
  } finally {
    executor.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unknown acceptance invokes the terminal callback and never retries", async () => {
  const channel = new Channel();
  const executor = new HostedDeepScanExecutor(channel);
  const errors: Error[] = [];
  const result = executor.run({
    kind: "discovery",
    promptPath: "unused",
    continuationPrompt: "continue",
    workingDirectory: "/synthetic/worker",
    subagents: 3,
    signal: new AbortController().signal,
    onNonRetryableError: (error: Error) => errors.push(error),
  });
  const rejected = assert.rejects(result, {
    name: "DeepScanNonRetryableError",
  });
  channel.result(channel.messages[0].id, {
    status: "acceptance_unknown",
    message: "host acceptance is uncertain",
  });
  await rejected;
  assert.equal(errors.length, 1);
  assert.equal(channel.messages.length, 1);
  executor.close();
});

test("comparison cancellation waits for its host receipt and releases the session", async () => {
  const channel = new Channel();
  const executor = new HostedDeepScanExecutor(channel);
  const controller = new AbortController();
  const result = executor.compareFindings(
    "compare",
    "/synthetic/worker",
    controller.signal,
    { type: "object" },
  );
  const rejected = assert.rejects(result, /canceled/);
  const request = channel.messages[0];
  assert.equal(request.params.kind, "comparison");
  assert.equal(request.params.subagents, 0);
  assert.deepEqual(request.params.outputSchema, { type: "object" });
  channel.started(request.id, "comparison-session");
  controller.abort();
  assert.deepEqual(channel.messages[1], {
    method: "execution.cancel",
    params: { requestId: request.id },
  });
  channel.result(request.id, {
    status: "canceled",
    sessionId: "comparison-session",
  });
  await until(() => channel.messages.length === 3);
  assert.equal(channel.messages[2].method, "execution.release");
  channel.result(channel.messages[2].id, {
    status: "completed",
    sessionId: "comparison-session",
  });
  await rejected;
  executor.close();
});

test("a failed receipt retains its session even when start progress was lost", async () => {
  const channel = new Channel();
  const executor = new HostedDeepScanExecutor(channel);
  const sessions: string[] = [];
  const result = executor.run({
    kind: "discovery",
    promptPath: "unused",
    continuationPrompt: "continue",
    workingDirectory: "/synthetic/worker",
    subagents: 3,
    signal: new AbortController().signal,
    onThreadStarted: async (sessionId: string) => {
      sessions.push(sessionId);
    },
  });
  const rejected = assert.rejects(result, /failed/);
  channel.result(channel.messages[0].id, {
    status: "failed",
    sessionId: "retained-session",
  });
  await rejected;
  assert.deepEqual(sessions, ["retained-session"]);
  executor.close();
  assert.equal(channel.listenerCount("message"), 0);
  assert.equal(channel.listenerCount("disconnect"), 0);
});
