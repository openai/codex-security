import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ThreadEvent } from "@openai/codex-sdk";
import {
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  temporaryDirectories,
  workerRequest,
} from "./deep_scan_executor_fixture.ts";
import { mockWorkerSpawn } from "./deep_scan_cancellation_cases.ts";
import {
  coordinatorFixture,
  createCoordinator,
  temporaryDirectories as coordinatorDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { trustedParentSandbox } from "./support/fake-codex-fixture.ts";
import { restoreEnv } from "./support/fake-codex-source.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { importSource } from "./import-module.ts";
import type { DeepScanConfig } from "../src/deep-scan/types.js";

const { createCodexSecurityArtifactWriterServer } = await importSource(
  path.join(import.meta.dirname, "../artifact-writer-main.ts"),
);
const draftTool = "record_codex_security_scan_draft";
const config: DeepScanConfig = {
  workers: 1,
  subagents: 0,
  stopAfterNoNew: 3,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 3,
};
afterEach(async () => {
  await temporaryDirectories.cleanup();
  await coordinatorDirectories.cleanup();
});

async function fixture() {
  const saved = new Map<string, string | undefined>();
  const set = (name: string, value?: string) => {
    if (!saved.has(name)) saved.set(name, process.env[name]);
    restoreEnv(name, value);
  };
  set("FAKE_CODEX_MARKER");
  const fake = await fakeCodexFixture(null);
  const home = path.join(fake.root, "home");
  await mkdir(home);
  const settings = path.join(fake.root, "config.toml");
  await writeFile(settings, "");
  set("CODEX_HOME", home);
  set("CODEX_SECURITY_CONFIG_PATH", settings);
  set("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH");
  set("OPENAI_API_KEY");
  set("CODEX_API_KEY", "synthetic-worker-key");
  set("FAKE_CODEX_ARTIFACT_EVENT");
  const eventsPath = path.join(fake.root, "events.jsonl");
  set("FAKE_CODEX_EVENTS_PATH", eventsPath);
  const launches: {
    child: ChildProcess;
    signal: AbortSignal;
    args: readonly string[];
  }[] = [];
  let onKill: (() => void) | undefined;
  const restoreSpawn = mockWorkerSpawn(
    fake.executablePath,
    (child, args, options) => {
      launches.push({ child, args, signal: options.signal! });
      const kill = child.kill;
      child.kill = function (...args: Parameters<ChildProcess["kill"]>) {
        onKill?.();
        return kill.apply(this, args);
      };
    },
  );
  const promptPath = path.join(fake.root, "prompt.md");
  await writeFile(promptPath, "Complete the synthetic review.\n");
  return {
    ...fake,
    promptPath,
    launches,
    setOnKill(callback: () => void) {
      onKill = callback;
    },
    async events(events: ThreadEvent[]) {
      await writeFile(
        eventsPath,
        events.map((event) => JSON.stringify(event)).join("\n") + "\n",
      );
    },
    executor(limit = 3) {
      return new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
        deepScanConfig: { ...config, stopAfterConsecutiveErrors: limit },
      });
    },
    close() {
      onKill = undefined;
      for (const { child } of launches) {
        if (child.exitCode === null && child.signalCode === null)
          child.kill("SIGKILL");
      }
      restoreSpawn();
      for (const [name, value] of saved) restoreEnv(name, value);
    },
  };
}

// Use the actual registered tool and MCP validation, then replay its replies in
// the Codex SDK's JSONL format through a fake child process. No model is needed.
async function artifactClient(root: string, id = scanId) {
  await mkdir(root, { recursive: true });
  const server = await createCodexSecurityArtifactWriterServer({
    CODEX_SECURITY_ARTIFACT_ROOT: root,
    CODEX_SECURITY_REPO_ROOT: root,
    CODEX_SECURITY_SCAN_ID: id,
    CODEX_SECURITY_DISCOVERY_BOARD_ROOT: path.join(root, "peer-notes"),
    CODEX_SECURITY_DISCOVERY_WORKER: "synthetic-worker",
  });
  const client = new Client({ name: "submission-fixture", version: "1.0.0" });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(right);
  await client.connect(left);
  let sequence = 0;
  return {
    async call(
      tool: string,
      args: Record<string, unknown>,
    ): Promise<ThreadEvent> {
      const reply = CallToolResultSchema.parse(
        await client.callTool({ name: tool, arguments: args }),
      );
      return {
        type: "item.completed",
        item: {
          id: `tool-${++sequence}`,
          type: "mcp_tool_call",
          server: "cs_artifacts",
          tool,
          arguments: args,
          status: reply.isError ? "failed" : "completed",
          result: {
            content: reply.content,
            structured_content: reply.structuredContent,
          },
        },
      };
    },
    draft: workerDraft([finding("preserved", "fixture.ts")], {
      scanId: id,
      complete: false,
    }),
    async close() {
      await client.close();
      await server.close();
    },
  };
}

for (const failure of ["schema", "handler", "transport"] as const) {
  test(`stops repeated ${failure} submissions inside the turn despite successful reads`, async () => {
    const f = await fixture();
    const artifacts = await artifactClient(path.join(f.root, "output"));
    const controller = new AbortController();
    try {
      const events: ThreadEvent[] = [];
      for (let i = 0; i < 3; i++) {
        events.push(
          failure === "transport"
            ? {
                type: "item.completed",
                item: {
                  id: `transport-${i}`,
                  type: "mcp_tool_call",
                  server: "cs_artifacts",
                  tool: draftTool,
                  arguments: {},
                  status: "failed",
                  error: { message: "synthetic transport closed" },
                },
              }
            : await artifacts.call(
                draftTool,
                failure === "schema"
                  ? {
                      ...artifacts.draft,
                      threatModel: JSON.stringify({
                        summary: "Synthetic model",
                      }),
                    }
                  : { ...artifacts.draft, scanId: randomUUID() },
              ),
        );
        events.push(await artifacts.call("read_deep_scan_peer_notes", {}));
      }
      assert.equal(
        (events[0] as { item: { status: string } }).item.status,
        "failed",
      );
      if (failure !== "transport") {
        assert.match(
          JSON.stringify(events[0]),
          failure === "schema"
            ? /Input validation error/
            : /coordinator-bound worker scan/,
        );
      }
      await f.events(events);
      let completed = false;
      await assert.rejects(
        f.executor().run(
          workerRequest(f.promptPath, f.root, {
            signal: controller.signal,
            onUsage: () => {
              completed = true;
            },
          }),
        ),
        /3 consecutive.*submission/i,
      );
      assert.equal(
        completed,
        false,
        "buffered turn.completed must not override the failure",
      );
      assert.equal(
        controller.signal.aborted,
        false,
        "only this attempt is canceled",
      );
      assert.equal(f.launches.length, 1);
      assert.equal(f.launches[0].signal.aborted, true);
      assert.equal(f.launches[0].child.killed, true);
    } finally {
      await artifacts.close();
      f.close();
    }
  });
}

test("persisted submissions reset the streak; other tools and intermediate events do not count", async () => {
  const f = await fixture();
  const output = path.join(f.root, "output");
  const artifacts = await artifactClient(output);
  try {
    const events: ThreadEvent[] = [];
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 2; i++)
        events.push(
          await artifacts.call(draftTool, {
            ...artifacts.draft,
            threatModel: "{}",
          }),
        );
      const success = await artifacts.call(draftTool, artifacts.draft);
      assert.equal(
        (success as { item: { status: string } }).item.status,
        "completed",
      );
      events.push(success);
    }
    // Failed reads, foreign tool names, and nonterminal updates are not submissions.
    for (let i = 0; i < 4; i++) {
      const failure = await artifacts.call(draftTool, {
        ...artifacts.draft,
        threatModel: "{}",
      });
      assert.equal(failure.type, "item.completed");
      if (failure.type !== "item.completed") throw new Error("Missing item");
      events.push({
        ...failure,
        item: { ...failure.item, server: "foreign" },
      } as ThreadEvent);
      events.push({
        ...failure,
        item: { ...failure.item, tool: "read_deep_scan_peer_notes" },
      } as ThreadEvent);
      events.push({ ...failure, type: "item.updated" });
    }
    await f.events(events);
    await f.executor().run(workerRequest(f.promptPath, f.root));
    assert.equal(f.launches[0].signal.aborted, false);
    const saved = JSON.parse(
      await readFile(path.join(output, "result.json"), "utf8"),
    );
    assert.equal(saved.complete, false);
    assert.equal(saved.findings.length, 1);
    assert.deepEqual(
      saved.findings[0].provenance,
      artifacts.draft.findings[0].provenance,
    );
  } finally {
    await artifacts.close();
    f.close();
  }
});

test("saved per-scan limits isolate concurrent executors and apply to resumed turns", async () => {
  const f = await fixture();
  const artifacts = await artifactClient(path.join(f.root, "output"));
  try {
    await f.events(
      await Promise.all(
        [1, 2].map(() =>
          artifacts.call(draftTool, { ...artifacts.draft, threatModel: "{}" }),
        ),
      ),
    );
    const results = await Promise.allSettled(
      [2, 3].map((limit) =>
        f.executor(limit).run(
          workerRequest(f.promptPath, f.root, {
            resumeThreadId: `thread-limit-${limit}`,
          }),
        ),
      ),
    );
    assert.equal(results[0].status, "rejected");
    assert.equal(results[1].status, "fulfilled");
    assert.equal(f.launches.filter(({ signal }) => signal.aborted).length, 1);
    assert.ok(f.launches.every(({ args }) => args.includes("resume")));
  } finally {
    await artifacts.close();
    f.close();
  }
});

test("coordinator retains accepted findings and partial checkpoints when submission retries exhaust", async () => {
  const f = await fixture();
  const { fixture: scan, store } = await coordinatorFixture({
    ...config,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3,
  });
  const executor = f.executor(2);
  let attempts = 0;
  let stopped = false;
  let acceptedCheckpoint: string | undefined;
  const resumes: (string | undefined)[] = [];
  try {
    const coordinator = createCoordinator(
      scan,
      store,
      {
        async run(request) {
          attempts++;
          if (attempts === 2) {
            acceptedCheckpoint = await readFile(
              store.iterations[0].resultPath,
              "utf8",
            );
          }
          resumes.push(request.resumeThreadId);
          const artifacts = await artifactClient(
            request.workingDirectory,
            scan.run.scanId,
          );
          try {
            // Accept the first discovery, then checkpoint the failing workers.
            const saved = await artifacts.call(draftTool, {
              ...artifacts.draft,
              complete: attempts === 1,
            });
            const failures =
              attempts === 1
                ? []
                : await Promise.all(
                    [1, 2].map(() =>
                      artifacts.call(draftTool, {
                        ...artifacts.draft,
                        threatModel: "{}",
                      }),
                    ),
                  );
            await f.events([saved, ...failures]);
          } finally {
            await artifacts.close();
          }
          return executor.run(request);
        },
      },
      {
        retryDelaysMs: [0],
        threadId: "synthetic-coordinator",
        onStopped: async () => {
          stopped = true;
        },
        onComplete: async () => {
          assert.fail("Partial scans must not be completed");
        },
      },
    );
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 10_000);
    assert.equal(terminal?.status, "failed", terminal?.error);
    assert.equal(
      attempts,
      5,
      "one accepted worker, two attempts per failing worker, then the saved error limit",
    );
    assert.deepEqual(
      resumes,
      [
        undefined,
        undefined,
        "fixture-thread-id",
        undefined,
        "fixture-thread-id",
      ],
      JSON.stringify(store.workerUpdates),
    );
    assert.equal(stopped, true);
    assert.equal(store.finishCalls.length, 0);
    assert.equal(f.launches[0].signal.aborted, false);
    assert.ok(f.launches.slice(1).every(({ signal }) => signal.aborted));
    assert.ok(
      store.workerUpdates.some(({ error }) =>
        /2 consecutive.*submission/i.test(error ?? ""),
      ),
    );
    assert.equal(store.iterations.length, 1);
    assert.equal(
      await readFile(store.iterations[0].resultPath, "utf8"),
      acceptedCheckpoint,
      "Accepted findings and their aggregate provenance must remain unchanged",
    );
    const aggregate = JSON.parse(
      await readFile(store.iterations[0].resultPath, "utf8"),
    );
    assert.equal(aggregate.scanId, scan.run.scanId);
    assert.equal(aggregate.findings.length, 1);
    assert.ok(aggregate.findings[0].provenance);
    for (const worker of store.workers.values()) {
      if (worker.kind !== "discovery") continue;
      const head = JSON.parse(
        await readFile(
          path.join(worker.artifactDir, "checkpoint-head.json"),
          "utf8",
        ),
      );
      const checkpoint = JSON.parse(
        await readFile(
          path.join(worker.artifactDir, "checkpoints", head.checkpoint),
          "utf8",
        ),
      );
      assert.equal(checkpoint.scanId, scan.run.scanId);
      assert.equal(checkpoint.complete, worker.status === "succeeded");
      assert.equal(checkpoint.findings.length, 1);
      assert.deepEqual(
        checkpoint.findings[0].provenance,
        finding("preserved", "fixture.ts").provenance,
      );
    }
  } finally {
    f.close();
  }
});

for (const cancel of [false, true]) {
  test(`coordinator ${cancel ? "cancellation racing the guard preserves" : "successful resume retains"} saved findings`, async () => {
    const f = await fixture();
    const { fixture: scan, store } = await coordinatorFixture({
      ...config,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 1,
    });
    const executor = f.executor(2);
    let attempts = 0;
    let published: Record<string, unknown> | undefined;
    try {
      const coordinator = createCoordinator(
        scan,
        store,
        {
          async run(request) {
            attempts++;
            const artifacts = await artifactClient(
              request.workingDirectory,
              scan.run.scanId,
            );
            try {
              if (attempts === 1) {
                const saved = await artifacts.call(draftTool, artifacts.draft);
                const failures = await Promise.all(
                  [1, 2].map(() =>
                    artifacts.call(draftTool, {
                      ...artifacts.draft,
                      threatModel: "{}",
                    }),
                  ),
                );
                await f.events([saved, ...failures]);
              } else {
                assert.equal(request.resumeThreadId, "fixture-thread-id");
                // The retry omits the previously saved finding. The real writer
                // must preserve it while accepting completion of source review.
                await f.events([
                  await artifacts.call(draftTool, {
                    ...artifacts.draft,
                    findings: [],
                    complete: true,
                  }),
                ]);
              }
            } finally {
              await artifacts.close();
            }
            return executor.run(request);
          },
        },
        {
          retryDelaysMs: [0],
          onComplete: async (draft: Record<string, unknown>) => {
            published = draft;
          },
        },
      );
      if (cancel)
        f.setOnKill(() =>
          coordinator.cancel("synthetic user cancellation during abort"),
        );
      coordinator.start();
      const terminal = await coordinator.wait(undefined, 10_000);
      assert.equal(
        terminal?.status,
        cancel ? "canceled" : "succeeded",
        terminal?.error,
      );
      assert.equal(attempts, cancel ? 1 : 2);
      assert.equal(f.launches[0].signal.aborted, true);
      const worker = [...store.workers.values()].find(
        (worker) => worker.kind === "discovery",
      )!;
      const head = JSON.parse(
        await readFile(
          path.join(worker.artifactDir, "checkpoint-head.json"),
          "utf8",
        ),
      );
      const checkpoint = JSON.parse(
        await readFile(
          path.join(worker.artifactDir, "checkpoints", head.checkpoint),
          "utf8",
        ),
      );
      assert.equal(checkpoint.findings.length, 1);
      assert.equal(checkpoint.complete, !cancel);
      assert.equal(checkpoint.scanId, scan.run.scanId);
      assert.deepEqual(
        checkpoint.findings[0].provenance,
        finding("preserved", "fixture.ts").provenance,
      );
      if (cancel) {
        assert.equal(published, undefined);
        assert.equal(store.finishCalls.length, 0);
      } else {
        assert.equal(f.launches[1].signal.aborted, false);
        assert.equal((published!.findings as unknown[]).length, 1);
        assert.equal(worker.status, "succeeded");
        assert.equal(worker.attempt, 2);
        assert.equal(store.iterations.length, 1);
      }
    } finally {
      f.close();
    }
  });
}
