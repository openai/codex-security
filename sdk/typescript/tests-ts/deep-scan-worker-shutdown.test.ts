import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { brotliDecompressSync } from "node:zlib";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("settles completed bundled Deep Scan workers without retaining parent cancellation", async () => {
  const chunks = await Promise.all(
    ["000", "001"].map((part) =>
      readFile(join(PLUGIN_ROOT, "mcp", `server.mjs.br.part-${part}`)),
    ),
  );
  const runtime = brotliDecompressSync(Buffer.concat(chunks)).toString("utf8");
  const source = /var CodexSdkWorkerExecutor = class \{[\s\S]*?\n\};/u.exec(
    runtime,
  )?.[0];
  if (source === undefined) {
    throw new Error("Bundled Deep Scan worker executor was not found.");
  }

  let workerSignal: AbortSignal | undefined;
  let iteratorClosed = false;
  class FakeCodex {
    startThread() {
      return {
        id: "fixture-worker-thread",
        async runStreamed(_input: string, options: { signal: AbortSignal }) {
          workerSignal = options.signal;
          return {
            events: (async function* () {
              try {
                yield {
                  type: "thread.started",
                  thread_id: "fixture-worker-thread",
                };
                yield {
                  type: "item.completed",
                  item: { type: "agent_message", text: "worker completed" },
                };
                yield { type: "turn.completed" };
                await new Promise<void>(() => {});
              } finally {
                iteratorClosed = true;
              }
            })(),
          };
        },
      };
    }
  }

  const WorkerExecutor = new Function(
    "Codex",
    "import_node_fs11",
    "assertVerifiedParentSandbox",
    "resolveCodexPath",
    "workerSubagentConfig",
    "appendSafeItemDiagnostic",
    "classifyCodexWorkerError",
    `${source}\nreturn CodexSdkWorkerExecutor;`,
  )(
    FakeCodex,
    { promises: { readFile: async () => "fixture worker prompt" } },
    () => {},
    () => "/fixture/codex",
    () => ({}),
    () => {},
    (error: unknown) => error,
  );
  const parentController = new AbortController();
  const timeout = setTimeout(() => {
    parentController.abort("completed bundled worker remained pending");
  }, 1_000);

  try {
    const result = await new WorkerExecutor({
      parentSandbox: { filesystem: "workspace-write", network: "restricted" },
    }).run({
      kind: "discovery",
      promptPath: "/fixture/prompt.md",
      workingDirectory: "/fixture/artifacts",
      subagents: 0,
      signal: parentController.signal,
    });

    expect(result).toEqual({
      finalResponse: "worker completed",
      threadId: "fixture-worker-thread",
    });
    expect(iteratorClosed).toBe(true);
    expect(workerSignal).not.toBe(parentController.signal);

    parentController.abort("coordinator canceled its remaining workers");
    expect(workerSignal?.aborted).toBe(false);
  } finally {
    clearTimeout(timeout);
  }
});
