import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, expect, mock, test } from "bun:test";
import { copyCompletedScan } from "./plugin-root.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  codexFactory,
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { completedCommand, writeSession } from "./support/usage-rollout.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

async function fixture(
  options: {
    failTurn?: boolean;
    abortOnStreamCleanup?: AbortController;
    abortPostScan?: AbortController;
    failWriter?: "prepare" | "write";
    worker?: boolean;
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "home");
  const scanDir = join(root, "scan");
  await Promise.all([mkdir(repository), mkdir(codexHome), mkdir(scanDir)]);
  const source = "export const token = 'SYNTHETIC_DIAGNOSTIC';\n";
  await writeFile(join(repository, "source.ts"), source);
  const artifacts: Map<string, string>[] = [];
  const recipes: Record<string, unknown>[] = [];
  let run = 0;
  let parentSessionPath: string | undefined;
  const prepareWriter = mock(async () => {
    if (options.failWriter === "prepare")
      throw new Error("Synthetic preparation failure");
    const files = new Map<string, string>();
    artifacts.push(files);
    return {
      restore: async (name: string, contents: Uint8Array) => {
        if (options.failWriter === "write")
          throw new Error("Synthetic write failure");
        files.set(name, new TextDecoder().decode(contents));
      },
    };
  });
  const client = TestClient.withDependencies({
    ...scanRuntimeDependencies(codexHome, scanDir),
    prepareScanArtifactRestorer: prepareWriter,
    runWorkbench: async (_options, args, input) => {
      if (args[0] === "register-cli-scan")
        recipes.push(JSON.parse(input!).recipe);
      return mockWorkbench(args, input);
    },
    createCodex: codexFactory(async () => {
      const threadId = `thread-${++run}`;
      if (run > 1 && options.abortPostScan !== undefined) {
        const postScanSource = "export const postScan = 'POST_SCAN_ONLY';\n";
        await writeFile(join(repository, "post-scan.ts"), postScanSource);
        await appendFile(
          parentSessionPath!,
          [
            {
              type: "response_item",
              payload: {
                type: "function_call",
                name: "exec_command",
                call_id: "post-scan-read",
                arguments: JSON.stringify({
                  cmd: "cat post-scan.ts",
                  workdir: repository,
                }),
              },
            },
            {
              type: "response_item",
              payload: {
                type: "function_call_output",
                call_id: "post-scan-read",
                output: postScanSource,
              },
            },
          ]
            .map((event) => JSON.stringify(event))
            .join("\n") + "\n",
        );
        options.abortPostScan.abort(new Error("Synthetic post-scan abort"));
        return { events: completedEvents("thread-1") };
      }
      await copyCompletedScan(root);
      for (const [id, parent] of [
        [threadId, undefined],
        ...(options.worker ? [[`worker-${run}`, threadId]] : []),
        [`unrelated-${run}`, undefined],
      ] as const) {
        const path = await writeSession(
          codexHome,
          id!,
          {},
          { parent, cwd: scanDir },
        );
        if (id === threadId) parentSessionPath = path;
        await appendFile(
          path,
          [
            {
              type: "response_item",
              payload: {
                type: "function_call",
                name: "exec_command",
                call_id: "read-source",
                arguments: JSON.stringify({
                  cmd: "cat source.ts",
                  workdir: repository,
                }),
              },
            },
            {
              type: "response_item",
              payload: {
                type: "function_call_output",
                call_id: "read-source",
                output: id!.startsWith("unrelated")
                  ? "UNRELATED_SCAN_OUTPUT"
                  : source,
              },
            },
          ]
            .map((event) => JSON.stringify(event))
            .join("\n") + "\n",
        );
      }
      async function* events(): AsyncGenerator<ThreadEvent> {
        try {
          yield completedCommand(
            "cat source.ts",
            `CAPTURED_PROCESS_${run}`,
            `command-${run}`,
          );
          yield {
            type: "item.completed",
            item: {
              type: "reasoning",
              id: `summary-${run}`,
              text: `PUBLIC_SUMMARY_${run}`,
            },
          };
          if (options.failTurn)
            yield {
              type: "turn.failed",
              error: { message: "Synthetic turn failure" },
            };
        } finally {
          options.abortOnStreamCleanup?.abort(
            new Error("Synthetic cleanup abort"),
          );
        }
      }
      return { events: completedEvents(threadId, events()) };
    }),
  });
  return { client, repository, artifacts, prepareWriter, recipes };
}

function savedTrace(files: Map<string, string>) {
  const events = [...files].find(([name]) => name.endsWith(".jsonl"));
  const summary = [...files].find(([name]) => name.endsWith(".json"));
  expect(events?.[0]).toMatch(/^scan-diagnostics-.*\.jsonl$/u);
  expect(summary?.[0]).toMatch(/^scan-diagnostics-.*\.json$/u);
  return { events: events![1], summary: JSON.parse(summary![1]) };
}

test("opted-in scans retain SDK output and owned worker tool responses even when an observer fails", async () => {
  const state = await fixture({ worker: true });
  await using client = state.client;
  const observerErrors: string[] = [];
  const result = await client.run(state.repository, {
    diagnostics: true,
    onSessionEvent: () => {
      throw new Error("Synthetic observer failure");
    },
    onObserverError: (observer) => observerErrors.push(observer),
  });
  expect(result.turnResult.status).toBe("completed");
  expect(state.prepareWriter).toHaveBeenCalledTimes(1);
  const trace = savedTrace(state.artifacts[0]!);
  expect(trace.events).toContain("CAPTURED_PROCESS_1");
  expect(trace.events).toContain("SYNTHETIC_DIAGNOSTIC");
  expect(trace.events).toContain("PUBLIC_SUMMARY_1");
  expect(trace.events).toContain('"threadId":"worker-1"');
  expect(trace.events).not.toContain("UNRELATED_SCAN_OUTPUT");
  expect(trace.summary.termination).toMatchObject({
    status: "completed",
    turnStatus: "completed",
  });
  expect(trace.summary.modelExecutionCapture).toMatchObject({
    requestedByDiagnostics: false,
    serverStatus: "unverified",
  });
  expect(observerErrors).toContain("onSessionEvent");
});

test("diagnostics stay off by default and do not persist into a subsequent scan or its recipe", async () => {
  const state = await fixture();
  await using client = state.client;
  await client.run(state.repository);
  expect(state.prepareWriter).not.toHaveBeenCalled();
  await client.run(state.repository, { diagnostics: true });
  await client.run(state.repository);
  expect(state.prepareWriter).toHaveBeenCalledTimes(1);
  const trace = savedTrace(state.artifacts[0]!);
  expect(trace.events).toContain("CAPTURED_PROCESS_2");
  expect(trace.events).not.toContain("CAPTURED_PROCESS_1");
  expect(trace.events).not.toContain("CAPTURED_PROCESS_3");
  for (const recipe of state.recipes)
    expect(recipe).not.toHaveProperty("diagnostics");
});

test("failed turns retain their diagnostic evidence and failure metadata", async () => {
  const state = await fixture({ failTurn: true });
  await using client = state.client;
  await expect(
    client.run(state.repository, { diagnostics: true }),
  ).rejects.toThrow("Synthetic turn failure");
  const trace = savedTrace(state.artifacts[0]!);
  expect(trace.events).toContain("SYNTHETIC_DIAGNOSTIC");
  expect(trace.summary.termination).toMatchObject({
    status: "failed",
    turnStatus: "failed",
    stopReason: "turn_failed",
    error: "Synthetic turn failure",
  });
});

test.each(["prepare", "write"] as const)(
  "optional diagnostic %s failures do not discard the scan result",
  async (failWriter) => {
    const state = await fixture({ failWriter });
    await using client = state.client;
    const warnings: string[] = [];
    const result = await client.run(state.repository, {
      diagnostics: true,
      onWarning: (warning) => warnings.push(warning),
    });
    expect(result.turnResult.status).toBe("completed");
    expect(
      warnings.some(
        (warning) =>
          warning.includes("scan diagnostics") && warning.includes("Synthetic"),
      ),
    ).toBe(true);
  },
);

test("a caller abort during failed-stream cleanup does not replace the recorded turn failure", async () => {
  const controller = new AbortController();
  const state = await fixture({
    failTurn: true,
    abortOnStreamCleanup: controller,
  });
  await using client = state.client;
  await expect(
    client.run(state.repository, {
      diagnostics: true,
      signal: controller.signal,
    }),
  ).rejects.toThrow();
  expect(controller.signal.aborted).toBe(true);
  const trace = savedTrace(state.artifacts[0]!);
  expect(trace.summary.termination).toMatchObject({
    status: "failed",
    turnStatus: "failed",
    stopReason: "turn_failed",
    error: "Synthetic turn failure",
  });
});

test("an aborted post-scan turn does not enter scan diagnostics during failure cleanup", async () => {
  const controller = new AbortController();
  const state = await fixture({ abortPostScan: controller });
  await using client = state.client;
  const observed: string[] = [];
  await expect(
    client.run(state.repository, {
      diagnostics: true,
      postScanPrompt: "Summarize the completed scan.",
      signal: controller.signal,
      onSessionEvent: ({ event }) => observed.push(JSON.stringify(event)),
    }),
  ).rejects.toThrow();
  expect(controller.signal.aborted).toBe(true);
  // Failure cleanup rereads the parent rollout after the post-scan turn.
  expect(observed.join("\n")).toContain("POST_SCAN_ONLY");
  const trace = savedTrace(state.artifacts[0]!);
  expect(trace.events).toContain("SYNTHETIC_DIAGNOSTIC");
  expect(trace.events).not.toContain("POST_SCAN_ONLY");
  expect(trace.events).not.toContain("post-scan-read");
  expect(
    trace.summary.coverage.files.map((file: { path: string }) => file.path),
  ).toEqual(["source.ts"]);
});
