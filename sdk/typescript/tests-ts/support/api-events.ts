export { createApiTestFixtures } from "./temporary-directories.js";

import { cp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions, ThreadEvent } from "@openai/codex-sdk";
import { CodexSecurity } from "../../src/api.js";
import { runScanTurn } from "../../src/scan-events.js";
import type { ScanOptions } from "../../src/index.js";
import { PLUGIN_ROOT, copyCompletedScan } from "../plugin-root.js";

type PreparedRuntime = Awaited<
  ReturnType<
    NonNullable<
      NonNullable<
        ConstructorParameters<typeof CodexSecurity>[1]
      >["prepareRuntime"]
    >
  >
>;

export function preparedRuntime(
  codexHome: string,
  marketplaceRoot = PLUGIN_ROOT,
): PreparedRuntime {
  return {
    codexHome,
    plugin: {
      pluginRoot: PLUGIN_ROOT,
      marketplaceRoot,
      installedRoot: PLUGIN_ROOT,
      marketplaceName: "codex-security-sdk",
      name: "codex-security",
      version: "0.1.0",
    },
    environment: {},
    credentialsAvailable: true,
  };
}

export async function copyPluginVariant(
  directory: string,
  marker: string,
): Promise<string> {
  const root = join(directory, marker);
  await cp(PLUGIN_ROOT, root, { recursive: true });
  await writeFile(
    join(root, ".codex-plugin", "plugin.json"),
    JSON.stringify({
      name: "codex-security",
      version: "0.1.0",
      skills: "./skills/",
      mcpServers: "./.mcp.json",
    }),
  );
  await writeFile(
    join(root, ".mcp.json"),
    JSON.stringify({
      mcpServers: {
        "synthetic-plugin": { command: process.execPath, args: [marker] },
      },
    }),
  );
  return root;
}

export function scanRuntimeDependencies(codexHome: string, scanDir: string) {
  return {
    prepareRuntime: async () => preparedRuntime(codexHome),
    resolvePluginPython: async () => "/managed/python",
    prepareOutputDir: async () => scanDir,
    repositoryRevision: async () => "deadbeef",
  };
}

export type ScanObserverName = Parameters<
  NonNullable<ScanOptions["onObserverError"]>
>[0];

type ScanEventOptions = Omit<
  Parameters<typeof runScanTurn>[0],
  "thread" | "events" | "signal" | "scanDir" | "repository" | "model"
> & { abortController?: AbortController };

export function completedTurn(): Extract<
  ThreadEvent,
  { type: "turn.completed" }
> {
  return {
    type: "turn.completed",
    usage: {
      input_tokens: 10,
      cached_input_tokens: 2,
      cache_write_input_tokens: 0,
      output_tokens: 3,
      reasoning_output_tokens: 1,
    },
  };
}

export async function* completedEvents(
  threadId = "thread-1",
  events?: AsyncIterable<ThreadEvent>,
): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: threadId };
  yield { type: "turn.started" };
  if (events) yield* events;
  else {
    yield {
      type: "item.completed",
      item: { id: "message-1", type: "agent_message", text: "scan complete" },
    };
  }
  yield completedTurn();
}

export function runEvents(
  scanDir: string,
  events: AsyncGenerator<ThreadEvent>,
  options: ScanEventOptions = {},
): ReturnType<typeof runScanTurn> {
  const { abortController = new AbortController(), ...observers } = options;
  return runScanTurn({
    thread: { id: null },
    events,
    signal: (options.abortController ?? new AbortController()).signal,
    scanDir,
    model: "gpt-5.6-sol",
    ...observers,
    repository: "/repository",
  });
}

export async function* failedEvents(): AsyncGenerator<ThreadEvent> {
  yield {
    type: "turn.failed",
    error: { message: "Could not draft fixes." },
  };
}

export function completedCodex(root: string, threadId: string | null = null) {
  return (_options: CodexOptions) => ({
    startThread: () => ({
      id: threadId,
      async runStreamed() {
        await copyCompletedScan(root);
        return { events: completedEvents() };
      },
    }),
  });
}

export function collectObserverErrors(errors: [ScanObserverName, string][]) {
  return (observer: ScanObserverName, error: unknown) => {
    errors.push([observer, (error as Error).message]);
  };
}

export function codexFactory<Run>(
  runStreamed: Run,
  threadId: string | null = null,
) {
  return () => ({
    startThread: () => ({ id: threadId, runStreamed }),
  });
}

export const failedPostScanEvents = failedEvents;
