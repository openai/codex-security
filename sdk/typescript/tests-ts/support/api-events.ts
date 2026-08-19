import { chmod, cp, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { CodexSecurity, runScanEvents } from "../../src/api.js";
import type { ScanOptions } from "../../src/index.js";
import { PLUGIN_ROOT } from "../plugin-root.js";

type PreparedRuntime = Awaited<
  ReturnType<
    NonNullable<
      ConstructorParameters<typeof CodexSecurity>[1]["prepareRuntime"]
    >
  >
>;

export function preparedRuntime(codexHome: string): PreparedRuntime {
  return {
    codexHome,
    plugin: {
      pluginRoot: PLUGIN_ROOT,
      marketplaceRoot: PLUGIN_ROOT,
      installedRoot: PLUGIN_ROOT,
      marketplaceName: "codex-security-sdk",
      name: "codex-security",
      version: "0.1.0",
    },
    environment: {},
    credentialsAvailable: true,
  };
}

export type ScanObserverName = Parameters<
  NonNullable<ScanOptions["onObserverError"]>
>[0];

type ScanEventOptions = Pick<
  Parameters<typeof runScanEvents>[0],
  | "authentication"
  | "expectedFilesTotal"
  | "onActivity"
  | "onObserverError"
  | "onProgress"
  | "onReconnect"
  | "onScanStarted"
  | "onTrustedAccessStatus"
  | "onWarning"
  | "onWorkerStatus"
> & { abortController?: AbortController };

export function createApiTestFixtures() {
  const temporaryDirectories: string[] = [];

  return {
    async cleanup(): Promise<void> {
      await Promise.all(
        temporaryDirectories
          .splice(0)
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    },

    async copyCompletedScan(root: string): Promise<string> {
      const scanDir = join(root, "scan");
      await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
        recursive: true,
      });
      await chmod(scanDir, 0o700);
      await writeFile(join(scanDir, "report.md"), "# Scan report\n");
      return scanDir;
    },

    async temporaryDirectory(): Promise<string> {
      const path = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-api-")),
      );
      temporaryDirectories.push(path);
      return path;
    },
  };
}

export async function* completedEvents(): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: "thread-1" };
  yield { type: "turn.started" };
  yield {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text: "scan complete" },
  };
  yield {
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

export function runEvents(
  scanDir: string,
  events: AsyncGenerator<ThreadEvent>,
  options: ScanEventOptions = {},
): ReturnType<typeof runScanEvents> {
  const { abortController = new AbortController(), ...observers } = options;
  return runScanEvents({
    thread: {
      id: null,
      async runStreamed() {
        return { events };
      },
    },
    events,
    signal: abortController.signal,
    scanDir,
    pluginRoot: PLUGIN_ROOT,
    model: "gpt-5.6-sol",
    ...observers,
    expectation: {
      repository: "/repository",
      repositoryRevision: "deadbeef",
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
    },
  });
}
