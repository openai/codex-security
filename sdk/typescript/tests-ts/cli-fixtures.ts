import { lstat, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { main } from "../src/cli.js";
import type {
  CodexSecurity,
  CodexSecurityConfig,
  CoverageDocument,
  FindingsDocument,
  JsonObject,
  ScanActivity,
  ScanCost,
  ScanManifest,
  ScanOptions,
  ScanPreflight,
  ScanProgress,
  ScanWorkerStatus,
  SeverityLevel,
} from "../src/index.js";
import { CodexSecurityError, ScanResult } from "../src/index.js";
import type { UpdateNotice } from "../src/version.js";

type MainDependencies = NonNullable<Parameters<typeof main>[3]>;

export const SYNTHETIC_CREDENTIALS = "sk-proj-SYNTHETIC_KEY_123";

export function capture(isTTY = false): {
  stream: Pick<NodeJS.WriteStream, "write"> &
    Partial<Pick<NodeJS.WriteStream, "isTTY">>;
  text(): string;
} {
  let value = "";
  return {
    stream: {
      isTTY,
      write(chunk: string | Uint8Array): boolean {
        value += chunk.toString();
        return true;
      },
    },
    text: () => value,
  };
}

export function fakePreflight(
  repository = "/current/repository",
): ScanPreflight {
  return {
    repository,
    target: { kind: "repository", paths: [] },
    mode: "standard",
    outputDir: null,
    authentication: { method: "stored_credentials", verified: false },
    model: "gpt-5.6-sol",
    reasoningEffort: "xhigh",
  };
}

export function fakeResult(
  severityLevels: readonly SeverityLevel[] = [],
  completeness: CoverageDocument["completeness"] = "complete",
  usage: unknown = null,
): ScanResult {
  const manifest = {
    documentType: "codex-security.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: "scan",
      producer: { name: "codex-security-plugin", version: "1.2.3" },
      status: "completed",
      startedAt: "2026-01-01T00:00:00Z",
      completedAt: "2026-01-01T00:00:01Z",
      sealedAt: "2026-01-01T00:00:01Z",
      target: {
        kind: "directory_snapshot",
        targetId: "id",
        displayName: "repo",
      },
      scope: { includePaths: ["."], excludePaths: [] },
      coverageRef: "coverage.json",
      findingsRef: "findings.json",
      artifacts: [],
    },
  } satisfies ScanManifest;
  const findings = {
    documentType: "codex-security.findings",
    schemaVersion: "1.0",
    scanId: "scan",
    findings: severityLevels.map((level) => ({
      severity: { level },
    })) as FindingsDocument["findings"],
  } satisfies FindingsDocument;
  const coverage = {
    documentType: "codex-security.coverage",
    schemaVersion: "1.0",
    scanId: "scan",
    mode: "repository",
    completeness,
    inventoryStrategy: "repository",
    includePaths: ["."],
    excludePaths: [],
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  } satisfies CoverageDocument;
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir: "/tmp/scan",
    threadId: "thread-1",
    turnResult: {
      status: "completed",
      model: "gpt-5.6-sol",
      finalResponse: "done",
      usage,
    },
  });
}

export class FakeSignals {
  readonly listeners = new Map<string, Set<() => void>>();

  public add(signal: string, listener: () => void): void {
    const listeners = this.listeners.get(signal) ?? new Set();
    listeners.add(listener);
    this.listeners.set(signal, listeners);
  }

  public remove(signal: string, listener: () => void): void {
    this.listeners.get(signal)?.delete(listener);
  }

  public emit(signal: string): void {
    for (const listener of this.listeners.get(signal) ?? []) listener();
  }
}

export function dependencies(
  options: {
    onConfig?: (config: CodexSecurityConfig) => void;
    onTurn?: (repository: string, options: unknown) => void;
    onRun?: () => void;
    onInterrupt?: () => void;
    onClose?: () => void | Promise<void>;
    onCodex?: (args: readonly string[]) => number;
    bulkScan?: MainDependencies["bulkScan"];
    onWorkbench?: (args: readonly string[]) => JsonObject | Promise<JsonObject>;
    onMatch?: MainDependencies["matchFindings"];
    onUpdateCheck?: () => Promise<UpdateNotice | undefined>;
    currentDirectory?: string;
    preflight?: ScanPreflight;
    environment?: NodeJS.ProcessEnv;
    signals?: FakeSignals;
    result?: ScanResult;
    activities?: ScanActivity[];
    costUpdates?: ScanCost[];
    scanProgress?: ScanProgress[];
    workerStatuses?: ScanWorkerStatus[];
  } = {},
): MainDependencies {
  const signals = options.signals ?? new FakeSignals();
  const result = options.result ?? fakeResult();
  const security = {
    run: async (repository: string, runOptions: ScanOptions) => {
      options.onTurn?.(repository, runOptions);
      const signal = runOptions.signal;
      signal?.addEventListener("abort", () => options.onInterrupt?.(), {
        once: true,
      });
      options.onRun?.();
      if (!signal?.aborted) {
        runOptions.onScanStarted?.();
        for (const activity of options.activities ?? []) {
          runOptions.onActivity?.(activity);
        }
        for (const cost of options.costUpdates ?? []) {
          runOptions.onCost?.(cost);
        }
        for (const progress of options.scanProgress ?? []) {
          runOptions.onProgress?.(progress);
        }
        for (const status of options.workerStatuses ?? []) {
          runOptions.onWorkerStatus?.(status);
        }
      }
      return result;
    },
    preflight: async (repository: string) =>
      options.preflight ?? fakePreflight(repository),
    close: async () => await options.onClose?.(),
  } as Pick<CodexSecurity, "run" | "preflight" | "close">;
  return {
    createSecurity: (config) => {
      options.onConfig?.(config);
      return security;
    },
    environment: options.environment ?? {},
    checkForUpdate: async () => await options.onUpdateCheck?.(),
    currentDirectory: () => options.currentDirectory ?? "/current/repository",
    now: () => 0,
    setInterval: () => ({}) as NodeJS.Timeout,
    clearInterval: () => {},
    addSignalListener: (signal, listener) => signals.add(signal, listener),
    removeSignalListener: (signal, listener) =>
      signals.remove(signal, listener),
    writeSynchronously: (stream, value) => stream.write(value),
    forceExit: () => {},
    runCodex: async (args) => options.onCodex?.(args) ?? 0,
    ...(options.bulkScan === undefined ? {} : { bulkScan: options.bulkScan }),
    runWorkbench: async (args) =>
      (await options.onWorkbench?.(args)) ?? { scans: [] },
    matchFindings: async (input) =>
      (await options.onMatch?.(input)) ?? { matches: [], uncertain: [] },
    exportFindings: async (arguments_) => {
      const contents = new TextEncoder().encode(
        arguments_.format === "csv"
          ? "occurrence_id,finding_id\n"
          : arguments_.format === "json"
            ? '{"documentType":"codex-security.findings"}\n'
            : '{"version":"2.1.0"}\n',
      );
      if (arguments_.output !== "-") {
        const metadata = await lstat(arguments_.output).catch(() => undefined);
        if (metadata?.isSymbolicLink()) {
          throw new CodexSecurityError(
            "results.sarif: expected a regular non-symlink file",
          );
        }
        await mkdir(join(arguments_.output, ".."), { recursive: true });
        await writeFile(arguments_.output, contents, { mode: 0o600 });
      }
      return contents;
    },
  };
}
