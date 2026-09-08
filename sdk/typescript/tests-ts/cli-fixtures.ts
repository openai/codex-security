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
import { ScanResult } from "../src/index.js";
import type { UpdateNotice } from "../src/version.js";

type MainDependencies = NonNullable<Parameters<typeof main>[3]>;

export const SYNTHETIC_CREDENTIALS = [
  "sk-proj-SYNTHETIC_KEY_123",
  "Bearer SYNTHETIC_TOKEN_123",
  "Authorization: Basic SYNTHETIC_BASIC_123",
  "Authorization: Token SYNTHETIC_HEADER_TOKEN_123",
  "Authorization: Bearer%20SYNTHETIC%2FENCODED%2BTOKEN_123",
  "Authorization%3A%20Bearer%20SYNTHETIC_FULLY_ENCODED_TOKEN_123",
  "https://SYNTHETIC_USER:SYNTHETIC_PASSWORD@example.test/private",
  "ssh://SYNTHETIC_USER:SYNTHETIC_SSH_PASSWORD@example.test/private",
  "git+ssh://SYNTHETIC_USER:SYNTHETIC_GIT_PASSWORD@example.test/private",
  "github_pat_SYNTHETIC_GITHUB_PAT_123",
  "ghs_SYNTHETIC_GITHUB_TOKEN_123",
  "OPENAI_API_KEY=SYNTHETIC_OPENAI_VALUE_123",
  "CODEX_API_KEY=SYNTHETIC_CODEX_VALUE_123",
  "CODEX_ACCESS_TOKEN=SYNTHETIC_CODEX_ACCESS_TOKEN_123",
  "GITHUB_TOKEN=SYNTHETIC_GITHUB_VALUE_123",
  "GH_TOKEN=SYNTHETIC_GH_VALUE_123",
  '{"OPENAI_API_KEY":"SYNTHETIC_JSON_OPENAI_123","CODEX_API_KEY":"SYNTHETIC_JSON_CODEX_123"}',
  '{\\"OPENAI_API_KEY\\":\\"SYNTHETIC_ESCAPED_OPENAI_123\\",\\"CODEX_API_KEY\\":\\"SYNTHETIC_ESCAPED_CODEX_123\\"}',
  '{"refresh_token":"SYNTHETIC_REFRESH_TOKEN_123","id_token":"SYNTHETIC_ID_TOKEN_123","clientSecret":"SYNTHETIC_CLIENT_SECRET_123","dbPassword":"SYNTHETIC_PASSWORD_123","passwd":"SYNTHETIC_PASSWD_123"}',
  '{\\"refreshToken\\":\\"SYNTHETIC_ESCAPED_REFRESH_123\\",\\"idToken\\":\\"SYNTHETIC_ESCAPED_ID_123\\",\\"clientSecret\\":\\"SYNTHETIC_ESCAPED_SECRET_123\\",\\"password\\":\\"SYNTHETIC_ESCAPED_PASSWORD_123\\"}',
  "AWS_SECRET_ACCESS_KEY=SYNTHETIC_AWS_SECRET_123",
  "AWS_ACCESS_KEY_ID=SYNTHETIC_AWS_ID_123",
  "AWS_SESSION_TOKEN=SYNTHETIC_AWS_SESSION_123",
  "NODE_AUTH_TOKEN=SYNTHETIC_NODE_AUTH_123",
  "NPM_TOKEN=SYNTHETIC_NPM_TOKEN_123",
  "OPENAI_API_KEY=sk-proj-SYNTHETIC_NAMED_OPENAI_123",
  "GITHUB_TOKEN=ghs_SYNTHETIC_NAMED_GITHUB_123",
  "NPM_TOKEN=npm_SYNTHETIC_NAMED_NPM_123",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN=SYNTHETIC_ACTIONS_TOKEN_123",
  "ACTIONS_RUNTIME_TOKEN=SYNTHETIC_ACTIONS_RUNTIME_123",
  "GITLAB_TOKEN=SYNTHETIC_GITLAB_TOKEN_123",
  "HF_TOKEN=SYNTHETIC_HF_TOKEN_123",
  "SLACK_BOT_TOKEN=SYNTHETIC_SLACK_TOKEN_123",
  "//registry.npmjs.org/:_authToken=SYNTHETIC_NPMRC_TOKEN_123",
  "x-api-key: SYNTHETIC_HEADER_KEY_123",
  "access_token=SYNTHETIC_ACCESS_TOKEN_123",
  "npm_SYNTHETIC_BARE_TOKEN_123",
  "https://example.test/?token=SYNTHETIC_QUERY_123&safe=1",
  "https://example.test/?credential=SYNTHETIC_CREDENTIAL_123&safe=1",
  "https://example.test/?AWS_ACCESS_KEY_ID=SYNTHETIC_QUERY_AWS_ID_123&safe=1",
  "https://example.test/?AWS%5FACCESS%5FKEY%5FID=SYNTHETIC_ENCODED_AWS_ID_123&AWS%2DACCESS%2DKEY%2DID=SYNTHETIC_ENCODED_AWS_DASH_ID_123&safe=1",
  "https://example.test/?service-api-key=SYNTHETIC_QUERY_API_KEY_123&service-access-token=SYNTHETIC_QUERY_ACCESS_TOKEN_123&service-token=SYNTHETIC_QUERY_TOKEN_123&service-secret=SYNTHETIC_QUERY_SECRET_123&signature=SYNTHETIC_SIGNATURE_123&safe=1",
  "https://example.test/?X-Amz-Signature=SYNTHETIC_AMZ_SIGNATURE_123&X-Amz-Credential=SYNTHETIC_AMZ_CREDENTIAL_123&X-Amz-Security-Token=SYNTHETIC_AMZ_TOKEN_123&safe=1",
  "https://example.test/?X-Goog-Signature=SYNTHETIC_GOOG_SIGNATURE_123&X-Goog-Credential=SYNTHETIC_GOOG_CREDENTIAL_123&safe=1",
  "https://example.test/?sv=2026-01-01&sig=SYNTHETIC_AZURE_SIG_123&safe=1",
  "https://example.test/?password=SYNTHETIC_QUERY_PASSWORD_123&passwd=SYNTHETIC_QUERY_PASSWD_123&safe=1",
  "https://example.test/?oauth.refreshToken=SYNTHETIC_DOTTED_TOKEN_123&auth[token]=SYNTHETIC_BRACKET_TOKEN_123&auth%5BclientSecret%5D=SYNTHETIC_ENCODED_SECRET_123&safe=1",
  "https://example.test/?access_token%3DSYNTHETIC_ENCODED_ACCESS_123&client_secret%3DSYNTHETIC_ENCODED_CLIENT_123&safe=1",
  "https://example.test/?redirect_uri=https%3A%2F%2Finner.test%2Fcb%3Frefresh_token%3DSYNTHETIC_NESTED_REFRESH_123%26password%3DSYNTHETIC_NESTED_PASSWORD_123%26safe%3D1",
].join(" ");

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
    onCodex?: (
      ...arguments_: Parameters<MainDependencies["runCodex"]>
    ) => number | Promise<number>;
    linearClient?: MainDependencies["linearClient"];
    importGitHubAlerts?: MainDependencies["importGitHubAlerts"];
    onRepositoryCommand?: (
      ...arguments_: Parameters<MainDependencies["runRepositoryCommand"]>
    ) => string | Promise<string>;
    bulkScan?: MainDependencies["bulkScan"];
    onWorkbench?: (
      args: readonly string[],
      input?: string,
      signal?: AbortSignal,
    ) => JsonObject | Promise<JsonObject>;
    onMatch?: MainDependencies["matchFindings"];
    onUpdateCheck?: (signal: AbortSignal) => Promise<UpdateNotice | undefined>;
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
    checkForUpdate: async (signal) => await options.onUpdateCheck?.(signal),
    currentDirectory: () => options.currentDirectory ?? "/current/repository",
    now: () => 0,
    setInterval: () => ({}) as NodeJS.Timeout,
    clearInterval: () => {},
    addSignalListener: (signal, listener) => signals.add(signal, listener),
    removeSignalListener: (signal, listener) =>
      signals.remove(signal, listener),
    writeSynchronously: (stream, value) => stream.write(value),
    forceExit: () => {},
    runCodex: async (...args) => (await options.onCodex?.(...args)) ?? 0,
    runRepositoryCommand: async (command, args, repository, commandOptions) =>
      (await options.onRepositoryCommand?.(
        command,
        args,
        repository,
        commandOptions,
      )) ?? "",
    ...(options.bulkScan === undefined ? {} : { bulkScan: options.bulkScan }),
    ...(options.linearClient === undefined
      ? {}
      : { linearClient: options.linearClient }),
    ...(options.importGitHubAlerts === undefined
      ? {}
      : { importGitHubAlerts: options.importGitHubAlerts }),
    runWorkbench: async (args, input, signal) =>
      (await options.onWorkbench?.(args, input, signal)) ?? { scans: [] },
    matchFindings: async (input, comparisonOptions) =>
      (await options.onMatch?.(input, comparisonOptions)) ?? {
        matches: [],
        uncertain: [],
      },
    exportFindings: async (arguments_) =>
      new TextEncoder().encode(
        arguments_.format === "csv"
          ? "occurrence_id,finding_id\n"
          : arguments_.format === "json"
            ? '{"documentType":"codex-security.findings"}\n'
            : '{"version":"2.1.0"}\n',
      ),
  };
}
