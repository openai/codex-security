import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { readScanFile, safeScopePath } from "./contract.js";
import { isRecord } from "./record.js";
import { VERSION } from "./version.js";
import {
  ScanExecutionError,
  type ScanExecutor,
  type ScanExecutionResult,
  type ScanExecutionEvent,
  type ScanExecutionRequest,
} from "./scan-executor.js";
export type { ScanExecutor, ScanExecutionRequest } from "./scan-executor.js";
import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { CodexSecurity } from "./api.js";
import { ScanInterruptedError, errorMessage } from "./errors.js";
import { normalizeRepository, repositoryRevision } from "./targets.js";
import { isWithin } from "./trusted-executable.js";

/** Hosted v2 mirrors repository/paths targets; only Standard scans are supported. */
export const HostedScanInputSchema = z.strictObject({
  version: z.literal(2),
  repository: z.string().min(1),
  revision: z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/),
  scope: z
    .strictObject({ paths: z.array(z.string().min(1)).min(1) })
    .optional(),
  outputDirectory: z.string().min(1),
  stateDirectory: z.string().min(1),
  model: z.string().min(1),
  reasoningEffort: z.string(),
  ownerSuggestions: z.boolean().optional(),
  identity: z.strictObject({
    runId: z.string().min(1),
    attemptId: z.string().min(1),
    buildId: z.string().min(1),
  }),
});

export type HostedScanInput = z.infer<typeof HostedScanInputSchema>;
export class HostedScanPreparationError extends Error {
  constructor(
    readonly reason:
      | "scope_syntax"
      | "scope_missing"
      | "scope_outside_repository"
      | "scope_alias"
      | "revision_mismatch",
    message: string,
  ) {
    super(message);
    this.name = "HostedScanPreparationError";
  }
}

export function normalizeHostedScope(path: string): string {
  const parts = path.split(process.platform === "win32" ? /[/\\]/ : "/");
  if (
    path.length === 0 ||
    path.includes("\0") ||
    isAbsolute(path) ||
    (process.platform === "win32" && /^[a-z]:/i.test(path)) ||
    parts.includes("..")
  ) {
    throw new HostedScanPreparationError(
      "scope_syntax",
      "Use non-empty repository-relative folders or files without parent traversal or NUL characters.",
    );
  }
  const normalized = parts
    .filter((part) => part !== "" && part !== ".")
    .join("/");
  try {
    return safeScopePath(normalized || ".");
  } catch {
    throw new HostedScanPreparationError(
      "scope_syntax",
      `${JSON.stringify(path)} cannot be used as scan scope: the output contract requires UTF-8 repository-relative paths without drive prefixes, backslashes, or control characters.`,
    );
  }
}

function comparePaths(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

export function normalizeHostedPaths(
  paths: readonly string[] = ["."],
): string[] {
  if (paths.length === 0)
    throw new HostedScanPreparationError(
      "scope_syntax",
      "An explicit path scope must not be empty. Omit scope to scan the repository.",
    );
  const normalized = [...new Set(paths.map(normalizeHostedScope))].sort(
    comparePaths,
  );
  if (normalized.length > 1 && normalized.includes("."))
    throw new HostedScanPreparationError(
      "scope_syntax",
      "Repository scope cannot be mixed with narrower paths.",
    );
  return normalized;
}

/** Validate every path at the frozen commit before registering a scan/executing. */
async function prepareHostedScan(input: HostedScanInput, signal?: AbortSignal) {
  const scope = { paths: normalizeHostedPaths(input.scope?.paths) };
  const repository = await normalizeRepository(input.repository, signal);
  if ((await repositoryRevision(repository, signal)) !== input.revision)
    throw new HostedScanPreparationError(
      "revision_mismatch",
      "Checkout does not match the frozen revision.",
    );
  for (const path of scope.paths) {
    const selected = resolve(repository, path);
    let target: string;
    try {
      target = await realpath(selected);
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "ENOENT"
      )
        throw error;
      throw new HostedScanPreparationError(
        "scope_missing",
        `${path} does not exist at the selected revision. Update the paths and start a new scan.`,
      );
    }
    if (!isWithin(repository, target))
      throw new HostedScanPreparationError(
        "scope_outside_repository",
        `${path} resolves outside the repository.`,
      );
    if (target !== selected) {
      const canonical =
        relative(repository, target).split(sep).join("/") || ".";
      throw new HostedScanPreparationError(
        "scope_alias",
        `${path} resolves to ${canonical}. Use the canonical repository path and start a new scan.`,
      );
    }
  }
  return {
    repository,
    revision: input.revision,
    scope,
    identity: input.identity,
  };
}

function hostedScanEnvironment(stateDirectory: string): Record<string, string> {
  const environment: Record<string, string> = {
    PATH: process.env["PATH"] ?? "",
    CODEX_SECURITY_STATE_DIR: resolve(stateDirectory),
  };
  for (const key of [
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "TMPDIR",
    "TEMP",
    "TMP",
  ])
    if (process.env[key] !== undefined) environment[key] = process.env[key]!;
  return environment;
}

export interface HostedScanOptions {
  executor: ScanExecutor;
  /** @deprecated Automatic owner reports validate scan hints without additional inference. */
  ownerCodex?: {
    startThread(options: { model?: string; modelReasoningEffort?: string }): {
      run(
        input: string,
        options: { outputSchema?: unknown; signal?: AbortSignal },
      ): Promise<{ finalResponse: string }>;
    };
  };
  signal?: AbortSignal;
  onEvent?: (event: ScanExecutionEvent) => void;
}

/** One invocation, with only scan-domain state. The host decides retry/reconciliation. */
export async function runHostedScan(
  value: HostedScanInput,
  options: HostedScanOptions,
) {
  const input = HostedScanInputSchema.parse(value);
  const context = await prepareHostedScan(input, options.signal);
  let execution: ScanExecutionResult | undefined;
  let request: ScanExecutionRequest | undefined;
  let scanId: string | undefined;
  const onEvent = (event: ScanExecutionEvent): void => {
    void Promise.resolve()
      .then(() => options.onEvent?.(event))
      .catch(() => {});
  };
  const client = new CodexSecurity(
    {
      codexOverrides: {
        model: input.model,
        model_reasoning_effort: input.reasoningEffort,
      },
    },
    {
      environment: hostedScanEnvironment(input.stateDirectory),
      hostedScan: {
        context,
        executor: {
          async run(value, runOptions) {
            request = value;
            execution = await options.executor.run(value, runOptions);
            return execution;
          },
        },
        onEvent,
      },
      createCodex() {
        throw new Error("Local inference is unavailable in hosted mode.");
      },
    },
    { surface: "sdk" },
  );
  let outputDirectory = resolve(input.outputDirectory);
  const base = () => ({
    version: 2 as const,
    ...context,
    outputDirectory,
    ...(scanId === undefined ? {} : { scanId }),
    ...(request === undefined
      ? {}
      : {
          pluginVersion: request.runtime.pluginVersion,
        }),
    provenance: {
      cliVersion: VERSION,
      buildId: input.identity.buildId,
      ...(request === undefined
        ? {}
        : { pluginVersion: request.runtime.pluginVersion }),
    },
    ...(execution === undefined ? {} : { execution }),
  });
  try {
    const result = await client.run(context.repository, {
      target:
        context.scope.paths[0] === "."
          ? "repository"
          : context.scope.paths.map((path) => `./${path}`),
      mode: "standard",
      outputDir: outputDirectory,
      signal: options.signal,
      ownerSuggestions: input.ownerSuggestions,
      onOutputDirReady(path) {
        outputDirectory = path;
      },
      onScanRegistered(scan) {
        scanId = scan.scanId;
        outputDirectory = scan.scanDir;
      },
      onProgress(progress) {
        onEvent({ type: "progress", progress });
      },
      onActivity(activity) {
        onEvent({ type: "activity", activity });
      },
    });
    if (
      result.manifest.scan.target.revision !== context.revision ||
      // Owner cancellation cannot invalidate an already sealed base scan.
      (await repositoryRevision(context.repository)) !== context.revision
    )
      throw new Error(
        "Checkout changed from the frozen revision during execution.",
      );
    if (
      !isDeepStrictEqual(
        [...result.manifest.scan.scope.includePaths].sort(comparePaths),
        context.scope.paths,
      ) ||
      result.manifest.scan.scope.excludePaths.length !== 0
    )
      throw new Error("Completed artifacts do not match the requested scope.");
    const sources = result.manifest.scan["preservedSources"];
    const names = new Set([
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      ...result.manifest.scan.artifacts.map((artifact) => artifact.path),
      ...(isRecord(sources) ? Object.keys(sources) : []),
    ]);
    if (result.ownerSuggestionsPath !== undefined)
      names.add("owner-suggestions.json");
    const artifacts = await Promise.all(
      [...names].sort().map(async (path) => {
        const contents = await readScanFile(outputDirectory, path, path);
        return {
          path,
          sha256: createHash("sha256").update(contents).digest("hex"),
          bytes: Buffer.byteLength(contents),
        };
      }),
    );
    return {
      ...base(),
      status: "completed" as const,
      ...(result.ownerSuggestionsError === undefined
        ? {}
        : { ownerSuggestionsError: result.ownerSuggestionsError }),
      artifacts,
    };
  } catch (error) {
    if (error instanceof ScanExecutionError) execution = error.result;
    return {
      ...base(),
      status:
        execution?.status === "acceptance_unknown"
          ? ("acceptance_unknown" as const)
          : options.signal?.aborted ||
              execution?.status === "canceled" ||
              error instanceof ScanInterruptedError
            ? ("canceled" as const)
            : ("failed" as const),
      error: errorMessage(error),
      artifacts: [],
    };
  } finally {
    try {
      await client.close();
    } catch (error) {
      onEvent({
        type: "activity",
        activity: {
          id: "runtime.cleanup",
          kind: "message",
          status: "failed",
          description: `Hosted scan cleanup failed: ${errorMessage(error)}`,
          paths: [],
        },
      });
    }
  }
}

export type HostedScanResult = Awaited<ReturnType<typeof runHostedScan>>;
