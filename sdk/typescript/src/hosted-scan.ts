import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { readScanFile } from "./contract.js";
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
import { relative, resolve, sep } from "node:path";
import { z } from "zod";
import { CodexSecurity } from "./api.js";
import {
  IncompleteScanError,
  ScanInterruptedError,
  errorMessage,
} from "./errors.js";
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
  reasoningEffort: z.enum(["low", "medium", "high", "xhigh"]),
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
  const selected = path.trim();
  if (
    /^[\\/]|^[a-z]:/i.test(selected) ||
    /[\\*?\[\]{},\u0000-\u001f\u007f]/u.test(path) ||
    selected.split("/").includes("..")
  ) {
    throw new HostedScanPreparationError(
      "scope_syntax",
      "Use literal repository-relative folders or files without traversal, globs, or comma-separated lists.",
    );
  }
  const normalized = selected
    .split("/")
    .filter((part) => part !== "" && part !== ".")
    .join("/");
  return normalized || ".";
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
  const repository = await normalizeRepository(input.repository);
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
    ...(request === undefined
      ? {}
      : {
          scanId: request.scanId,
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
      onOutputDirReady(path) {
        outputDirectory = path;
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
      (await repositoryRevision(context.repository, options.signal)) !==
        context.revision
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
      status:
        result.coverage.completeness === "complete"
          ? ("completed" as const)
          : ("incomplete" as const),
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
            : error instanceof IncompleteScanError
              ? ("incomplete" as const)
              : ("failed" as const),
      error: errorMessage(error),
      artifacts: [],
    };
  } finally {
    await client.close();
  }
}

export type HostedScanResult = Awaited<ReturnType<typeof runHostedScan>>;
