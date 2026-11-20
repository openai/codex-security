import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { open, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { retryWindowsRename } from "./retry-windows-rename.js";
import { renderScaReport } from "./sca-report.js";
import type { OsvScanResult } from "./sca-osv.js";
import type { ScaMatch, ScaResult } from "./sca-types.js";
import { gitMarkerRoot, isolatedGitEnvironment } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

/** Observed dependency scan work, independent of the persisted result status. */
export type DependencyScanProgress =
  | { phase: "preparing" | "discovering" | "preparing_assessment" | "saving" }
  | {
      phase: "matching";
      inputsTotal: number;
      /** OSV invocations that have finished, including failed invocations. */
      inputsProcessed: number;
      /** Failed selected inputs, including failures before an invocation starts. */
      inputsFailed: number;
      currentInput: string | null;
      components: number;
      matches: number;
    }
  | {
      phase: "assessing";
      assessmentsTotal: number;
      /** Saved assessments, including needs_review verdicts. */
      assessmentsCompleted: number;
      assessmentsFailed: number;
      current: {
        matchId: string;
        componentId: string;
        packageName: string | null;
        packageVersion: string | null;
        advisoryIds: readonly string[];
      } | null;
    };

export function assessmentProgress(
  result: ScaResult,
  match: ScaMatch | null,
): DependencyScanProgress {
  let assessmentsCompleted = 0;
  let assessmentsFailed = 0;
  for (const assessment of result.assessments) {
    if (assessment.status === "completed") assessmentsCompleted++;
    else if (assessment.status === "failed") assessmentsFailed++;
  }
  const component =
    match && result.components.find((item) => item.id === match.componentId);
  return {
    phase: "assessing",
    assessmentsTotal: result.matches.length,
    assessmentsCompleted,
    assessmentsFailed,
    current: match && {
      matchId: match.id,
      componentId: match.componentId,
      packageName: component?.name ?? null,
      packageVersion: component?.version ?? null,
      advisoryIds: [...match.advisoryIds],
    },
  };
}

export function dependencyScanResult(
  scan: OsvScanResult,
  repository: ScaResult["repository"],
  outputDir: string,
): ScaResult {
  return {
    schemaVersion: "sca/v0",
    ...scan,
    status:
      scan.status === "completed" && scan.matches.length > 0
        ? "partial"
        : scan.status,
    startedAt: scan.scanner.startedAt,
    completedAt: scan.scanner.completedAt,
    repository,
    outputDir,
    assessments: scan.matches.map((match) => ({
      matchId: match.id,
      status: "not_started",
      verdict: null,
      triage: null,
      error: null,
    })),
    model: { model: null, skillDigest: null, threadId: null, costUsd: null },
  };
}

/** Checkpoint typed facts before attempting model authentication or assessment. */
export async function saveDependencyScan(result: ScaResult): Promise<void> {
  result.completedAt = new Date().toISOString();
  for (const [name, content] of [
    ["sca-result.json", `${JSON.stringify(result, null, 2)}\n`],
    ["report.md", renderScaReport(result)],
  ] as const) {
    const path = join(result.outputDir, name);
    const temporary = `${path}.${randomUUID()}.tmp`;
    const file = await open(temporary, "wx", 0o600);
    try {
      try {
        await file.writeFile(content);
      } finally {
        await file.close();
      }
      await retryWindowsRename(() => rename(temporary, path));
    } finally {
      await rm(temporary, { force: true });
    }
  }
}

export async function dependencyRepositoryDirty(
  repository: string,
  environment: Record<string, string | undefined>,
  signal: AbortSignal,
): Promise<boolean | null> {
  const git = await resolveTrustedExecutable(
    "git",
    isolatedGitEnvironment(false, environment),
    (await gitMarkerRoot(repository, signal, "outermost")) ?? repository,
  );
  if (git === null) return null;
  try {
    const { stdout } = await execFile(
      git.executable,
      [
        "-c",
        "core.fsmonitor=false",
        "-C",
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        ".",
      ],
      { env: git.environment, signal, maxBuffer: Infinity },
    );
    return stdout.length > 0;
  } catch {
    signal.throwIfAborted();
    return null;
  }
}
