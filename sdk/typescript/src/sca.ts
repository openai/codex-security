import { execFile as execFileCallback } from "node:child_process";
import { rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { renderScaReport } from "./sca-report.js";
import type { OsvScanResult } from "./sca-osv.js";
import type { ScaResult } from "./sca-types.js";
import { gitMarkerRoot, isolatedGitEnvironment } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

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
    await writeFile(`${path}.tmp`, content, { mode: 0o600 });
    await rename(`${path}.tmp`, path);
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
