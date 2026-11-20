import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, open, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { retryWindowsRename } from "./retry-windows-rename.js";
import { renderScaReport } from "./sca-report.js";
import type { OsvScanResult } from "./sca-osv.js";
import type { ScaAssessment, ScaMatch, ScaResult } from "./sca-types.js";
import { gitMarkerRoot, isolatedGitEnvironment } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import Ajv from "ajv";
import { readScanFile } from "./contract.js";
import { bundledPluginRoot } from "./runtime.js";

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
      /** Completed assessments whose available evidence was inconclusive. */
      assessmentsInconclusive?: number;
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
  let assessmentsInconclusive = 0;
  for (const assessment of result.assessments) {
    if (assessment.status === "completed") {
      assessmentsCompleted++;
      if (assessment.verdict === "needs_review") assessmentsInconclusive++;
    } else if (assessment.status === "failed") assessmentsFailed++;
  }
  const component =
    match && result.components.find((item) => item.id === match.componentId);
  return {
    phase: "assessing",
    assessmentsTotal: result.matches.length,
    assessmentsCompleted,
    assessmentsFailed,
    assessmentsInconclusive,
    current: match && {
      matchId: match.id,
      componentId: match.componentId,
      packageName: component?.name ?? null,
      packageVersion: component?.version ?? null,
      advisoryIds: [...match.advisoryIds],
    },
  };
}

export async function readDependencyScan(
  outputDir: string,
): Promise<ScaResult> {
  const root = await bundledPluginRoot();
  const [schema, triage] = await Promise.all([
    readFile(join(root, "schemas/sca-result.schema.json"), "utf8"),
    readFile(join(root, "schemas/triage-result.schema.json"), "utf8"),
  ]);
  const ajv = new Ajv({ allErrors: true, strict: false });
  ajv.addSchema(JSON.parse(triage), "triage-result.schema.json");
  const validate = ajv.compile<ScaResult>(JSON.parse(schema));
  const result: unknown = JSON.parse(
    (
      await readScanFile(outputDir, "sca-result.json", "dependency results")
    ).toString("utf8"),
  );
  if (!validate(result))
    throw new Error(
      `Cannot continue invalid dependency results: ${ajv.errorsText(validate.errors)}.`,
    );
  if (result.outputDir !== outputDir)
    throw new Error(
      "Continue dependency assessment in its original output directory.",
    );
  return result;
}

/** Older checkpoints can contain matches with no assessment yet. */
export function missingDependencyAssessments(result: ScaResult) {
  const missing: ScaAssessment[] = [];
  const existing = new Set(result.assessments.map((item) => item.matchId));
  for (const match of result.matches) {
    if (existing.has(match.id)) continue;
    missing.push(pendingAssessment(match));
    existing.add(match.id);
  }
  return missing;
}

export async function hasDependencyScan(outputDir: string): Promise<boolean> {
  try {
    await lstat(join(outputDir, "sca-result.json"));
    return true;
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    if (code === "ENOENT" || code === "ENOTDIR") return false;
    throw error;
  }
}

function pendingAssessment(match: ScaMatch): ScaAssessment {
  return {
    matchId: match.id,
    status: "not_started",
    verdict: null,
    triage: null,
    error: null,
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
    assessments: scan.matches.map(pendingAssessment),
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
    await writeDependencyArtifact(result.outputDir, name, content);
  }
}

export async function writeDependencyArtifact(
  outputDir: string,
  name: "sca-result.json" | "report.md" | "sca-assessment-input.json",
  content: string,
): Promise<void> {
  const path = join(outputDir, name);
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
