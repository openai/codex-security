import { execFile as execFileCallback } from "node:child_process";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { promisify } from "node:util";
import { renderScaReport } from "./sca-report.js";
import type { OsvScanResult } from "./sca-osv.js";
import type { ScaResult } from "./sca-types.js";
import { gitMarkerRoot, isolatedGitEnvironment } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import Ajv from "ajv";
import { readScanFile } from "./contract.js";
import { bundledPluginRoot } from "./runtime.js";

const execFile = promisify(execFileCallback);

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
  await writeFile(temporary, content, { flag: "wx", mode: 0o600 });
  try {
    await rename(temporary, path);
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
