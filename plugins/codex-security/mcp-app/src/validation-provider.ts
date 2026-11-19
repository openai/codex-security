import { constants } from "node:fs";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { requireRegularFile } from "./deep-scan/artifacts.js";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { readProjectConfig } from "../../../../sdk/typescript/src/project-config.js";
import { validationProviderFromConfiguration } from "../../../../sdk/typescript/src/validation-providers.js";
import {
  unavailableAssessment,
  type ValidationProvider,
  type ValidationProviderAssessment,
  type ValidationProviderConfiguration,
  type ValidationItemRecord,
} from "../../../../sdk/typescript/src/validation-provider.js";
import type { JsonObject } from "./types.js";
import { protectedHostPathResolver } from "./helpers/inventory-git.js";

/** Text accompanies structured content so every MCP client exposes the result. */
export function validationCompletionText(
  validation: JsonObject | undefined,
): string {
  if (!validation) return "";
  return `\n\nSupplemental validation (${validation.provider ?? "provider"}): ${validation.status}\n${validation.summary ?? validation.report ?? validation.message ?? ""}${validation.reportPath ? `\nReport: ${validation.reportPath}` : ""}${validation.recordsPath ? `\nRecords: ${validation.recordsPath}` : ""}`;
}

function itemConclusion(record: ValidationItemRecord): string {
  const bases = [...new Set(record.reasons.map((reason) => reason.basis))];
  return `Item ${record.itemId}: ${record.severityBefore} → ${record.severityAfter}. Verdict: ${record.verdict}.${record.providerSeverity ? ` Provider severity: ${record.providerSeverity}.` : ""}${bases.length ? ` Reason bases: ${bases.join(", ")}.` : ""} Claim match: ${record.claimMatch}.${record.freshness.stale ? " Evidence predates this submission." : ""}${record.unavailable ? ` Unavailable: ${record.unavailable}` : ""}`;
}

function configurationPath(scanId: string): string {
  return join(
    process.env.CODEX_SECURITY_STATE_DIR?.trim() ||
      join(homedir(), ".codex-security"),
    "validation-providers",
    `${scanId}.json`,
  );
}

/** Bind explicitly selected host configuration, never repository-discovered settings. */
export async function bindValidationProvider(
  scanId: string,
  repositoryPath: string,
  projectConfigPath: string | undefined,
  created: boolean,
): Promise<void> {
  if (!created || projectConfigPath === undefined) return;
  const project = await readProjectConfig(projectConfigPath, repositoryPath);
  const configuration = project.input.scan?.validation;
  await bindValidationProviderConfiguration(scanId, configuration, created);
}

/** Bind the host-owned setup snapshot without rereading a changed project file. */
export async function bindValidationProviderConfiguration(
  scanId: string,
  configuration: ValidationProviderConfiguration | undefined,
  created: boolean,
): Promise<void> {
  if (!created || configuration === undefined) return;
  validationProviderFromConfiguration(configuration);
  const path = configurationPath(scanId);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(configuration), {
    flag: "wx",
    mode: 0o600,
  });
}

async function readSupplementalArtifact(
  path: string,
  scanDir: string,
): Promise<string> {
  await requireRegularFile(path, scanDir, true);
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | constants.O_NONBLOCK,
  );
  try {
    if (!(await handle.stat()).isFile())
      throw new Error("Validation artifact must be a regular file.");
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

/** Run only after the workbench has sealed the scan. Its artifacts stay unchanged. */
export async function validateCompletedScan(
  scan: JsonObject,
  resolveProvider = validationProviderFromConfiguration,
): Promise<JsonObject | undefined> {
  if (typeof scan.scanId !== "string") return;
  let configuration: ValidationProviderConfiguration;
  try {
    configuration = JSON.parse(
      await readFile(configurationPath(scan.scanId), "utf8"),
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    return { status: "failed", message: String(error) };
  }
  try {
    const scanDir = String(scan.scanDir);
    const repositoryPath = String(scan.targetPath);
    const reportPath = join(scanDir, "validation.md");
    const recordsPath = join(scanDir, "validation.json");
    // Completed results survive host restart and must not cause another submission.
    try {
      const saved = JSON.parse(
        await readSupplementalArtifact(recordsPath, scanDir),
      );
      const report = await readSupplementalArtifact(reportPath, scanDir);
      return {
        status: "complete",
        provider: configuration.provider,
        findings: saved.findings,
        reportPath,
        recordsPath,
        report,
        summary:
          (saved.summary ?? saved.items.map(itemConclusion).join("\n")) ||
          report,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const provider: ValidationProvider = resolveProvider(configuration);
    const { findings }: { findings: Record<string, unknown>[] } = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    );
    const context = {
      repositoryPath,
      resolveHostPaths: protectedHostPathResolver,
    };
    const assessments: ValidationProviderAssessment[] = provider.validateBatch
      ? await provider
          .validateBatch(findings, context)
          .catch((error: unknown) =>
            findings.map(() => unavailableAssessment(provider, error)),
          )
      : await Promise.all(
          findings.map(async (finding: Record<string, unknown>) => {
            try {
              return await provider.validate(finding, context);
            } catch (error) {
              return unavailableAssessment(provider, error);
            }
          }),
        );
    const summary = assessments
      .map((assessment) =>
        assessment.record
          ? itemConclusion(assessment.record)
          : assessment.report,
      )
      .join("\n");
    const report = assessments
      .map(
        (assessment, index) =>
          `## ${findings[index].occurrenceId ?? findings[index].id ?? `item-${index + 1}`}\n\nDisposition: ${assessment.disposition}\n\n${assessment.report}\n`,
      )
      .join("\n---\n\n");
    await writeFile(reportPath, report, { flag: "wx", mode: 0o600 });
    await writeFile(
      recordsPath,
      JSON.stringify(
        {
          schemaVersion: 1,
          findings: findings.length,
          summary,
          items: assessments.flatMap((assessment) =>
            assessment.record ? [assessment.record] : [],
          ),
        },
        null,
        2,
      ) + "\n",
      { flag: "wx", mode: 0o600 },
    );
    return {
      status: "complete",
      provider: provider.name,
      findings: findings.length,
      reportPath,
      recordsPath,
      report,
      summary,
    };
  } catch (error) {
    // An unavailable supplemental provider must not turn a sealed scan into a failure.
    return {
      status: "failed",
      provider: configuration.provider,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
