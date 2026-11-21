import { mkdir, readFile } from "node:fs/promises";
import { replaceArtifactText } from "./artifact-io.js";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { readSelectedProjectConfig } from "./deep-scan/project-config.js";
import {
  validationProviderFromConfiguration,
  assessPluginFindings,
  continuumAssessmentVersion,
  savedContinuumAssessments,
  withPublicationLock,
  type ValidationProviderConfiguration,
} from "#validation-runtime";
import type { JsonObject } from "./types.js";
import { asRecord } from "./record.js";
import { protectedHostPathResolver } from "./helpers/inventory-git.js";

/** Text accompanies structured content so every MCP client exposes the result. */
export function validationCompletionText(
  validation: JsonObject | undefined,
): string {
  if (!validation) return "";
  const retry = validation.retryable
    ? `\nOn request, ${validation.status === "outdated" ? "refresh assessments" : "retry unavailable findings"} with complete_codex_security_scan and this scan ID.`
    : "";
  return `\n\nSupplemental validation (${validation.provider ?? "provider"}): ${validation.status}\n${validation.summary ?? validation.report ?? validation.message ?? ""}${validation.reportPath ? `\nReport: ${validation.reportPath}` : ""}${validation.recordsPath ? `\nRecords: ${validation.recordsPath}` : ""}${retry}`;
}

function configurationPath(scanId: string): string {
  return join(
    process.env.CODEX_SECURITY_STATE_DIR?.trim() ||
      join(homedir(), ".codex-security"),
    "validation-providers",
    `${scanId}.json`,
  );
}

/** Called after get-scan authorizes the caller's remediation claim. */
export async function withAssignedAssessment(
  context: JsonObject,
): Promise<JsonObject> {
  const scan = asRecord(context.scan);
  if (!Array.isArray(scan?.findings)) return context;
  // Only a protected host record can supply this field.
  const findings = scan.findings.map(
    ({ continuumAssessment: _ignored, ...finding }: JsonObject) => finding,
  );
  const finding = findings[0];
  const action = asRecord(finding?.remediationState)?.pendingAction;
  if (
    findings.length === 1 &&
    (action === "generate" || action === "verify") &&
    typeof scan.scanId === "string" &&
    typeof scan.targetPath === "string" &&
    typeof finding?.occurrenceId === "string"
  ) {
    const saved = await savedContinuumAssessments(
      process.env,
      scan.scanId,
      scan.targetPath,
      [finding.occurrenceId],
    );
    const assessment = saved.get(finding.occurrenceId);
    if (assessment) finding.continuumAssessment = assessment;
  }
  return { ...context, scan: { ...scan, findings } };
}

/** Bind explicitly selected host configuration, never repository-discovered settings. */
export async function bindValidationProvider(
  scanId: string,
  repositoryPath: string,
  projectConfigPath: string | undefined,
  created: boolean,
): Promise<void> {
  if (!created || projectConfigPath === undefined) return;
  const project = await readSelectedProjectConfig(
    projectConfigPath,
    repositoryPath,
  );
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
  await replaceArtifactText(path, JSON.stringify(configuration));
}

interface SavedValidation {
  schemaVersion?: number;
  configuration: ValidationProviderConfiguration;
  repositoryPath: string;
  records: { items: JsonObject[] };
  result: JsonObject & { report: string };
  retry?: unknown[] | null;
}

async function readSavedValidation(
  path: string,
  configuration: ValidationProviderConfiguration,
  repositoryPath: string,
): Promise<SavedValidation | undefined> {
  let saved: SavedValidation;
  try {
    saved = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (
    JSON.stringify(saved.configuration) !== JSON.stringify(configuration) ||
    saved.repositoryPath !== repositoryPath
  ) {
    throw new Error(
      "Saved validation does not match this scan's provider configuration.",
    );
  }
  // Legacy terminal conclusions and mixed retry lists may both attribute an
  // issue-wide verdict to one finding. Re-evaluate the whole batch from the
  // separate submission receipts only when completion is explicitly requested.
  if (
    (saved.schemaVersion !== continuumAssessmentVersion ||
      saved.retry === undefined) &&
    saved.result.provider === "continuum" &&
    (saved.result.findings || saved.records.items.length)
  ) {
    saved.retry = [];
    saved.result.status = "outdated";
  }
  return saved;
}

/** Run only after the workbench has sealed the scan. */
export function validateCompletedScan(
  scan: JsonObject,
  resolveProvider = validationProviderFromConfiguration,
) {
  return completedScanValidation(scan, resolveProvider);
}

/** Read the last protected assessment without running the provider. */
export function readCompletedValidation(scan: JsonObject) {
  return completedScanValidation(scan);
}

async function completedScanValidation(
  scan: JsonObject,
  resolveProvider?: typeof validationProviderFromConfiguration,
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
    const cachePath = `${configurationPath(scan.scanId)}.result`;
    const readSaved = () =>
      readSavedValidation(cachePath, configuration, repositoryPath);
    if (!resolveProvider) {
      const saved = await readSaved();
      if (!saved) return;
      const { status, provider, findings, summary, retryable } = saved.result;
      if (status === "outdated") {
        return {
          status,
          provider,
          findings,
          retryable: true,
          message:
            "Complete this scan again to refresh Continuum terminal statuses and finding attribution. Findings without a saved submission receipt may be submitted again.",
        };
      }
      return {
        status,
        provider,
        findings,
        summary,
        retryable,
        items: saved.records.items,
      };
    }
    return await withPublicationLock(
      dirname(cachePath),
      scan.scanId,
      undefined,
      async () => {
        let saved = await readSaved();
        if (!saved || saved.retry) {
          const { findings }: { findings: JsonObject[] } = JSON.parse(
            await readFile(join(scanDir, "findings.json"), "utf8"),
          );
          const { providerName, status, summary, report, records, retry } =
            await assessPluginFindings(
              configuration,
              findings,
              { repositoryPath, resolveHostPaths: protectedHostPathResolver },
              resolveProvider,
              saved?.retry,
            );
          const result = {
            status,
            provider: providerName,
            findings: findings.length,
            reportPath,
            recordsPath,
            report,
            summary,
            ...(retry ? { retryable: true } : {}),
          };
          saved = {
            schemaVersion: continuumAssessmentVersion,
            configuration,
            repositoryPath,
            records,
            result,
            retry,
          };
          await replaceArtifactText(cachePath, JSON.stringify(saved));
        }
        // These model-writable files are projections, never authoritative cache input.
        await replaceArtifactText(reportPath, saved.result.report);
        await replaceArtifactText(
          recordsPath,
          JSON.stringify(saved.records, null, 2) + "\n",
        );
        return { ...saved.result, reportPath, recordsPath };
      },
    );
  } catch (error) {
    // An unavailable supplemental provider must not turn a sealed scan into a failure.
    return {
      status: "failed",
      provider: configuration.provider,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
