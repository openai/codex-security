import { randomUUID } from "node:crypto";
import { lstatSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { replaceArtifactText } from "./artifact-io.js";
import { dirname, join } from "node:path";
import { readSelectedProjectConfig } from "./deep-scan/project-config.js";
import { loadSealedContract } from "./sealed-contract.js";
import {
  codexSecurityStateDirectory,
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
    ? `\nOn request, ${validation.status === "outdated" ? "refresh assessments" : "resume pending checks or retry unavailable findings"} with complete_codex_security_scan and this scan ID.`
    : "";
  return `\n\nSupplemental validation (${validation.provider ?? "provider"}): ${validation.status}\n${validation.summary ?? validation.report ?? validation.message ?? ""}${validation.reportPath ? `\nReport: ${validation.reportPath}` : ""}${validation.recordsPath ? `\nRecords: ${validation.recordsPath}` : ""}${retry}`;
}

const sharingConflict =
  "Automatic Continuum validation is disabled for this scan because the project file selected on rejoin did not confirm the saved destination and permission to share local validation details. Finish the local scan, then review the findings and use codex-security validate --scan with your chosen project file. Earlier submissions cannot be recalled.";

function sharingBlocked(path: string) {
  return Boolean(lstatSync(path + ".blocked", { throwIfNoEntry: false }));
}

function configurationPath(scanId: string): string {
  return join(
    codexSecurityStateDirectory(),
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

/** A rejoin may withdraw permission but cannot expand or redirect an existing grant. */
export async function bindValidationProviderConfiguration(
  scanId: string,
  configuration: ValidationProviderConfiguration | undefined,
  created: boolean,
  selection?: { file: string; target: string; mode: "standard" | "deep" },
): Promise<string | undefined> {
  if (configuration === undefined) return;
  const path = configurationPath(scanId);
  if (sharingBlocked(path)) return sharingConflict;
  const saved = asRecord(configuration.continuum);
  if (!created && selection && saved?.include_local_validation === true) {
    let candidate: JsonObject | undefined;
    let problem: unknown;
    try {
      const { input } = await readSelectedProjectConfig(
        selection.file,
        selection.target,
        selection.mode,
      );
      const validation = input.scan?.validation;
      if (validation?.provider === configuration.provider)
        candidate = asRecord(validation.continuum);
    } catch (error) {
      problem = error;
    }
    if (
      candidate?.include_local_validation !== true ||
      candidate.environment_id !== saved.environment_id ||
      candidate.aws_region !== saved.aws_region ||
      candidate.aws_profile !== saved.aws_profile
    ) {
      // Persist the withdrawal for detached coordinators and later rejoins.
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await replaceArtifactText(path + ".blocked", sharingConflict);
      return problem
        ? sharingConflict + " " + String(problem)
        : sharingConflict;
    }
  }
  // Registration may have committed before the original host wrote the binding.
  if (!created && lstatSync(path, { throwIfNoEntry: false })) return;
  validationProviderFromConfiguration(configuration);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await replaceArtifactText(path, JSON.stringify(configuration));
}

interface SavedValidation {
  schemaVersion?: number;
  attemptId?: string;
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
  signal?: AbortSignal,
) {
  return completedScanValidation(scan, resolveProvider, signal);
}

/** Read the last protected assessment without running the provider. */
export function readCompletedValidation(scan: JsonObject) {
  return completedScanValidation(scan);
}

async function completedScanValidation(
  scan: JsonObject,
  resolveProvider?: typeof validationProviderFromConfiguration,
  signal?: AbortSignal,
): Promise<JsonObject | undefined> {
  const { scanId, sealManifestDigest } = scan;
  if (typeof scanId !== "string") return;
  let configuration: ValidationProviderConfiguration;
  try {
    const path = configurationPath(scanId);
    if (sharingBlocked(path))
      return {
        status: "failed",
        provider: "continuum",
        message: sharingConflict,
      };
    configuration = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    return { status: "failed", message: String(error) };
  }
  try {
    const scanDir = String(scan.scanDir);
    const repositoryPath = String(scan.targetPath);
    const reportPath = join(scanDir, "validation.md");
    const recordsPath = join(scanDir, "validation.json");
    const cachePath = `${configurationPath(scanId)}.result`;
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
    if (
      asRecord(scan.progress)?.status !== "complete" ||
      typeof sealManifestDigest !== "string"
    )
      throw new Error(
        "Validation requires a completed scan with a recorded seal.",
      );
    const attempt = (await readSaved())?.attemptId;
    return await withPublicationLock(
      dirname(cachePath),
      scanId,
      signal,
      async () => {
        let saved = await readSaved();
        // A waiter shares the result even if another attempt could be useful.
        if (
          saved?.attemptId &&
          saved.attemptId !== attempt &&
          saved.result.status !== "outdated"
        )
          return saved.result;
        const { contract } = await loadSealedContract(scanDir, {
          pluginRoot: process.env.CODEX_SECURITY_PLUGIN_ROOT,
          expectedScanId: scanId,
          expectedManifestDigest: sealManifestDigest,
          signal,
        });
        if (contract.manifest.scan.status !== "completed")
          throw new Error("Validation requires a completed scan.");
        if (!saved || saved.retry) {
          if (sharingBlocked(configurationPath(scanId)))
            throw new Error(sharingConflict);
          const { findings } = contract.findings;
          // Receipt-backed polls do not require a fresh upload or an unchanged checkout.
          const checkSubmissionTarget = async (signal?: AbortSignal) => {
            const { runWorkbench } = await import("./workbench-client.js");
            const { scan: current } = await runWorkbench(
              ["get-scan", "--scan-id", scanId, "--check-target"],
              undefined,
              { signal },
            );
            if (sharingBlocked(configurationPath(scanId)))
              throw new Error(sharingConflict);
            const registered = asRecord(current);
            if (
              registered?.scanId !== scanId ||
              registered.targetPath !== repositoryPath ||
              registered.sealManifestDigest !== sealManifestDigest
            )
              throw new Error(
                "Validation no longer matches the recorded scan.",
              );
          };
          const { providerName, status, summary, report, records, retry } =
            await assessPluginFindings(
              configuration,
              findings,
              {
                repositoryPath,
                signal,
                checkSubmissionTarget,
                resolveHostPaths: protectedHostPathResolver,
              },
              resolveProvider,
              saved?.retry,
              saved?.result.status === "outdated"
                ? saved.records.items
                : undefined,
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
            attemptId: randomUUID(),
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
