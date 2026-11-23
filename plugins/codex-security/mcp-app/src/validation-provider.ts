import { randomUUID } from "node:crypto";
import { lstatSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { replaceArtifactText } from "./artifact-io.js";
import { dirname, join } from "node:path";
import { loadSealedContract } from "./sealed-contract.js";
import {
  codexSecurityStateDirectory,
  validationProviderFromConfiguration,
  assessPluginFindings,
  continuumAssessmentVersion,
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
    ? `\nOn request, resume pending checks or retry unavailable findings with complete_codex_security_scan and this scan ID.`
    : "";
  return `\n\nSupplemental validation (${validation.provider ?? "provider"}): ${validation.status}\n${validation.summary ?? validation.report ?? validation.message ?? ""}${validation.reportPath ? `\nReport: ${validation.reportPath}` : ""}${validation.recordsPath ? `\nRecords: ${validation.recordsPath}` : ""}${retry}`;
}

function configurationPath(scanId: string): string {
  return join(
    codexSecurityStateDirectory(),
    "validation-providers",
    `${scanId}.json`,
  );
}

/** Bind the host-owned setup snapshot without rereading a changed project file. */
export async function bindValidationProviderConfiguration(
  scanId: string,
  configuration: ValidationProviderConfiguration | undefined,
  created: boolean,
): Promise<void> {
  if (configuration === undefined) return;
  const path = configurationPath(scanId);
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
  // Refresh older attribution rules from the separate submission receipts.
  if (saved.schemaVersion !== continuumAssessmentVersion) return;
  return saved;
}

/** Run only after the workbench has sealed the scan. */
export async function validateCompletedScan(
  scan: JsonObject,
  resolveProvider = validationProviderFromConfiguration,
  signal?: AbortSignal,
): Promise<JsonObject | undefined> {
  const { scanId, sealManifestDigest } = scan;
  if (typeof scanId !== "string") return;
  let configuration: ValidationProviderConfiguration;
  try {
    configuration = JSON.parse(
      await readFile(configurationPath(scanId), "utf8"),
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
    const cachePath = `${configurationPath(scanId)}.result`;
    const readSaved = () =>
      readSavedValidation(cachePath, configuration, repositoryPath);
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
        if (saved?.attemptId && saved.attemptId !== attempt)
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
          const { findings } = contract.findings;
          // Receipt-backed polls do not require a fresh upload or an unchanged checkout.
          const checkSubmissionTarget = async (signal?: AbortSignal) => {
            const { runWorkbench } = await import("./workbench-client.js");
            const { scan: current } = await runWorkbench(
              ["get-scan", "--scan-id", scanId, "--check-target"],
              undefined,
              { signal },
            );
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
