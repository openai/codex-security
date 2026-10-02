import type { ScanOptions } from "./api.js";
import type { ScanExpectation } from "./contract.js";
import type { JsonObject } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { findScanSession } from "./scan-logs.js";

/** Bind registration and resume metadata to this prepared execution. */
export async function registerScan(options: {
  scan: Pick<
    ScanOptions,
    | "resumeScanId"
    | "archiveExisting"
    | "parentScanId"
    | "scanPrompt"
    | "workflowId"
  >;
  recipe: JsonObject;
  expectation: ScanExpectation;
  scanDir: string;
  archivedScanDir: string | null;
  codexHome: string;
  workbench: (args: readonly string[], input?: string) => Promise<JsonObject>;
}) {
  const {
    scan: scanOptions,
    recipe,
    expectation,
    scanDir,
    archivedScanDir,
    codexHome,
    workbench,
  } = options;
  const repo = expectation.repository;
  const registration =
    scanOptions.resumeScanId !== undefined
      ? await workbench([
          "get-cli-scan-resume",
          "--scan-id",
          scanOptions.resumeScanId,
        ])
      : await workbench(
          [
            "register-cli-scan",
            "--repository",
            repo,
            "--scan-dir",
            scanDir,
            "--registration-json-stdin",
            ...(scanOptions.archiveExisting === true
              ? ["--archive-existing"]
              : []),
            ...(archivedScanDir === null
              ? []
              : ["--archived-scan-dir", archivedScanDir]),
            ...(scanOptions.parentScanId === undefined
              ? []
              : ["--parent-scan-id", scanOptions.parentScanId]),
          ],
          JSON.stringify({
            recipe,
            userContext: scanOptions.scanPrompt,
            ...(scanOptions.workflowId === undefined
              ? {}
              : { workflowId: scanOptions.workflowId }),
          }),
        );
  const scanId = registration["scanId"];
  const resumeThreadId =
    scanOptions.resumeScanId === undefined
      ? undefined
      : registration["threadId"];
  if (scanOptions.resumeScanId !== undefined) {
    const savedRecipe = registration["recipe"];
    if (
      scanId !== scanOptions.resumeScanId ||
      !isRecord(savedRecipe) ||
      savedRecipe["repository"] !== repo ||
      typeof resumeThreadId !== "string" ||
      !resumeThreadId ||
      JSON.stringify(savedRecipe["target"]) !== JSON.stringify(recipe["target"])
    ) {
      throw new CodexSecurityError(
        "The workbench returned mismatched scan resume context.",
      );
    }
    const savedSession = await findScanSession(codexHome, resumeThreadId);
    if (savedSession === null || savedSession.workingDirectory !== scanDir) {
      throw new CodexSecurityError(
        `The original Codex session for scan ${scanId} is unavailable. Restore its session logs in the original Codex Security state directory before resuming.`,
      );
    }
    if (typeof registration["sealedProducerVersion"] === "string") {
      expectation.pluginVersion = registration["sealedProducerVersion"];
    }
  }
  const targetId = registration["targetId"];
  const contract = registration["contract"];
  const contractTarget = isRecord(contract) ? contract["target"] : undefined;
  const allowedKinds = isRecord(contractTarget)
    ? contractTarget["allowedKinds"]
    : undefined;
  const targetKind =
    Array.isArray(allowedKinds) && allowedKinds.length === 1
      ? allowedKinds[0]
      : undefined;
  const diffTarget = isRecord(contract) ? contract["diffTarget"] : undefined;
  const snapshotDigest =
    targetKind === "git_diff" && isRecord(diffTarget)
      ? diffTarget["contentDigest"]
      : isRecord(contractTarget)
        ? contractTarget["requiredSnapshotDigest"]
        : undefined;
  const registeredRevision = registration["targetRevision"];
  if (
    typeof scanId !== "string" ||
    typeof targetId !== "string" ||
    registration["scanDir"] !== scanDir ||
    typeof targetKind !== "string" ||
    ![
      "git_revision",
      "git_worktree",
      "git_diff",
      "directory_snapshot",
    ].includes(targetKind) ||
    (snapshotDigest !== undefined && typeof snapshotDigest !== "string") ||
    ((targetKind === "git_worktree" || targetKind === "directory_snapshot") &&
      typeof snapshotDigest !== "string") ||
    typeof registeredRevision !== "string"
  ) {
    throw new CodexSecurityError(
      "The Codex Security workbench returned an invalid scan registration.",
    );
  }
  const targetRevision =
    registeredRevision === "unversioned" ? null : registeredRevision;

  const registeredFileCount = registration["scopeFileCount"];
  const scopeFileCount =
    typeof registeredFileCount === "number" &&
    Number.isSafeInteger(registeredFileCount) &&
    registeredFileCount >= 0
      ? registeredFileCount
      : null;
  return {
    registration,
    scanId,
    resumeThreadId,
    targetId,
    contract,
    targetKind,
    snapshotDigest,
    registeredRevision,
    targetRevision,
    scopeFileCount,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
