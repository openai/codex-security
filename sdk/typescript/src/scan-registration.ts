import type { NormalizedTarget } from "./targets.js";
import type { ScanOptions } from "./api.js";
import type { ScanExpectation } from "./contract.js";
import type { DeepScanOptions } from "./scan-settings.js";
import type { ScanPermissions } from "./execution-preparation.js";
import type { JsonObject } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { findScanSession } from "./scan-logs.js";
import { join } from "node:path";
import { workflowDigest } from "./finding-workflow.js";

/** Validated saved execution options shared by SDK and native resume. */
export interface SavedScanRecipe {
  repository: string;
  target: Pick<
    NormalizedTarget,
    "kind" | "paths" | "base" | "head" | "baseRef" | "headRef"
  >;
  mode: ScanOptions["mode"];
  pluginVersion: string;
  repositoryRevision?: string;
  auth?: ScanOptions["auth"];
  cyberAccessProgram?: ScanOptions["cyberAccessProgram"];
  knowledgeBasePaths?: string[];
  knowledgeBaseSha256?: string;
  scanInputs?: JsonObject;
  maxCostUsd?: number;
  postScanPrompt?: string;
  failOnSeverity?: ScanOptions["failureSeverity"];
  deepScan?: Required<DeepScanOptions>;
  safetyIdentifier?: string;
  inheritedPermissions?: ScanPermissions;
  preserveProviderEnvironment?: boolean;
  config: JsonObject;
}

/** Bind registration and resume metadata to this prepared execution. */
export async function registerScan(options: {
  scan: Pick<
    ScanOptions,
    | "resumeScanId"
    | "registeredScan"
    | "archiveExisting"
    | "parentScanId"
    | "scanPrompt"
    | "workflowId"
  >;
  parentScanRole?: "deep_pass";
  recipe: JsonObject;
  expectation: ScanExpectation;
  scanDir: string;
  workbench: (args: readonly string[], input?: string) => Promise<JsonObject>;
}) {
  const {
    scan: scanOptions,
    recipe,
    expectation,
    scanDir,
    workbench,
  } = options;
  const repo = expectation.repository;
  // The execution lock is held: a queued native caller may have prepared
  // before another process bound the original recipe and saved its knowledge.
  const resumed =
    scanOptions.resumeScanId !== undefined ||
    (scanOptions.registeredScan !== undefined &&
      isRecord(
        (
          await workbench([
            "get-scan",
            "--scan-id",
            scanOptions.registeredScan.scanId,
          ])
        )["recipe"],
      ));
  const registration =
    scanOptions.resumeScanId !== undefined &&
    scanOptions.registeredScan === undefined
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
            ...(scanOptions.parentScanId === undefined
              ? []
              : ["--parent-scan-id", scanOptions.parentScanId]),
          ],
          JSON.stringify({
            recipe,
            ...(options.parentScanRole === undefined
              ? {}
              : { parentScanRole: options.parentScanRole }),
            userContext: scanOptions.scanPrompt,
            ...(scanOptions.registeredScan === undefined
              ? {}
              : {
                  scanId: scanOptions.registeredScan.scanId,
                  threadId: scanOptions.registeredScan.threadId,
                  claimToken: scanOptions.registeredScan.handoffClaimToken,
                }),
            ...(scanOptions.workflowId === undefined
              ? {}
              : { workflowId: scanOptions.workflowId }),
          }),
        );
  const scanId = registration["scanId"];
  const resumeThreadId =
    scanOptions.resumeScanId === undefined &&
    scanOptions.registeredScan === undefined
      ? undefined
      : registration["threadId"];
  const savedRecipe = registration["recipe"];
  if (
    (scanOptions.resumeScanId !== undefined ||
      scanOptions.registeredScan !== undefined) &&
    isRecord(savedRecipe) &&
    !(
      typeof registration["sealedProducerVersion"] === "string" &&
      savedRecipe["knowledgeBaseSha256"] === undefined
    ) &&
    savedRecipe["knowledgeBaseSha256"] !== recipe["knowledgeBaseSha256"]
  )
    throw new CodexSecurityError(
      "The knowledge base changed since this scan started. Restore the original documents before resuming.",
    );
  if (
    (scanOptions.resumeScanId !== undefined ||
      scanOptions.registeredScan !== undefined) &&
    isRecord(savedRecipe) &&
    isRecord(savedRecipe["scanInputs"]) &&
    workflowDigest(savedRecipe["scanInputs"]["knowledgeBase"]) !==
      workflowDigest((recipe["scanInputs"] as JsonObject)["knowledgeBase"])
  ) {
    throw new CodexSecurityError(
      "The supplied knowledge base differs from this scan's original context. Restore the saved snapshot or start a new scan.",
    );
  }
  if (scanOptions.resumeScanId !== undefined) {
    if (
      scanId !== scanOptions.resumeScanId ||
      !isRecord(savedRecipe) ||
      savedRecipe["repository"] !== repo ||
      (resumeThreadId !== null && typeof resumeThreadId !== "string") ||
      JSON.stringify(savedRecipe["target"]) !== JSON.stringify(recipe["target"])
    ) {
      throw new CodexSecurityError(
        "The workbench returned mismatched scan resume context.",
      );
    }
  }
  if (typeof registration["sealedProducerVersion"] === "string") {
    expectation.pluginVersion = registration["sealedProducerVersion"];
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
    !isRecord(contract) ||
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
    resumed,
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
    sealed: typeof registration["sealedProducerVersion"] === "string",
  };
}

/** Require continuation logs only after terminal-state rejection and accounting. */
export async function requireScanResumeSession(options: {
  registration: Pick<
    Awaited<ReturnType<typeof registerScan>>,
    "scanId" | "resumeThreadId" | "sealed"
  >;
  codexHome: string;
  scanDir: string;
  mode: ScanExpectation["mode"];
}): Promise<void> {
  const {
    registration: { scanId, resumeThreadId, sealed },
    codexHome,
    scanDir,
    mode,
  } = options;
  if (sealed || typeof resumeThreadId !== "string") return;
  const savedSession = await findScanSession(codexHome, resumeThreadId);
  if (
    savedSession === null ||
    savedSession.workingDirectory !==
      (mode === "deep"
        ? join(scanDir, "artifacts", "deep-scan", "merge")
        : scanDir)
  ) {
    throw new CodexSecurityError(
      `The original Codex session for scan ${scanId} is unavailable. Restore its session logs in the original Codex Security state directory before resuming.`,
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
