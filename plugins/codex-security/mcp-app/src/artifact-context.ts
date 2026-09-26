import { promises as fs } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { ArtifactContext } from "./artifact-io.js";

export type { ArtifactContext } from "./artifact-io.js";

export type RunArtifactWorkbench = (
  arguments_: string[],
  input?: string | Buffer,
) => Promise<Record<string, unknown>>;

export interface ScanArtifactContextOptions {
  requireRunning?: boolean;
  requireClaim?: boolean;
  handoffClaimToken?: string;
  pluginRoot?: string;
  pythonCommand?: string;
}

/**
 * Resolve parent artifacts from their authoritative, persisted workbench scan.
 */
export async function createScanArtifactContext(
  scanId: string,
  runWorkbench: RunArtifactWorkbench,
  options: ScanArtifactContextOptions = {},
): Promise<ArtifactContext> {
  if (!scanId.trim()) {
    throw new Error(
      "Codex Security artifact context requires a scan identity.",
    );
  }

  const result = await runWorkbench(["get-scan", "--scan-id", scanId]);
  const scan = scanRecord(result, scanId);
  const progress = asRecord(scan.progress);
  const status =
    optionalString(progress?.status) ?? optionalString(scan.status);
  if (options.requireRunning && status !== "running") {
    throw new Error(
      "Codex Security scan " +
        scanId +
        " is not running; its artifacts cannot be modified.",
    );
  }

  const expectedClaim = optionalString(scan.handoffClaimToken);
  const suppliedClaim = options.handoffClaimToken;
  if (suppliedClaim && expectedClaim && suppliedClaim !== expectedClaim) {
    throw new Error(
      "Codex Security scan " +
        scanId +
        " is owned by a different continuation.",
    );
  }
  if (
    options.requireClaim &&
    expectedClaim &&
    suppliedClaim !== expectedClaim
  ) {
    throw new Error(
      "Codex Security scan " +
        scanId +
        " requires its current continuation claim.",
    );
  }

  const rawRoot = requireString(
    scan.scanDir,
    "Codex Security scan " + scanId + " has no bound artifact context.",
  );
  const rawRepoRoot = requireString(
    scan.targetPath,
    "Codex Security scan " + scanId + " has no bound target context.",
  );
  const targetContract = asRecord(scan.contract);
  const contractTarget = asRecord(targetContract?.target);
  return {
    root: await canonicalDirectory(
      rawRoot,
      "Codex Security scan artifact root",
    ),
    repoRoot: await canonicalDirectory(
      rawRepoRoot,
      "Codex Security scan target root",
    ),
    layout: "scan",
    scanId,
    ...defined("scope", optionalString(scan.scope)),
    ...defined("pluginRoot", options.pluginRoot),
    ...defined("pythonCommand", options.pythonCommand),
    ...defined("targetContract", targetContract),
    ...defined("targetRevision", optionalString(scan.targetRevision)),
    ...defined(
      "targetSnapshotDigest",
      optionalString(scan.targetSnapshotDigest) ??
        optionalString(contractTarget?.requiredSnapshotDigest),
    ),
    ...defined("handoffClaimToken", suppliedClaim ?? expectedClaim),
    ...defined("status", status),
    ...defined("mode", optionalString(scan.mode)),
  };
}

function scanRecord(
  result: Record<string, unknown>,
  scanId: string,
): Record<string, unknown> {
  const nested = asRecord(result.scan);
  const direct = result.scanId === scanId ? result : undefined;
  const scan = nested ?? direct;
  if (!scan || scan.scanId !== scanId) {
    throw new Error(
      "Codex Security workbench did not return the requested scan identity.",
    );
  }
  return scan;
}

async function canonicalDirectory(
  value: string,
  label: string,
): Promise<string> {
  if (!value || !isAbsolute(value)) {
    throw new Error(label + " must be an absolute directory.");
  }
  const requested = resolve(value);
  const metadata = await fs.lstat(requested).catch(() => undefined);
  if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(label + " is not a safe regular directory.");
  }
  try {
    return await fs.realpath(requested);
  } catch {
    throw new Error(label + " cannot be resolved.");
  }
}

function requireString(value: unknown, message: string): string {
  const result = optionalString(value);
  if (!result) throw new Error(message);
  return result;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function defined<Key extends string, Value>(
  key: Key,
  value: Value | undefined,
): Partial<Record<Key, Value>> {
  return value === undefined ? {} : ({ [key]: value } as Record<Key, Value>);
}
