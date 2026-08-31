import { promises as fs } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { ArtifactContext } from "./artifact-io.js";

export type {
  ArtifactContext,
  DeepReducerContext,
  DeepReducerWorkerContext
} from "./artifact-io.js";

export type RunArtifactWorkbench = (
  arguments_: string[]
) => Promise<Record<string, unknown>>;

export interface ScanArtifactContextOptions {
  requireRunning?: boolean;
  requireClaim?: boolean;
  handoffClaimToken?: string;
  pluginRoot?: string;
  pythonCommand?: string;
}

export interface WorkerArtifactContextInput {
  root: string;
  repoRoot: string;
  layout?: "worker" | "reducer";
  scanId?: string;
  scope?: string;
  pluginRoot?: string;
  pythonCommand?: string;
  targetContract?: Readonly<Record<string, unknown>>;
  targetRevision?: string;
  targetSnapshotDigest?: string;
  handoffClaimToken?: string;
  status?: string;
  mode?: string;
  deepReducer?: ArtifactContext["deepReducer"];
}

/**
 * Resolve parent artifacts from their authoritative, persisted workbench scan.
 */
export async function createScanArtifactContext(
  scanId: string,
  runWorkbench: RunArtifactWorkbench,
  options: ScanArtifactContextOptions = {}
): Promise<ArtifactContext> {
  if (!scanId.trim()) {
    throw new Error("Codex Security artifact context requires a scan identity.");
  }

  const result = await runWorkbench(["get-scan", "--scan-id", scanId]);
  const scan = scanRecord(result, scanId);
  const progress = asRecord(scan.progress);
  const status = optionalString(progress?.status)
    ?? optionalString(scan.status);
  if (options.requireRunning && status !== "running") {
    throw new Error(
      "Codex Security scan "
      + scanId
      + " is not running; its artifacts cannot be modified."
    );
  }

  const expectedClaim = optionalString(scan.handoffClaimToken);
  const suppliedClaim = options.handoffClaimToken;
  if (suppliedClaim && expectedClaim && suppliedClaim !== expectedClaim) {
    throw new Error(
      "Codex Security scan "
      + scanId
      + " is owned by a different continuation."
    );
  }
  if (options.requireClaim && expectedClaim && suppliedClaim !== expectedClaim) {
    throw new Error(
      "Codex Security scan "
      + scanId
      + " requires its current continuation claim."
    );
  }

  const rawRoot = requireString(
    scan.scanDir,
    "Codex Security scan " + scanId + " has no bound artifact context."
  );
  const rawRepoRoot = requireString(
    scan.targetPath,
    "Codex Security scan " + scanId + " has no bound target context."
  );
  const targetContract = asRecord(scan.contract);
  const contractTarget = asRecord(targetContract?.target);
  return {
    root: await canonicalDirectory(rawRoot, "Codex Security scan artifact root"),
    repoRoot: await canonicalDirectory(
      rawRepoRoot,
      "Codex Security scan target root"
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
      optionalString(scan.targetSnapshotDigest)
      ?? optionalString(contractTarget?.requiredSnapshotDigest)
    ),
    ...defined("handoffClaimToken", suppliedClaim ?? expectedClaim),
    ...defined("status", status),
    ...defined("mode", optionalString(scan.mode))
  };
}

/**
 * Bind a lightweight worker to host-supplied state, never model-supplied paths.
 */
export async function createWorkerArtifactContext(
  input: WorkerArtifactContextInput
): Promise<ArtifactContext> {
  const layout = input.layout ?? "worker";
  if (layout !== "worker" && layout !== "reducer") {
    throw new Error("Codex Security worker artifact layout is invalid.");
  }
  const context: ArtifactContext = {
    root: await canonicalDirectory(
      input.root,
      "Codex Security worker artifact root"
    ),
    repoRoot: await canonicalDirectory(
      input.repoRoot,
      "Codex Security worker target root"
    ),
    layout,
    ...defined("scanId", input.scanId),
    ...defined("scope", input.scope),
    ...defined("pluginRoot", input.pluginRoot),
    ...defined("pythonCommand", input.pythonCommand),
    ...defined("targetContract", input.targetContract),
    ...defined("targetRevision", input.targetRevision),
    ...defined("targetSnapshotDigest", input.targetSnapshotDigest),
    ...defined("handoffClaimToken", input.handoffClaimToken),
    ...defined("status", input.status),
    ...defined("mode", input.mode),
    ...defined("deepReducer", input.deepReducer)
  };
  if (context.deepReducer && layout !== "reducer") {
    throw new Error("Codex Security reducer state requires a reducer-bound context.");
  }
  return context;
}

function scanRecord(
  result: Record<string, unknown>,
  scanId: string
): Record<string, unknown> {
  const nested = asRecord(result.scan);
  const direct = result.scanId === scanId ? result : undefined;
  const scan = nested ?? direct;
  if (!scan || scan.scanId !== scanId) {
    throw new Error(
      "Codex Security workbench did not return the requested scan identity."
    );
  }
  return scan;
}

async function canonicalDirectory(
  value: string,
  label: string
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
    ? value as Record<string, unknown>
    : undefined;
}

function defined<Key extends string, Value>(
  key: Key,
  value: Value | undefined
): Partial<Record<Key, Value>> {
  return value === undefined ? {} : { [key]: value } as Record<Key, Value>;
}
