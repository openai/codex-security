import { createHash } from "node:crypto";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { contractValuesEqual } from "./helpers/contract-validation";
import { object, stringifyJson } from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { resolvedPath } from "./helpers/resolve-path";
import { openScanLocalFile, readJsonObject } from "./workbench-files";
import { requireScan } from "./workbench-records";
import {
  expectedCoverageMode,
  requestedScanPaths,
  scanContract,
} from "./workbench-results";
import {
  pathWithinScope,
  WorkbenchValidationError,
} from "./workbench-validation";

export function workbenchCompletionBinding(
  scan: Row,
  completedAt: string,
  pluginRoot: string,
  sealedManifest: Record<string, unknown> | null = null,
): Record<string, unknown> {
  const contract = scanContract(scan),
    targetContract = contract["target"] as Record<string, unknown>;
  const manifest = readJsonObject(
    appendPath(resolvedPath(pluginRoot, false), ".codex-plugin/plugin.json"),
  );
  const version = manifest["version"];
  if (typeof version !== "string" || !version)
    throw new WorkbenchValidationError(
      "plugin.json: expected a nonempty Codex Security plugin version.",
    );
  const target: Record<string, unknown> = {
    targetId: targetContract["targetId"],
    displayName: targetContract["displayName"],
  };
  if (scan.get("mode") === "diff") {
    target["baseRevision"] = scan.get("diff_base_revision");
    target["headRevision"] = scan.get("diff_head_revision");
    if (
      scan.get("diff_target_kind") === "working_tree" &&
      scan.get("diff_content_digest")
    )
      target["snapshotDigest"] = scan.get("diff_content_digest");
  } else {
    if (scan.get("target_revision") !== "unversioned")
      target["revision"] = scan.get("target_revision");
    if (Object.hasOwn(targetContract, "requiredSnapshotDigest"))
      target["snapshotDigest"] = targetContract["requiredSnapshotDigest"];
  }
  const scope = {
    includePaths: requestedScanPaths(scan),
    excludePaths: (contract["scope"] as Record<string, unknown>)[
      "requiredExcludePaths"
    ],
  };
  const producer: Record<string, unknown> = {
    name: "codex-security-plugin",
    version,
  };
  const binding: Record<string, unknown> = {
    scanId: scan.get("id"),
    startedAt: scan.get("started_at"),
    completedAt,
    producer,
    target,
    allowedTargetKinds: targetContract["allowedKinds"],
    scope,
    coverageMode: expectedCoverageMode(scan),
  };
  const sealedScan = sealedManifest?.["scan"];
  if (object(sealedScan) && (sealedScan["sealedAt"] ?? null) !== null) {
    // Keep the original producer; finalization still validates schema, seal and owner.
    binding["startedAt"] = sealedScan["startedAt"] ?? null;
    binding["completedAt"] = sealedScan["completedAt"] ?? null;
    if (object(sealedScan["producer"]))
      producer["version"] = sealedScan["producer"]["version"] ?? null;
  }
  return binding;
}

export function verifyManifestBinding(
  scan: Row,
  manifest: Record<string, unknown>,
): void {
  const manifestScan = manifest["scan"];
  if (!object(manifestScan))
    throw new WorkbenchValidationError(
      "scan-manifest.json scan must be an object.",
    );
  if (!contractValuesEqual(manifestScan["id"] ?? null, scan.get("id")))
    throw new WorkbenchValidationError(
      "scan-manifest.json scan.id must match the workbench scan ID.",
    );
  const target = manifestScan["target"];
  if (!object(target))
    throw new WorkbenchValidationError(
      "scan-manifest.json scan.target must be an object.",
    );
  const expected = scanContract(scan)["target"] as Record<string, unknown>;
  const field = (key: string) =>
    Object.hasOwn(target, key) ? target[key] : null;
  if (!contractValuesEqual(field("targetId"), expected["targetId"]))
    throw new WorkbenchValidationError(
      "scan-manifest.json targetId must match the workbench target.",
    );
  if (!contractValuesEqual(field("displayName"), expected["displayName"]))
    throw new WorkbenchValidationError(
      "scan-manifest.json target displayName must match the workbench target.",
    );
  const kind = field("kind");
  if (!(expected["allowedKinds"] as string[]).includes(kind as string))
    throw new WorkbenchValidationError(
      "scan-manifest.json target kind must match the workbench target.",
    );
  if (
    scan.get("target_revision") !== "unversioned" &&
    (kind === "git_worktree" || kind === "git_revision") &&
    !contractValuesEqual(field("revision"), scan.get("target_revision"))
  )
    throw new WorkbenchValidationError(
      "scan-manifest.json target revision must match the workbench target.",
    );
  if (
    scan.get("mode") !== "diff" &&
    scan.get("target_snapshot_digest") !== null &&
    (kind === "directory_snapshot" || kind === "git_worktree") &&
    !contractValuesEqual(
      field("snapshotDigest"),
      scan.get("target_snapshot_digest"),
    )
  )
    throw new WorkbenchValidationError(
      "scan-manifest.json target snapshotDigest must match the workbench target snapshot.",
    );
  if (scan.get("mode") === "diff") {
    if (!scan.get("diff_target_kind"))
      throw new WorkbenchValidationError(
        "This migrated diff scan does not have a validated change set.",
      );
    if (
      !contractValuesEqual(
        field("baseRevision"),
        scan.get("diff_base_revision"),
      )
    )
      throw new WorkbenchValidationError(
        "scan-manifest.json target baseRevision must match the workbench diff target.",
      );
    if (
      !contractValuesEqual(
        field("headRevision"),
        scan.get("diff_head_revision"),
      )
    )
      throw new WorkbenchValidationError(
        "scan-manifest.json target headRevision must match the workbench diff target.",
      );
    if (
      scan.get("diff_target_kind") === "working_tree" &&
      !contractValuesEqual(
        field("snapshotDigest"),
        scan.get("diff_content_digest"),
      )
    )
      throw new WorkbenchValidationError(
        "scan-manifest.json target snapshotDigest must match the selected working-tree contents.",
      );
  }
  const scope = manifestScan["scope"];
  if (!object(scope))
    throw new WorkbenchValidationError(
      "scan-manifest.json scan.scope must be an object.",
    );
  const include = scope["includePaths"];
  if (!Array.isArray(include))
    throw new WorkbenchValidationError(
      "scan-manifest.json scope includePaths must be an array.",
    );
  if (
    !Array.isArray(scope["excludePaths"]) ||
    scope["excludePaths"].length !== 0
  )
    throw new WorkbenchValidationError(
      "scan-manifest.json scope excludePaths must match the workbench scan scope.",
    );
  const requested = scan.get("scope") as string;
  if (
    scan.get("mode") !== "diff" &&
    !contractValuesEqual(include, requestedScanPaths(scan))
  )
    throw new WorkbenchValidationError(
      "scan-manifest.json scope must match the workbench scan scope.",
    );
  for (const path of include)
    if (typeof path !== "string" || !pathWithinScope(path, requested))
      throw new WorkbenchValidationError(
        "scan-manifest.json scope must stay inside the workbench scan scope.",
      );
}

export function scanLocalFileDigest(scanDir: string, relative: string): string {
  const digest = createHash("sha256"),
    source = openScanLocalFile(scanDir, relative),
    buffer = Buffer.alloc(1024 * 1024);
  try {
    for (;;) {
      const count = source.read(buffer);
      if (!count) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally {
    source.close();
  }
  return `sha256:${digest.digest("hex")}`;
}
export function publishedManifestDigest(
  scanDir: string,
  manifest: Record<string, unknown>,
): string {
  const canonical =
    stringifyJson(manifest, { allowNan: false, sortKeys: true }) + "\n";
  const expected = `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
  const actual = scanLocalFileDigest(scanDir, "scan-manifest.json");
  if (actual !== expected)
    throw new WorkbenchValidationError(
      "The sealed scan manifest changed while it was being published.",
    );
  return expected;
}
export function requireRecordedManifestDigest(
  scan: Row,
  scanDir: string,
): void {
  const expected = scan.get("seal_manifest_digest");
  if (expected === null) return;
  if (scanLocalFileDigest(scanDir, "scan-manifest.json") !== expected)
    throw new WorkbenchValidationError(
      "The sealed scan manifest changed after completion.",
    );
}
export function pinLegacyManifestDigest(
  connection: Connection,
  scanId: string,
  manifestDigest: string,
): void {
  connection.prepare("BEGIN IMMEDIATE").run();
  connection.transaction(() => {
    const scan = requireScan(connection, scanId),
      current = scan.get("seal_manifest_digest");
    if (current !== null && current !== manifestDigest)
      throw new WorkbenchValidationError(
        "The sealed scan manifest changed after completion.",
      );
    if (current === null)
      connection
        .prepare("UPDATE scans SET seal_manifest_digest = ? WHERE id = ?")
        .run([manifestDigest, scan.get("id")]);
  });
}
