import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import type { Connection } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { encodePosixPath } from "./helpers/posix-path";
import { preflightInteger } from "./helpers/preflight-config";
import {
  jsonContains,
  jsonTypeName,
  object,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import {
  ContractError,
  RecoverableContractError,
} from "./helpers/scan-contract-errors";
import {
  finalizeScan,
  prepareScanFinalization,
  writePreparedScanFinalization,
} from "./helpers/scan-finalization";
import { schemaDirectory } from "./helpers/sealed-scan";
import {
  pinLegacyManifestDigest,
  publishedManifestDigest,
  requireRecordedManifestDigest,
  verifyManifestBinding,
  workbenchCompletionBinding,
} from "./workbench-binding";
import { withScanCompletionLock } from "./workbench-completion-lock";
import { requireDeepScanReadyForParentCompletion } from "./workbench-deep-state";
import {
  artifactPath,
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { indexFindings } from "./workbench-finding-index";
import { requireCurrentContinuation } from "./workbench-handoff";
import {
  mergeSavedResults,
  type SavedMergeBinding,
} from "./workbench-merge-saved-results";
import type { PreservedResultsContext } from "./workbench-preserve-saved-results";
import { requireScan } from "./workbench-records";
import {
  expectedCoverageMode,
  resultCallbacks,
  scanContext,
} from "./workbench-results";
import { failScanLocked } from "./workbench-scan-stop";
import {
  collectScanUsage,
  measuredScanCostJson,
  reconcileCompletedScanCost,
} from "./workbench-scan-usage";
import { scanTargetWarning, type SnapshotScan } from "./workbench-target";
import {
  parseScanCost,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

type Table = Record<string, unknown>;
export interface CompleteScanArguments {
  scanId: string;
  claimToken: string | null;
  costJson: string | null;
  threadId?: string | null;
}
export interface CompletionOptions {
  prepareOnly?: boolean;
  threadId?: string | null;
}
const artifacts = {
  coverage: "coverage.json",
  findings: "findings.json",
  manifest: "scan-manifest.json",
  markdownReport: "report.md",
};
const json = (value: unknown) => stringifyJson(value, { compact: true });

export function completeScan(
  context: PreservedResultsContext,
  connection: Connection,
  args: CompleteScanArguments,
  prepareOnly = false,
): Table {
  const scanId = requireUuid(args.scanId, "scan-id"),
    costJson = prepareOnly ? null : parseScanCost(args.costJson);
  return withScanCompletionLock(scanId, () =>
    completeScanLocked(context, connection, scanId, args.claimToken, costJson, {
      prepareOnly,
      threadId: args.threadId ?? null,
    }),
  );
}

export function completeScanLocked(
  context: PreservedResultsContext,
  connection: Connection,
  scanId: string,
  claimToken: string | null,
  costJson: string | null,
  { prepareOnly = false, threadId = null }: CompletionOptions = {},
): Table {
  let scan = requireScan(connection, scanId);
  if (scan.get("status") === "complete") {
    const scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    );
    requireRecordedManifestDigest(scan, scanDir);
    verifyManifestBinding(
      scan,
      readJsonObject(appendPath(scanDir, artifacts.manifest)),
    );
    let manifest: Table;
    try {
      [manifest] = finalizeScan(scanDir, undefined, undefined, {
        expectedCoverageMode: expectedCoverageMode(scan),
        reportAttempts: 5,
      });
    } catch (error) {
      if (!(error instanceof ContractError)) throw error;
      throw new WorkbenchValidationError(error.message);
    }
    verifyManifestBinding(scan, manifest);
    pinLegacyManifestDigest(
      connection,
      scan.get("id") as string,
      publishedManifestDigest(scanDir, manifest),
    );
    if (costJson !== null && scan.get("recipe_json") !== null)
      reconcileCompletedScanCost(connection, scan, costJson);
    return scanContext(connection, scan.get("id") as string, resultCallbacks);
  }
  if (scan.get("status") !== "running")
    throw new WorkbenchValidationError("Only a running scan can be completed.");
  requireCurrentContinuation(scan, claimToken, {
    errorMessage: "Scan completion is owned by another continuation.",
  });
  requireDeepScanReadyForParentCompletion(connection, scan);
  const warnings = parseJson(
      scan.get("completion_warnings_json") as string | Buffer,
      false,
      preflightInteger,
    ) as string[],
    targetWarnings: string[] = [];
  const addWarning = () => {
    const warning = scanTargetWarning(
      scan.toObject() as unknown as SnapshotScan,
    );
    if (warning !== null)
      for (const values of [targetWarnings, warnings]) {
        if (jsonContains(values, warning)) continue;
        if (!Array.isArray(values))
          throw new TypeError(
            `'${jsonTypeName(values)}' object has no attribute 'append'`,
          );
        values.push(warning);
      }
  };
  addWarning();
  const scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    ),
    completionTimestamp = context.now(),
    currentManifestPath = artifactPath(scanDir, artifacts.manifest, false),
    currentManifest =
      currentManifestPath === null ? null : readJsonObject(currentManifestPath),
    currentScan = currentManifest?.["scan"];
  if (object(currentScan) && currentScan["complete"] === false)
    throw new WorkbenchValidationError(
      "The latest saved scan draft is incomplete; continue the scan before completing it.",
    );
  const alreadySealed =
    object(currentScan) &&
    ((currentScan["sealedAt"] ?? null) !== null ||
      (currentScan["artifacts"] ?? null) !== null);
  const binding = workbenchCompletionBinding(
    scan,
    completionTimestamp,
    dirname(schemaDirectory()),
    currentManifest,
  );
  if (scan.get("recipe_json") !== null) {
    const missing: string[] = [];
    for (const name of [
      artifacts.manifest,
      artifacts.findings,
      artifacts.coverage,
    ]) {
      const path = appendPath(scanDir, name);
      try {
        if (process.platform === "win32")
          windowsFileSystem(windowsBinding()).stat(widePath(path), false);
        else lstatSync(encodePosixPath(path));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        missing.push(name);
        continue;
      }
      artifactPath(scanDir, name, true);
    }
    if (missing.length)
      throw new WorkbenchValidationError(
        `Scan agent did not create required draft artifacts: ${missing.join(", ")}. Check that the scan agent can run shell commands and write to the scan directory before retrying.`,
      );
  }
  let wrote = false,
    manifest: Table,
    findings: Table;
  try {
    const prepared = prepareScanFinalization(scanDir, undefined, {
      expectedCoverageMode: expectedCoverageMode(scan),
      reportAttempts: 5,
      completionBinding: binding,
      completionWarnings: scan.get("mode") !== "deep" ? warnings : null,
      // Save a completed Deep result as submitted; recovery owns stopped drafts.
      draftDocuments:
        scan.get("mode") !== "deep" &&
        currentManifestPath !== null &&
        !alreadySealed
          ? mergeSavedResults(
              scanDir,
              scan.get("id") as string,
              binding as unknown as SavedMergeBinding,
              connection
                .prepare(
                  "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
                )
                .all([scan.get("id")]),
              warnings,
              { stopped: false, reason: "" },
            )
          : null,
    });
    addWarning();
    wrote = true;
    [manifest, findings] = writePreparedScanFinalization(prepared);
  } catch (error) {
    if (!(error instanceof ContractError)) throw error;
    if (
      wrote ||
      (scan.get("mode") === "deep" &&
        !alreadySealed &&
        !(error instanceof RecoverableContractError))
    )
      failScanLocked(context, connection, {
        claimToken,
        costJson,
        message: error.message,
        scanId,
      });
    throw new WorkbenchValidationError(error.message);
  }
  const paths = Object.fromEntries(
      Object.entries(artifacts).map(([kind, filename]) => [
        kind,
        artifactPath(scanDir, filename, true),
      ]),
    ),
    manifestDigest = publishedManifestDigest(scanDir, manifest);
  if (prepareOnly) {
    connection.prepare("BEGIN IMMEDIATE").run();
    try {
      const updated = connection
        .prepare(
          "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
        )
        .run([json(warnings), scan.get("id")]);
      if (updated.rowcount !== 1n)
        throw new WorkbenchValidationError(
          "Only a running scan can be prepared for completion.",
        );
      connection.commit();
    } catch (error) {
      connection.rollback();
      throw error;
    }
    return {
      ...scanContext(connection, scan.get("id") as string, resultCallbacks),
      targetWarnings,
    };
  }
  if (costJson === null)
    costJson = parseScanCost(
      measuredScanCostJson(
        collectScanUsage(connection, scan, threadId, completionTimestamp),
      ),
    );
  connection.prepare("BEGIN IMMEDIATE").run();
  try {
    const timestamp = (manifest["scan"] as Table)["completedAt"] as string;
    scan = requireScan(connection, scan.get("id") as string);
    if (scan.get("status") === "complete") {
      connection.commit();
      return scanContext(connection, scan.get("id") as string, resultCallbacks);
    }
    if (scan.get("status") !== "running")
      throw new WorkbenchValidationError(
        "Only a running scan can be completed.",
      );
    requireDeepScanReadyForParentCompletion(connection, scan);
    requireCurrentContinuation(scan, claimToken, {
      errorMessage: "Scan completion is owned by another continuation.",
    });
    connection
      .prepare("DELETE FROM scan_artifacts WHERE scan_id = ?")
      .run([scan.get("id")]);
    for (const [kind, path] of Object.entries(paths))
      if (path !== null)
        connection
          .prepare(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
          )
          .run([scan.get("id"), kind, path, timestamp]);
    connection
      .prepare("DELETE FROM finding_occurrences WHERE scan_id = ?")
      .run([scan.get("id")]);
    indexFindings(connection, scan.get("id") as string, findings, timestamp);
    const count = (findings["findings"] as unknown[]).length,
      artifactCount = Object.keys(paths).length;
    connection
      .prepare(
        `UPDATE scan_progress
      SET reportable_findings_count = ?, phase_items_total = ?,
          phase_items_completed = ?, phase_progress_unit = 'report_artifacts', updated_at = ?
      WHERE scan_id = ?`,
      )
      .run([
        BigInt(count),
        BigInt(artifactCount),
        BigInt(artifactCount),
        timestamp,
        scan.get("id"),
      ]);
    const updated = connection
      .prepare(
        `UPDATE scans
      SET status = 'complete', phase = 'reporting', completed_at = ?, updated_at = ?,
          seal_manifest_digest = ?, cost_json = ?, completion_warnings_json = ?
      WHERE id = ? AND status = 'running'`,
      )
      .run([
        timestamp,
        timestamp,
        manifestDigest,
        costJson,
        json(warnings),
        scan.get("id"),
      ]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Only a running scan can be completed.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return {
    ...scanContext(connection, scan.get("id") as string, resultCallbacks),
    targetWarnings,
  };
}
