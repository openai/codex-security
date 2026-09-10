import { dirname } from "node:path";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { contractValuesEqual } from "./helpers/contract-validation";
import { fileInfo } from "./helpers/helper-files";
import { JsonSyntaxError, object } from "./helpers/python-json";
import { appendPath, pathKey, relativePath } from "./helpers/rank-selection";
import { resolvedPath } from "./helpers/resolve-path";
import { parsedPath } from "./helpers/resolve-security-md";
import { JsonValueError, loadsJson } from "./helpers/scan-contract-json";
import { ContractError } from "./helpers/scan-contract-errors";
import { prepareScanFinalization } from "./helpers/scan-finalization";
import { schemaDirectory } from "./helpers/sealed-scan";
import { encodeUtf8, UnicodeDecodeError } from "./helpers/utf8";
import { requireScan } from "./workbench-records";
import { workbenchCompletionBinding } from "./workbench-binding";
import {
  artifactPath,
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { TargetInspectionError } from "./workbench-git-snapshot";
import { scanContract } from "./workbench-results";
import {
  requireScanTargetIdentity,
  scanTargetIdentity,
} from "./workbench-target";
import { requireTarget } from "./workbench-setup";
import { WorkbenchValidationError } from "./workbench-validation";

export interface ScanRecipe extends Record<string, unknown> {
  repository: string;
  mode: "standard" | "deep";
  config: Record<string, unknown>;
  target: Record<string, unknown> &
    (
      | { kind: "repository" | "paths"; paths: string[] }
      | {
          kind: "refs" | "working_tree";
          paths: string[];
          base: string;
          head: string;
        }
    );
}

function member(value: unknown, choices: readonly string[]): boolean {
  if (Array.isArray(value) || object(value))
    throw new TypeError(
      `unhashable type: '${Array.isArray(value) ? "list" : "dict"}'`,
    );
  return typeof value === "string" && choices.includes(value);
}

export function parseScanRecipe(value: string, repository: string): ScanRecipe {
  if (encodeUtf8(value).length > 256 * 1024)
    throw new WorkbenchValidationError(
      "Scan launch recipe must be no larger than 256 KiB.",
    );
  let recipe: unknown;
  try {
    recipe = loadsJson(value);
  } catch (error) {
    if (
      !(
        error instanceof TypeError ||
        error instanceof JsonSyntaxError ||
        error instanceof JsonValueError ||
        error instanceof UnicodeDecodeError
      )
    )
      throw error;
    throw new WorkbenchValidationError(
      "Scan launch recipe must be a valid JSON object.",
    );
  }
  if (!object(recipe))
    throw new WorkbenchValidationError(
      "Scan launch recipe must be a JSON object.",
    );
  repository = parsedPath(repository);
  const requestedRepository = recipe["repository"];
  if (
    typeof requestedRepository !== "string" ||
    pathKey(requireTarget(requestedRepository)) !== pathKey(repository)
  )
    throw new WorkbenchValidationError(
      "Scan launch recipe repository must match the scanned repository.",
    );
  if (!member(recipe["mode"], ["standard", "deep"]))
    throw new WorkbenchValidationError(
      "Scan launch recipe mode must be standard or deep.",
    );
  if (!object(recipe["config"]))
    throw new WorkbenchValidationError(
      "Scan launch recipe config must be a JSON object.",
    );
  const target = recipe["target"];
  if (
    !object(target) ||
    !member(target["kind"], ["repository", "paths", "refs", "working_tree"])
  )
    throw new WorkbenchValidationError(
      "Scan launch recipe target must identify a supported scan target.",
    );
  const paths = target["paths"];
  if (!Array.isArray(paths) || !paths.every((path) => typeof path === "string"))
    throw new WorkbenchValidationError(
      "Scan launch recipe target paths must be an array of strings.",
    );
  if (target["kind"] === "paths" && paths.length === 0)
    throw new WorkbenchValidationError(
      "A scoped scan launch recipe must include at least one target path.",
    );
  if (target["kind"] !== "paths" && paths.length !== 0)
    throw new WorkbenchValidationError(
      "Only scoped scan launch recipes can include target paths.",
    );
  for (const path of paths) {
    const candidate = appendPath(repository, path);
    if (
      !path ||
      path.startsWith("/") ||
      path.split("/").includes("..") ||
      path.includes("\\") ||
      path.includes("\0") ||
      (process.platform !== "win32" &&
        /[\ud800-\udc7f\udd00-\udfff]/u.test(path)) ||
      fileInfo(candidate) === undefined ||
      relativePath(
        resolvedPath(candidate, false, { preserveRelativeErrors: true }),
        repository,
      ) === undefined
    )
      throw new WorkbenchValidationError(
        "Scan launch recipe target paths must exist inside the repository.",
      );
  }
  if (target["kind"] === "refs" || target["kind"] === "working_tree") {
    if (
      typeof target["base"] !== "string" ||
      typeof target["head"] !== "string"
    )
      throw new WorkbenchValidationError(
        "Diff scan launch recipes require resolved base and head revisions.",
      );
  }
  return recipe as ScanRecipe;
}

export function setScanThread(
  connection: Connection,
  args: { scanId: string; threadId: string },
  now: () => string,
): { scanId: string; threadId: string } {
  const scan = requireScan(connection, args.scanId);
  connection.transaction(() => {
    connection
      .prepare(
        "UPDATE scans SET continuation_thread_id = ?, updated_at = ? WHERE id = ?",
      )
      .run([args.threadId, now(), scan.get("id")]);
  });
  return { scanId: scan.get("id") as string, threadId: args.threadId };
}

export function getScanRecipe(
  connection: Connection,
  args: { scanId: string },
): Record<string, unknown> {
  const scan = requireScan(connection, args.scanId);
  if (scan.get("recipe_json") === null)
    throw new WorkbenchValidationError(
      "This scan does not have a saved launch recipe.",
    );
  return {
    parentScanId: scan.get("parent_scan_id"),
    recipe: loadsJson(scan.get("recipe_json") as string | Buffer),
    scanId: scan.get("id"),
  };
}

export function cliScanResume(
  connection: Connection,
  scan: Row,
  workspace: Row,
): Record<string, unknown> {
  if (scan.get("mode") !== "deep" || scan.get("recipe_json") === null)
    throw new WorkbenchValidationError(
      "Resume requires a Deep Scan with a saved CLI launch recipe.",
    );
  if (scan.get("status") !== "running" || scan.get("canceled_at") !== null)
    throw new WorkbenchValidationError(
      "Resume requires a running scan; completed, failed, and canceled scans cannot resume.",
    );
  const threadId = scan.get("continuation_thread_id"),
    owner = scan.get("deep_scan_owner_thread_id") || workspace.get("thread_id");
  if (
    !threadId ||
    (owner !== null && owner !== threadId) ||
    scan.get("handoff_status") !== "delivered" ||
    scan.get("handoff_claim_token") !== null
  )
    throw new WorkbenchValidationError(
      "Resume requires the original owning CLI session.",
    );
  const run = connection
    .prepare(
      "SELECT status, cancel_requested FROM deep_scan_runs WHERE scan_id = ?",
    )
    .get([scan.get("id")]);
  if (
    run !== undefined &&
    (!["running", "succeeded"].includes(run.get("status") as string) ||
      run.get("cancel_requested"))
  )
    throw new WorkbenchValidationError(
      "This Deep Scan has stopped and cannot resume.",
    );
  let repository: string;
  try {
    repository = requireScanTargetIdentity({
      target_path: scan.get("target_path") as string,
      target_inode: scan.get("target_inode"),
    });
  } catch (error) {
    if (!(error instanceof TargetInspectionError)) throw error;
    throw new WorkbenchValidationError(
      "Cannot resume: the original checkout is missing or was replaced.",
    );
  }
  if (
    !contractValuesEqual(scanTargetIdentity(repository, null), [
      scan.get("target_revision"),
      scan.get("target_snapshot_digest"),
      scan.get("target_device"),
      scan.get("target_inode"),
    ])
  )
    throw new WorkbenchValidationError(
      "Cannot resume: the original checkout revision or contents changed.",
    );
  const recipe = parseScanRecipe(scan.get("recipe_json") as string, repository),
    scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    ),
    progress = connection
      .prepare("SELECT scope_file_count FROM scan_progress WHERE scan_id = ?")
      .get([scan.get("id")]);
  const result: Record<string, unknown> = {
    contract: scanContract(scan),
    recipe,
    scanDir,
    scanId: scan.get("id"),
    scopeFileCount: progress!.get("scope_file_count"),
    startedAt: scan.get("started_at"),
    targetId: scan.get("target_id"),
    targetRevision: scan.get("target_revision"),
    threadId,
    userContext: scan.get("user_context"),
  };
  // Active coordinators may still be writing drafts. Validate sealed results
  // before attaching to a coordinator that has finished.
  if (run?.get("status") === "succeeded") {
    const manifestPath = artifactPath(scanDir, "scan-manifest.json", false);
    if (manifestPath !== null) {
      const manifest = readJsonObject(manifestPath),
        manifestScan = manifest["scan"];
      if (
        object(manifestScan) &&
        ((manifestScan["sealedAt"] ?? null) !== null ||
          (manifestScan["artifacts"] ?? null) !== null)
      ) {
        try {
          const binding = workbenchCompletionBinding(
            scan,
            scan.get("started_at") as string,
            dirname(schemaDirectory()),
            manifest,
          );
          prepareScanFinalization(scanDir, undefined, {
            expectedCoverageMode: binding["coverageMode"] as string,
            completionBinding: binding,
          });
          result["sealedProducerVersion"] = (
            manifestScan["producer"] as Record<string, unknown>
          )["version"];
        } catch (error) {
          if (!(error instanceof ContractError)) throw error;
          throw new WorkbenchValidationError(
            `Cannot resume sealed scan: ${error.message}`,
          );
        }
      }
    }
  }
  return result;
}
