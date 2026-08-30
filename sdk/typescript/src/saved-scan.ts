import { lstat } from "node:fs/promises";
import { resolve } from "node:path";
import type { JsonObject, JsonValue } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { expandHome } from "./runtime.js";

export type SavedScan = JsonObject & { scanId: string; scanDir: string };

export interface SavedScanDependencies {
  currentDirectory(): string;
  runWorkbench(args: readonly string[], input?: string): Promise<JsonObject>;
}

export async function resolveWorkflowScan(
  workflowId: string,
  dependencies: SavedScanDependencies,
): Promise<{ scanId: string; scanDir: string }> {
  const context = await dependencies.runWorkbench(
    ["finding-workflow"],
    JSON.stringify({ id: workflowId, action: "get" }),
  );
  const workflow = context["workflow"];
  if (
    workflow === undefined ||
    !isJsonObject(workflow) ||
    typeof workflow["scanId"] !== "string" ||
    typeof workflow["scanDir"] !== "string"
  ) {
    throw new CodexSecurityError(
      `Workflow ${workflowId} has no saved scan. Start it with scan --workflow-id ${workflowId}.`,
    );
  }
  return { scanId: workflow["scanId"], scanDir: workflow["scanDir"] };
}

export async function resolveCompletedScan(
  requestedId: string,
  dependencies: SavedScanDependencies,
): Promise<SavedScan> {
  let scanId = requestedId;
  if (scanId === "latest") {
    const history = await dependencies.runWorkbench([
      "list-scans",
      "--repository",
      resolve(dependencies.currentDirectory()),
      "--status",
      "complete",
    ]);
    const scans = history["scans"];
    const latest = Array.isArray(scans) ? scans[0] : undefined;
    if (
      latest === undefined ||
      !isJsonObject(latest) ||
      typeof latest["scanId"] !== "string"
    ) {
      throw new CodexSecurityError(
        "No completed saved scan was found for this repository.",
      );
    }
    scanId = latest["scanId"];
  }
  const context = await dependencies.runWorkbench([
    "get-scan",
    "--scan-id",
    scanId,
  ]);
  const scan = context["scan"];
  if (
    scan === undefined ||
    !isJsonObject(scan) ||
    typeof scan["scanId"] !== "string"
  ) {
    throw new CodexSecurityError(`Could not read saved scan ${scanId}.`);
  }
  scanId = scan["scanId"];
  const progress = scan["progress"];
  if (
    progress === undefined ||
    !isJsonObject(progress) ||
    progress["status"] !== "complete"
  ) {
    throw new CodexSecurityError(`Scan ${scanId} is not complete.`);
  }
  const storedDirectory = scan["scanDir"];
  const scanDir =
    typeof storedDirectory === "string" && storedDirectory.length > 0
      ? resolve(dependencies.currentDirectory(), expandHome(storedDirectory))
      : undefined;
  const metadata =
    scanDir === undefined
      ? undefined
      : await lstat(scanDir).catch(() => undefined);
  if (scanDir === undefined || metadata?.isDirectory() !== true) {
    throw new CodexSecurityError(
      `Artifacts for scan ${scanId} are unavailable. Restore the completed scan artifacts or run a new scan.`,
    );
  }
  return { ...scan, scanId, scanDir };
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
