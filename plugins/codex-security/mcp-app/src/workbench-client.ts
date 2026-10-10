import { execFile } from "node:child_process";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { JsonObject } from "./types.js";
import { isRecord as isJsonObject } from "./record.js";
import {
  missingPythonHelperMessage,
  resolvePythonCommand,
} from "./python_command.js";
import { WORKBENCH_PYTHON } from "./server/workbench-process.js";

const execFileAsync = promisify(execFile);
const CONFIGURED_SCAN_ROOT = process.env.CODEX_SECURITY_SCAN_ROOT?.trim();
export const PLUGIN_ROOT =
  process.env.CODEX_SECURITY_PLUGIN_ROOT || resolve(__dirname, "..");

export async function scanRoot(): Promise<string> {
  const result = await runWorkbench([
    "resolve-scan-root",
    ...(CONFIGURED_SCAN_ROOT ? [`--scan-root=${CONFIGURED_SCAN_ROOT}`] : []),
  ]);
  if (typeof result.scanRoot !== "string")
    throw new Error("Missing scan artifact root.");
  return result.scanRoot;
}

interface WorkbenchOptions {
  isolatedPython?: boolean;
}

export async function runWorkbench(
  args: string[],
  input?: string | Buffer,
  options: WorkbenchOptions = {},
): Promise<JsonObject> {
  let pythonCommand: string | undefined;
  try {
    pythonCommand = await resolvePythonCommand();
    return await executeWorkbench(pythonCommand, args, input, options);
  } catch (error) {
    const launchError = pythonCommand
      ? missingPythonHelperMessage(error, pythonCommand)
      : undefined;
    if (launchError) {
      throw new Error(launchError, { cause: error });
    }
    if (isExecError(error) && error.stderr.trim()) {
      throw new Error(error.stderr.trim(), { cause: error });
    }
    throw error;
  }
}

async function executeWorkbench(
  pythonCommand: string,
  args: string[],
  input?: string | Buffer,
  options: WorkbenchOptions = {},
): Promise<JsonObject> {
  const timeout = [
    "begin-deep-scan",
    "cancel-scan",
    "fail-scan",
    "claim-deep-scan-dedup",
    "commit-deep-scan-dedup",
    "complete-scan",
    "export-findings",
    "finish-deep-scan",
    "get-scan",
    "get-deep-scan",
    "get-workspace",
    "inspect-setup",
    "list-findings",
    "preserve-scan-results",
    "recover-scan-results",
    "request-finding-remediation",
    "request-finding-remediation-action",
    "save-workspace",
    "set-finding-triage",
    "set-finding-remediation",
    "start-headless-standard-scan",
    "start-prompt-only-scan",
    "start-scan",
    "upsert-deep-scan-worker",
  ].includes(args[0] ?? "")
    ? 300_000
    : 30_000;
  const execution = execFileAsync(
    pythonCommand,
    [
      ...(options.isolatedPython ? ["-I", "-X", "utf8", "-B"] : []),
      "-c",
      WORKBENCH_PYTHON,
      workbenchScriptPath(),
    ],
    {
      cwd: PLUGIN_ROOT,
      windowsHide: true,
      env: process.env,
      encoding: "utf8" as const,
      // Artifact bytes are base64-encoded here; retain the existing file-size behavior.
      maxBuffer: args[0] === "read-artifact" ? Infinity : 4 * 1024 * 1024,
      timeout,
    },
  );
  execution.child.stdin!.on("error", () => {
    // The workbench may exit before consuming stdin; surface its process error.
  });
  // Match native argv's UTF-8 encoding while framing NUL separately from stdin.
  execution.child.stdin!.write(
    `${JSON.stringify(args.map((argument) => argument.toWellFormed()))}\n`,
  );
  execution.child.stdin!.end(input);
  const { stdout } = await execution.catch((error: unknown) => {
    if (
      error instanceof Error &&
      "killed" in error &&
      error.killed === true &&
      "signal" in error &&
      error.signal === "SIGTERM"
    ) {
      throw new Error(
        `Codex Security workbench ${args[0]} timed out after ${timeout / 1000} seconds: ${error.message}`,
        { cause: error },
      );
    }
    throw error;
  });
  const result = JSON.parse(stdout) as unknown;
  if (!isJsonObject(result)) {
    throw new Error("Codex Security workbench helper returned invalid JSON.");
  }
  return result;
}

function workbenchScriptPath(): string {
  return join(PLUGIN_ROOT, "scripts", "workbench_db.py");
}

function isExecError(error: unknown): error is { stderr: string } {
  return Boolean(
    error &&
    typeof error === "object" &&
    "stderr" in error &&
    typeof error.stderr === "string",
  );
}
