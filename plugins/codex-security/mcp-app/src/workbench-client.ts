import { execFile } from "node:child_process";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { JsonObject } from "./types.js";
import { isRecord } from "./record.js";
import {
  missingPythonHelperMessage,
  resolvePythonCommand,
} from "./python_command.js";
import { WORKBENCH_PYTHON } from "./server/workbench-process.js";

const execFileAsync = promisify(execFile);
const INSTRUCTION_COMMANDS = new Set([
  "begin-deep-scan",
  "start-headless-standard-scan",
  "start-prompt-only-scan",
  "start-scan",
]);
const configuredScanRoot = process.env.CODEX_SECURITY_SCAN_ROOT;
// A padded absolute or home-relative override must keep its original base.
const CONFIGURED_SCAN_ROOT =
  process.platform !== "win32" &&
  configuredScanRoot?.trimStart() === configuredScanRoot
    ? configuredScanRoot
    : configuredScanRoot?.trim();
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
  workerInstructionDigest?: string;
  signal?: AbortSignal;
}

export async function runWorkbench(
  args: string[],
  input?: string | Buffer,
  options: WorkbenchOptions = {},
): Promise<JsonObject> {
  const pythonCommand = await resolvePythonCommand({
    workingDirectory: PLUGIN_ROOT,
  });
  try {
    return await executeWorkbench(pythonCommand, args, input, options);
  } catch (error) {
    const message =
      missingPythonHelperMessage(error, pythonCommand) ??
      workbenchExitMessage(error, args[0]);
    if (message) throw new Error(message, { cause: error });
    throw error;
  }
}

function workbenchExitMessage(error: unknown, command: string) {
  if (!isRecord(error) || typeof error.stderr !== "string") return;
  const stderr = error.stderr.trim();
  if (stderr) return stderr;

  const operation = `Codex Security workbench ${command}`;
  if (typeof error.signal === "string")
    return `${operation} was terminated by signal ${error.signal}.`;
  if (typeof error.code === "number")
    return `${operation} exited with code ${error.code}.`;
}

function workbenchTimeout(args: string[]): number {
  const contextHandoff =
    args[0] === "mark-handoff-delivered" && args.includes("--return-context");
  const longRunningCommand = [
    "begin-deep-scan",
    "cancel-scan",
    "fail-scan",
    "record-deep-scan-iteration",
    "complete-scan",
    "export-findings",
    "finish-deep-scan",
    "finding-issues",
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
  ].includes(args[0] ?? "");
  return contextHandoff || longRunningCommand ? 300_000 : 30_000;
}

async function executeWorkbench(
  pythonCommand: string,
  args: string[],
  input?: string | Buffer,
  options: WorkbenchOptions = {},
): Promise<JsonObject> {
  const timeout = workbenchTimeout(args);
  const execution = execFileAsync(
    pythonCommand,
    [
      ...(options.isolatedPython ? ["-I", "-X", "utf8"] : []),
      "-B",
      "-c",
      WORKBENCH_PYTHON,
      workbenchScriptPath(),
    ],
    {
      cwd: PLUGIN_ROOT,
      signal: options.signal,
      windowsHide: true,
      env: {
        ...process.env,
        CODEX_MCP_NODE_PATH:
          process.env.CODEX_MCP_NODE_PATH || process.execPath,
        _CODEX_SECURITY_INSTRUCTION_ROOT: INSTRUCTION_COMMANDS.has(
          args[0] ?? "",
        )
          ? PLUGIN_ROOT
          : undefined,
        _CODEX_SECURITY_WORKER_INSTRUCTION_DIGEST:
          options.workerInstructionDigest,
      },
      encoding: "utf8" as const,
      maxBuffer: Infinity,
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
  if (!isRecord(result)) {
    throw new Error("Codex Security workbench helper returned invalid JSON.");
  }
  return result;
}

function workbenchScriptPath(): string {
  return join(PLUGIN_ROOT, "scripts", "workbench_db.py");
}
