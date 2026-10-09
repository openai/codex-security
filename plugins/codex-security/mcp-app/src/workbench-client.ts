import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { JsonObject } from "./types.js";
import { isRecord as isJsonObject } from "./record.js";
import { AsyncLock } from "./deep-scan/registry.js";
import {
  missingPythonHelperMessage,
  resolvePythonCommand,
} from "./python_command.js";
import {
  WORKBENCH_PYTHON,
  WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE,
} from "./server/workbench-process.js";

const execFileAsync = promisify(execFile);
const CONFIGURED_SCAN_ROOT = process.env.CODEX_SECURITY_SCAN_ROOT?.trim();
const CONFIGURED_WORKBENCH_STATE_DIR =
  process.env.CODEX_SECURITY_STATE_DIR?.trim();
export const PLUGIN_ROOT =
  process.env.CODEX_SECURITY_PLUGIN_ROOT || resolve(__dirname, "..");
const WORKBENCH_COMMANDS_WITHOUT_DATABASE = new Set([
  "resolve-scan-root",
  "inspect-target",
  "inspect-setup",
  "save-artifact",
  "read-artifact",
]);

let fallbackWorkbenchStateDir: Promise<string> | undefined;
let persistentWorkbenchStateSucceeded = false;
const workbenchStateSelectionLock = new AsyncLock();

export async function scanRoot(): Promise<string> {
  if (
    !CONFIGURED_SCAN_ROOT &&
    !CONFIGURED_WORKBENCH_STATE_DIR &&
    !persistentWorkbenchStateSucceeded &&
    !fallbackWorkbenchStateDir
  ) {
    // Select the workbench state before choosing its default artifact directory.
    await runWorkbench(["list-scans", "--limit", "1"]);
  }
  if (!CONFIGURED_SCAN_ROOT && fallbackWorkbenchStateDir) {
    return join(await fallbackWorkbenchStateDir, "scans");
  }
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
    return await executeWorkbenchWithStateSelection(
      pythonCommand,
      args,
      input,
      options,
    );
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

async function executeWorkbenchWithStateSelection(
  pythonCommand: string,
  args: string[],
  input: string | Buffer | undefined,
  options: WorkbenchOptions,
): Promise<JsonObject> {
  if (WORKBENCH_COMMANDS_WITHOUT_DATABASE.has(args[0] ?? "")) {
    return await executeWorkbench(
      pythonCommand,
      args,
      undefined,
      input,
      options,
    );
  }
  if (CONFIGURED_WORKBENCH_STATE_DIR) {
    return await executeWorkbench(
      pythonCommand,
      args,
      undefined,
      input,
      options,
    );
  }
  if (fallbackWorkbenchStateDir) {
    return await executeWorkbench(
      pythonCommand,
      args,
      await fallbackWorkbenchStateDir,
      input,
      options,
    );
  }
  if (persistentWorkbenchStateSucceeded) {
    return await executeWorkbench(
      pythonCommand,
      args,
      undefined,
      input,
      options,
    );
  }
  return await workbenchStateSelectionLock.run(async () => {
    if (fallbackWorkbenchStateDir) {
      return await executeWorkbench(
        pythonCommand,
        args,
        await fallbackWorkbenchStateDir,
        input,
        options,
      );
    }
    if (persistentWorkbenchStateSucceeded) {
      return await executeWorkbench(
        pythonCommand,
        args,
        undefined,
        input,
        options,
      );
    }
    try {
      const result = await executeWorkbench(
        pythonCommand,
        args,
        undefined,
        input,
        options,
      );
      persistentWorkbenchStateSucceeded = true;
      return result;
    } catch (error) {
      if (
        !isExecError(error) ||
        !("code" in error) ||
        error.code !== WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE
      )
        throw error;
      const fallbackStateDir = await pinFallbackWorkbenchStateDir();
      console.error(
        JSON.stringify({
          component: "codex_security_workbench",
          event: "state_fallback_pinned",
          reason: "persistent_sqlite_unwritable",
        }),
      );
      return await executeWorkbench(
        pythonCommand,
        args,
        fallbackStateDir,
        input,
        options,
      );
    }
  });
}

async function executeWorkbench(
  pythonCommand: string,
  args: string[],
  stateDir?: string,
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
      env: stateDir
        ? { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir }
        : process.env,
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

async function pinFallbackWorkbenchStateDir(): Promise<string> {
  fallbackWorkbenchStateDir ??= (async () => {
    const stateDir = CONFIGURED_SCAN_ROOT
      ? join(await scanRoot(), "workbench-state")
      : await fs.mkdtemp(join(tmpdir(), "codex-security-state-"));
    await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
    return stateDir;
  })();
  return await fallbackWorkbenchStateDir;
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
