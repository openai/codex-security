import { execFile as execFileCallback } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  PLUGIN_ROOT,
  SecurityError,
  ensureDirectory,
  isFile,
  stateDirectory,
} from "./util.mjs";

const execFile = promisify(execFileCallback);

const MIN_PYTHON = [3, 10];

/**
 * The workbench entry point is workbench_db.py, not workbench_cli.py: the
 * latter only declares the argument parser and exits without dispatching.
 */
const WORKBENCH_ENTRY = join(PLUGIN_ROOT, "scripts", "workbench_db.py");
const FINALIZER = join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py");
const SCHEMA_DIR = join(PLUGIN_ROOT, "schemas");

let resolvedPython = null;

export async function resolvePython(explicit) {
  if (explicit !== undefined && explicit !== null && explicit !== "") {
    await requireUsablePython(explicit);
    return explicit;
  }
  if (resolvedPython !== null) return resolvedPython;
  const fromEnvironment = process.env["PYTHON"];
  const candidates = [
    ...(fromEnvironment ? [fromEnvironment] : []),
    ...(process.platform === "win32" ? ["python", "python3"] : ["python3", "python"]),
  ];
  const failures = [];
  for (const candidate of candidates) {
    try {
      await requireUsablePython(candidate);
      resolvedPython = candidate;
      return candidate;
    } catch (error) {
      failures.push(`${candidate}: ${error.message}`);
    }
  }
  throw new SecurityError(
    `The security plugin requires Python ${MIN_PYTHON.join(".")} or later, but no usable interpreter was found. ` +
      `Pass --python, set PYTHON, or add python3 to PATH. Tried:\n  ${failures.join("\n  ")}`,
  );
}

async function requireUsablePython(command) {
  let stdout;
  try {
    ({ stdout } = await execFile(
      command,
      ["-c", "import sys;print('%d.%d' % sys.version_info[:2])"],
      { encoding: "utf8", windowsHide: true, timeout: 20_000 },
    ));
  } catch (error) {
    throw new Error(error.code === "ENOENT" ? "not found" : String(error.message).trim());
  }
  const [major, minor] = stdout.trim().split(".").map((part) => Number.parseInt(part, 10));
  if (
    !Number.isInteger(major) ||
    !Number.isInteger(minor) ||
    major < MIN_PYTHON[0] ||
    (major === MIN_PYTHON[0] && minor < MIN_PYTHON[1])
  ) {
    throw new Error(`Python ${stdout.trim()} is older than ${MIN_PYTHON.join(".")}`);
  }
  if (major === 3 && minor === 10) {
    try {
      await execFile(command, ["-c", "import tomli"], { windowsHide: true, timeout: 20_000 });
    } catch {
      throw new Error("Python 3.10 also requires the tomli package");
    }
  }
}

/**
 * Environment for every plugin helper.
 *
 * The Python workbench predates this port and still reads the CODEX_SECURITY_*
 * and CODEX_HOME names for its state directory, so those are set here from the
 * Claude-side values rather than editing several hundred kilobytes of helpers.
 */
export function workbenchEnvironment(python, extra = {}) {
  const state = stateDirectory();
  return {
    ...process.env,
    PYTHON: python,
    PYTHONIOENCODING: "utf-8",
    PYTHONUTF8: "1",
    CODEX_HOME: state,
    CODEX_SECURITY_STATE_DIR: state,
    CLAUDE_SECURITY_STATE_DIR: state,
    ...extra,
  };
}

export async function runWorkbench(options, args) {
  const python = options.python;
  const environment = options.environment ?? workbenchEnvironment(python);
  await ensureDirectory(stateDirectory());
  let stdout;
  try {
    ({ stdout } = await execFile(python, ["-I", "-B", WORKBENCH_ENTRY, ...args], {
      env: environment,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true,
      signal: options.signal,
    }));
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const detail = processErrorDetail(error);
    const databaseFailure =
      /unable to open database file|readonly database|disk i\/o error/iu.test(detail);
    const failure = options.failureMessage ?? "Could not run the security workbench";
    throw new SecurityError(
      databaseFailure
        ? `${failure}: cannot open the workbench database at ${join(
            stateDirectory(),
            "workbench.sqlite3",
          )}. Ensure the state directory is writable, or set CLAUDE_SECURITY_STATE_DIR to a writable directory outside the scanned repository.`
        : `${failure}: ${detail}`,
      { cause: error },
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new SecurityError("The security workbench returned invalid JSON.", {
      cause: error,
    });
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new SecurityError("The security workbench returned an invalid response.");
  }
  return parsed;
}

/**
 * Seals the scan contract and generates report.md plus SARIF.
 *
 * This is the same deterministic finalizer the original plugin used; the model
 * never writes report.md itself, which is what keeps the report faithful to the
 * canonical JSON regardless of which model ran the scan.
 */
export async function finalizeScanContract(options) {
  if (!(await isFile(FINALIZER))) {
    throw new SecurityError(`The plugin finalizer is missing: ${FINALIZER}`);
  }
  const args = [
    "-I",
    "-B",
    FINALIZER,
    "--scan-dir",
    options.scanDir,
    "--schema-dir",
    SCHEMA_DIR,
    ...(options.sourceRoot === undefined ? [] : ["--source-root", options.sourceRoot]),
  ];
  try {
    const { stdout } = await execFile(options.python, args, {
      env: options.environment ?? workbenchEnvironment(options.python),
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true,
      signal: options.signal,
    });
    return stdout.trim();
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new SecurityError(
      `Could not finalize the scan contract: ${processErrorDetail(error)}`,
      { cause: error },
    );
  }
}

export async function runPluginScript(options, script, args) {
  const path = join(PLUGIN_ROOT, "scripts", script);
  try {
    const { stdout } = await execFile(options.python, ["-I", "-B", path, ...args], {
      env: options.environment ?? workbenchEnvironment(options.python),
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      signal: options.signal,
    });
    return stdout;
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new SecurityError(`${script} failed: ${processErrorDetail(error)}`, {
      cause: error,
    });
  }
}

export function processErrorDetail(error) {
  if (error === null || typeof error !== "object") return String(error);
  const stderr = typeof error.stderr === "string" ? error.stderr.trim() : "";
  if (stderr !== "") return stderr.split("\n").slice(-6).join("\n");
  const stdout = typeof error.stdout === "string" ? error.stdout.trim() : "";
  if (stdout !== "") return stdout.split("\n").slice(-6).join("\n");
  return String(error.message ?? error);
}
