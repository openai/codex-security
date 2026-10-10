import { spawn } from "node:child_process";
import { constants, promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

type PythonPlatform = NodeJS.Platform;

interface ResolvePythonCommandOptions {
  cacheDirectory?: string;
  configuredPython?: string;
  homeDirectory?: string;
  isUsableExecutable?: (candidate: string) => Promise<boolean>;
  platform?: PythonPlatform;
}

const MISSING_PYTHON_HELPER_MESSAGE =
  "Codex Security could not start its Python 3 helper. Reinstall or update Codex to restore its bundled Python runtime, or set the PYTHON environment variable to a working Python 3 executable, then restart Codex.";

/**
 * Resolve Python for each workbench invocation because Codex may finish installing
 * its primary runtime after the MCP server has already started.
 */
export async function resolvePythonCommand(
  options: ResolvePythonCommandOptions = {},
): Promise<string> {
  if (
    options.configuredPython === undefined &&
    process.env.CODEX_SECURITY_PYTHON_COMMAND
  ) {
    return process.env.CODEX_SECURITY_PYTHON_COMMAND;
  }
  const configuredPython = options.configuredPython ?? process.env.PYTHON;
  if (configuredPython?.trim()) {
    return configuredPython.trim();
  }

  const platform = options.platform ?? process.platform;
  const pathImplementation = platform === "win32" ? path.win32 : path.posix;
  const cacheDirectory =
    (options.cacheDirectory ?? process.env.XDG_CACHE_HOME) ||
    pathImplementation.join(options.homeDirectory ?? homedir(), ".cache");
  const bundledPythonRoot = pathImplementation.join(
    cacheDirectory,
    "codex-runtimes",
    "codex-primary-runtime",
    "dependencies",
    "python",
  );
  const bundledPythonCandidates =
    platform === "win32"
      ? [
          pathImplementation.join(bundledPythonRoot, "python.exe"),
          pathImplementation.join(bundledPythonRoot, "python", "python.exe"),
          pathImplementation.join(bundledPythonRoot, "bin", "python.exe"),
        ]
      : [
          pathImplementation.join(bundledPythonRoot, "bin", "python3"),
          pathImplementation.join(bundledPythonRoot, "bin", "python"),
        ];
  const isUsableExecutable =
    options.isUsableExecutable ??
    ((candidate: string) => isUsablePythonExecutable(candidate, platform));
  for (const candidate of bundledPythonCandidates) {
    if (await isUsableExecutable(candidate)) {
      return candidate;
    }
  }
  return platform === "win32" ? "python" : "python3";
}

/**
 * Windows does not use POSIX execute bits, so a regular .exe file is the most
 * reliable preflight available there. Actual spawn failures are normalized below.
 */
export async function isUsablePythonExecutable(
  candidate: string,
  platform: PythonPlatform,
): Promise<boolean> {
  try {
    if (!(await fs.stat(candidate)).isFile()) {
      return false;
    }
    if (platform !== "win32") {
      await fs.access(candidate, constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

/** Add installation advice to missing-runtime errors without hiding their cause. */
export function missingPythonHelperMessage(
  error: unknown,
  pythonCommand: string,
): string | undefined {
  if (
    !error ||
    typeof error !== "object" ||
    !("code" in error) ||
    error.code !== "ENOENT" ||
    !("path" in error) ||
    error.path !== pythonCommand
  ) {
    return undefined;
  }
  return `${error instanceof Error ? error.message : String(error)}\n${MISSING_PYTHON_HELPER_MESSAGE}`;
}

/** Run an existing Python helper with in-memory input and preserve its output. */
export function runPythonWithInput(
  python: string,
  args: string[],
  input: string | Buffer,
  label: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(python, args, {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const output: string[] = [],
      errors: string[] = [];
    child.stdout
      .setEncoding("utf8")
      .on("data", (chunk: string) => output.push(chunk));
    child.stderr
      .setEncoding("utf8")
      .on("data", (chunk: string) => errors.push(chunk));
    let inputError: Error | undefined;
    child.on("error", reject);
    child.stdin.on("error", (error: Error) => {
      inputError = error;
    });
    child.on("close", (code, signal) => {
      const detail = errors.join("").trim();
      if (code !== 0 && detail) reject(new Error(detail));
      else if (inputError) reject(inputError);
      else if (code === 0) resolve(output.join(""));
      else reject(new Error(`${label} exited with ${signal ?? code}.`));
    });
    child.stdin.end(input);
  });
}
