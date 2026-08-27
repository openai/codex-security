import { constants, promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

type PythonPlatform = NodeJS.Platform;

interface ResolvePythonCommandOptions {
  configuredPython?: string;
  homeDirectory?: string;
  isUsableExecutable?: (candidate: string) => Promise<boolean>;
  platform?: PythonPlatform;
}

const MISSING_PYTHON_HELPER_MESSAGE = "Codex Security could not start its Python 3 helper. Reinstall or update Codex to restore its bundled Python runtime, or set the PYTHON environment variable to a working Python 3 executable, then restart Codex.";

/**
 * Resolve Python for each workbench invocation because Codex may finish installing
 * its primary runtime after the MCP server has already started.
 */
export async function resolvePythonCommand(options: ResolvePythonCommandOptions = {}): Promise<string> {
  const configuredPython = options.configuredPython ?? process.env.PYTHON;
  if (configuredPython?.trim()) {
    return configuredPython.trim();
  }

  const platform = options.platform ?? process.platform;
  const pathImplementation = platform === "win32" ? path.win32 : path.posix;
  const bundledPythonRoot = pathImplementation.join(
    options.homeDirectory ?? homedir(),
    ".cache",
    "codex-runtimes",
    "codex-primary-runtime",
    "dependencies",
    "python"
  );
  const bundledPythonCandidates = platform === "win32"
    ? [
        pathImplementation.join(bundledPythonRoot, "python.exe"),
        pathImplementation.join(bundledPythonRoot, "python", "python.exe"),
        pathImplementation.join(bundledPythonRoot, "bin", "python.exe")
      ]
    : [
        pathImplementation.join(bundledPythonRoot, "bin", "python3"),
        pathImplementation.join(bundledPythonRoot, "bin", "python")
      ];
  const isUsableExecutable = options.isUsableExecutable
    ?? ((candidate: string) => isUsablePythonExecutable(candidate, platform));
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
export async function isUsablePythonExecutable(candidate: string, platform: PythonPlatform): Promise<boolean> {
  try {
    const candidateStat = await fs.stat(candidate);
    if (!candidateStat.isFile()) {
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

/** Translate operating-system spawn failures without hiding Python process errors. */
export function missingPythonHelperMessage(error: unknown, pythonCommand: string): string | undefined {
  if (
    !error
    || typeof error !== "object"
    || !("code" in error)
    || typeof error.code !== "string"
    || !("path" in error)
    || error.path !== pythonCommand
  ) {
    return undefined;
  }
  return MISSING_PYTHON_HELPER_MESSAGE;
}
