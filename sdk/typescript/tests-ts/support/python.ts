import {
  PLUGIN_PYTHON_PROBE,
  PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
  PLUGIN_PYTHON_READY,
} from "../../src/plugin-python-probe.js";
import { runNodePython } from "./python-probe.js";

export function pythonExecutable(inheritEnvironment = true): string | null {
  const configured = inheritEnvironment
    ? process.env["PYTHON"]?.trim()
    : undefined;
  if (configured) return configured;
  if (process.platform !== "win32")
    return Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");

  // Windows Store aliases can resolve on PATH even without an interpreter.
  for (const name of ["python", "python3", "py"]) {
    const candidate = Bun.which(name);
    if (candidate === null) continue;
    const result = runNodePython(candidate, ["-c", PLUGIN_PYTHON_PROBE], {
      timeout: PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
      windowsHide: true,
    });
    if (result.status === 0 && result.stdout.trim() === PLUGIN_PYTHON_READY)
      return candidate;
  }
  return null;
}
