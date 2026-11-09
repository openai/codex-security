import { beforeAll } from "bun:test";
import {
  PLUGIN_PYTHON_PROBE,
  PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
  PLUGIN_PYTHON_READY,
} from "../../src/plugin-python-probe.js";
import { runNodePython } from "./python-probe.js";

// Tests can change and restore PATH. Reuse the probes for each ordered set of candidates.
const windowsPythonByCandidates = new Map<string, string | null>();

function findWindowsPython(): string | null {
  const candidates = ["python", "python3", "py"].map((name) =>
    Bun.which(name, { PATH: process.env["PATH"] ?? "" }),
  );
  const key = JSON.stringify(candidates);
  const cached = windowsPythonByCandidates.get(key);
  if (cached !== undefined) return cached;
  // Windows Store aliases can resolve on PATH even without an interpreter.
  const executable =
    candidates.find((candidate) => {
      if (candidate === null) return false;
      const result = runNodePython(candidate, ["-c", PLUGIN_PYTHON_PROBE], {
        timeout: PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
        windowsHide: true,
      });
      return (
        result.status === 0 && result.stdout.trim() === PLUGIN_PYTHON_READY
      );
    }) ?? null;
  windowsPythonByCandidates.set(key, executable);
  return executable;
}

export function useTestPython(inheritEnvironment = true): () => string | null {
  function resolve() {
    const configured = inheritEnvironment
      ? process.env["PYTHON"]?.trim()
      : undefined;
    if (configured) return configured;
    return process.platform === "win32"
      ? findWindowsPython()
      : (Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py"));
  }
  if (process.platform === "win32") {
    // Three bounded probes fit in the Windows CI budget, outside each test's deadline.
    beforeAll(() => {
      resolve();
    }, 120_000);
  }
  return resolve;
}
