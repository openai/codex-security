import {
  execFileSync,
  spawnSync,
  type SpawnSyncOptionsWithStringEncoding,
} from "node:child_process";
import { join } from "node:path";
import { expect } from "bun:test";
import { PLUGIN_ROOT } from "../plugin-root.js";

export function runPythonJsonProbe(program: string, input: unknown): unknown {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const result = runPython(python, [
    "-c",
    program,
    join(PLUGIN_ROOT, "scripts"),
    JSON.stringify(input),
  ]);

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout));
}

export function runPython(
  python: string,
  args: string[],
  options: { env?: NodeJS.ProcessEnv; stdin?: Buffer } = {},
) {
  return Bun.spawnSync([python, "-I", "-B", ...args], {
    ...options,
    stdout: "pipe",
    stderr: "pipe",
  });
}

export function runNodePython(
  python: string,
  args: string[],
  options: Omit<SpawnSyncOptionsWithStringEncoding, "encoding"> = {},
) {
  return spawnSync(python, ["-I", "-B", ...args], {
    encoding: "utf8",
    ...options,
  });
}

export function execNodePython(
  python: string,
  args: string[],
  env: NodeJS.ProcessEnv,
) {
  return execFileSync(python, ["-I", "-B", ...args], { encoding: "utf8", env });
}
