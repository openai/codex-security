import {
  execFileSync,
  spawnSync,
  type SpawnSyncOptionsWithStringEncoding,
} from "node:child_process";

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
