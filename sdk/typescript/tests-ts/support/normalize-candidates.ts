import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
const node = Bun.which("node");
const pythonNormalizer = fileURLToPath(
  new URL(
    "../../_bundled_plugin/scripts/normalize_candidates.py",
    import.meta.url,
  ),
);
const typescriptNormalizer = fileURLToPath(
  new URL(
    "../../_bundled_plugin/scripts/normalize_candidates.mjs",
    import.meta.url,
  ),
);

function executable(value: string | null, name: string): string {
  if (value === null) throw new Error(`${name} is required for this test`);
  return value;
}

export function writeSource(
  repository: string,
  path: string,
  contents: string | Uint8Array,
): void {
  const output = join(repository, path);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, contents);
}

export function runPythonNormalizer(
  args: string[],
  script = pythonNormalizer,
  options: Pick<SpawnSyncOptions, "cwd" | "env" | "timeout"> = {},
) {
  return spawnSync(executable(python, "Python"), ["-B", script, ...args], {
    ...options,
    encoding: "utf8",
    env: { ...process.env, ...options.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

export function runTypeScriptNormalizer(
  args: string[],
  script = typescriptNormalizer,
  options: Pick<SpawnSyncOptions, "cwd" | "env" | "timeout"> = {},
) {
  return spawnSync(executable(node, "Node.js"), [script, ...args], {
    ...options,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
  });
}

export function normalizerArguments(
  inputs: string[],
  output: string,
  repository: string,
  inventory: string,
  allowMissing = false,
): string[] {
  return [
    "--input",
    ...inputs,
    "--out",
    output,
    "--repo-root",
    repository,
    "--in-scope-files",
    inventory,
    ...(allowMissing ? ["--allow-missing-in-scope"] : []),
  ];
}
