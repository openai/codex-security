import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const normalizer = fileURLToPath(
  new URL(
    "../../_bundled_plugin/scripts/normalize_candidates.mjs",
    import.meta.url,
  ),
);

export function writeSource(
  repository: string,
  path: string,
  contents: string | Uint8Array,
): void {
  const output = join(repository, path);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, contents);
}

export function runNormalizer(
  args: string[],
  script = normalizer,
  options: Pick<SpawnSyncOptions, "cwd" | "timeout"> = {},
) {
  return spawnSync("node", [script, ...args], { ...options, encoding: "utf8" });
}

export function normalizerArguments(
  inputs: string[],
  output: string,
  repository: string,
  inventory: string,
  allowMissing = false,
): string[] {
  return [
    ...inputs.flatMap((input) => ["--input", input]),
    "--out",
    output,
    "--repo-root",
    repository,
    "--in-scope-files",
    inventory,
    ...(allowMissing ? ["--allow-missing-in-scope"] : []),
  ];
}
