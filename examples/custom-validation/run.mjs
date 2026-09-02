import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = await mkdtemp(join(tmpdir(), "codex-security-validation-demo-"));
const target = join(root, "target");
const output = join(root, "scan");
await mkdir(target);
for (const name of ["app.mts", "validate.mts"]) {
  await copyFile(new URL(name, import.meta.url), join(target, name));
}

const build = spawnSync(
  process.execPath,
  [
    fileURLToPath(
      new URL(
        "../../sdk/typescript/node_modules/typescript/bin/tsc",
        import.meta.url,
      ),
    ),
    "--project",
    fileURLToPath(
      new URL("../../sdk/typescript/tsconfig.examples.json", import.meta.url),
    ),
    "--outDir",
    target,
  ],
  { stdio: "inherit" },
);
if (build.error) throw build.error;
if (build.status !== 0) process.exit(build.status ?? 1);

console.log(`Demo target: ${target}\nScan output: ${output}`);
const child = spawnSync(
  process.execPath,
  [
    fileURLToPath(
      new URL("../../sdk/typescript/bin/codex-security.mjs", import.meta.url),
    ),
    "scan",
    target,
    "--path",
    "app.mts",
    "--scan-prompt-file",
    fileURLToPath(new URL("scan.md", import.meta.url)),
    "--validation-prompt-file",
    fileURLToPath(new URL("validation.md", import.meta.url)),
    "--output-dir",
    output,
    "--headless",
    ...process.argv.slice(2),
  ],
  { stdio: "inherit" },
);
if (child.error) throw child.error;
process.exitCode = child.status ?? 1;
