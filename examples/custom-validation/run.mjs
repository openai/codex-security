import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = await mkdtemp(join(tmpdir(), "codex-security-validation-demo-"));
const target = join(root, "target");
const output = join(root, "scan");
await mkdir(target);
for (const name of ["app.py", "validate.py"]) {
  await copyFile(new URL(name, import.meta.url), join(target, name));
}

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
    "app.py",
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
