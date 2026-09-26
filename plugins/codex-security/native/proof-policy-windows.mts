import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { binaryPath, output, root } from "./binding.mjs";
import { nativeTarget } from "./platform.mjs";

const testDirectory = join(output, "policy-proof");
const helper = join(testDirectory, "helpers.cjs");
if (process.argv[2] === "build") {
  execFileSync(
    process.execPath,
    [
      join(root, "../../../sdk/typescript/node_modules/esbuild/bin/esbuild"),
      join(root, "../mcp-app/helpers-main.ts"),
      "--bundle",
      "--platform=node",
      "--format=cjs",
      "--target=node20",
      "--define:import.meta.url=__filename",
      `--outfile=${helper}`,
    ],
    { stdio: "inherit" },
  );
  const nativeDirectory = join(testDirectory, "native", nativeTarget);
  mkdirSync(nativeDirectory, { recursive: true });
  copyFileSync(binaryPath, join(nativeDirectory, "windows.node"));
} else {
  const fixture = mkdtempSync(join(tmpdir(), "codex-security-policy-proof-"));
  try {
    const proof: unknown = JSON.parse(
      execFileSync(
        join(output, "windows-wide-launcher.exe"),
        [process.execPath, helper, fixture, "policy"],
        { encoding: "utf8", maxBuffer: Infinity, timeout: 30_000 },
      ),
    );
    console.log(
      JSON.stringify({ node: process.version, arch: process.arch, proof }),
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}
