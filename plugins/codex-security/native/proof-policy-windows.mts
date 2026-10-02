import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { binaryPath, output, root } from "./binding.mjs";
import { nativeTarget } from "./platform.mjs";
import {
  loadWindowsBinding,
  windowsFlags as flags,
} from "./windows-binding.mjs";

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
    const repo = join(fixture, "volume-repository");
    mkdirSync(repo);
    writeFileSync(join(repo, "SECURITY.md"), "volume policy\n");
    const opened = loadWindowsBinding().openWindowsFile(
      Buffer.from(repo, "utf16le"),
      0,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      flags.OPEN_EXISTING,
      flags.FILE_FLAG_BACKUP_SEMANTICS,
    );
    assert.equal(opened.error, 0);
    assert(opened.handle);
    let volumePath: string;
    try {
      const final = opened.handle.finalPath(flags.VOLUME_NAME_GUID);
      assert.equal(final.error, 0);
      volumePath = final.path.toString("utf16le");
    } finally {
      assert.equal(opened.handle.close(), 0);
    }
    for (const scope of [".", repo.slice(win32.parse(repo).root.length - 1)]) {
      assert.equal(
        execFileSync(
          process.execPath,
          [
            helper,
            "--helper",
            "resolve-security-md",
            "--repo",
            volumePath,
            "--scope",
            scope,
          ],
          { encoding: "utf8" },
        ),
        '## SECURITY.md source: "SECURITY.md"\n\nvolume policy\n',
      );
    }
    const proof: unknown = JSON.parse(
      execFileSync(
        join(output, "windows-wide-launcher.exe"),
        [process.execPath, helper, fixture, "policy"],
        { encoding: "utf8", maxBuffer: Infinity, timeout: 30_000 },
      ),
    );
    console.log(
      JSON.stringify({
        node: process.version,
        arch: process.arch,
        proof,
        volumeGuidScope: true,
      }),
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}
