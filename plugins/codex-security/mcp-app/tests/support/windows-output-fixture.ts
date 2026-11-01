import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";

const icacls = path.join(
  process.env.SystemRoot ?? "C:\\Windows",
  "System32",
  "icacls.exe",
);

export function windowsAcl(target: string): string {
  const work = mkdtempSync(path.join(tmpdir(), "codex-security-acl-"));
  try {
    const aclFile = path.join(work, "dacl.txt");
    execFileSync(icacls, [target, "/save", aclFile, "/q"]);
    // icacls writes the relative path followed by its SDDL, in UTF-16LE.
    const dacl = readFileSync(aclFile, "utf16le")
      .trimEnd()
      .split(/\r?\n/u)
      .at(-1);
    assert.ok(dacl && dacl.startsWith("D:"));
    return dacl;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

export async function privateWindowsOutputRoot(root: string): Promise<string> {
  execFileSync(icacls, [root, "/grant", "*S-1-1-0:(OI)(CI)R"]);
  assert.ok(windowsAcl(root).includes(";;;WD)"));
  root = path.join(root, "private scan artifacts");
  // Use the same existing atomic creator as SDK scan-output preparation.
  const pluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT;
  const nativeRoot = pluginRoot
    ? path.resolve(pluginRoot, "mcp/native")
    : path.resolve(import.meta.dirname, "../../../native/prebuilt");
  const native = createRequire(import.meta.url)(
    path.join(nativeRoot, `win32-${process.arch}`, "windows.node"),
  ) as { createPrivateWindowsDirectory(path: Buffer): number };
  assert.equal(
    native.createPrivateWindowsDirectory(
      Buffer.from(path.toNamespacedPath(root), "utf16le"),
    ),
    0,
  );
  root = await realpath(root);
  assert.ok(windowsAcl(root).includes("D:P"));
  return root;
}
