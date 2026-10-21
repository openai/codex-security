import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function windowsAcl(directory: string): string {
  const system = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32");
  const result = spawnSync(
    path.join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$ErrorActionPreference = 'Stop'; Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        CODEX_SECURITY_TEST_ACL_PATH: directory,
        PSModulePath: path.join(system, "WindowsPowerShell", "v1.0", "Modules"),
      },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

export async function privateWindowsOutputRoot(root: string): Promise<string> {
  const icacls = path.join(
    process.env.SystemRoot ?? "C:\\Windows",
    "System32",
    "icacls.exe",
  );
  assert.equal(
    spawnSync(icacls, [root, "/grant", "*S-1-1-0:(OI)(CI)R"]).status,
    0,
  );
  assert.ok(windowsAcl(root).includes(";;;WD)"));
  root = path.join(root, "private scan artifacts");
  // Use the same existing atomic creator as SDK scan-output preparation.
  const native = createRequire(import.meta.url)(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      `../../../native/prebuilt/win32-${process.arch}/windows.node`,
    ),
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
