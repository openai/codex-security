import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, win32 } from "node:path";
import type { WindowsBinding } from "./windows-binding.mjs";

// Inspect the actual Windows ACL, including inherited grants.
const inspectAccess = String.raw`
$ErrorActionPreference = 'Stop'
$path = $env:CODEX_SECURITY_TEST_ACL_PATH
$acl = if ([System.IO.Directory]::Exists($path)) {
    [System.IO.Directory]::GetAccessControl($path)
} else {
    [System.IO.File]::GetAccessControl($path)
}
$descriptor = $acl.GetSecurityDescriptorBinaryForm()
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$principals = @($rules | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
$privateRules = @($rules | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -in @($identity, 'S-1-5-18', 'S-1-5-32-544') -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl
})
$hash = [System.Security.Cryptography.SHA256]::Create()
try { $digest = [Convert]::ToBase64String($hash.ComputeHash($descriptor)) } finally { $hash.Dispose() }
[pscustomobject]@{
    digest = $digest
    protected = $acl.AreAccessRulesProtected
    privateRules = ($rules.Count -eq 3 -and $privateRules.Count -eq 3 -and $principals.Count -eq 3)
    inheritable = @($rules | Where-Object { $_.InheritanceFlags -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) }).Count -eq 3
    inherited = @($rules | Where-Object { $_.IsInherited }).Count -eq 3
    everyone = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band 1) }).Count -gt 0
} | ConvertTo-Json -Compress
`;

export function privateDirectoryProof(root: string, native: WindowsBinding) {
  const system = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
  function access(path: string) {
    return JSON.parse(
      execFileSync(
        join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(inspectAccess, "utf16le").toString("base64"),
        ],
        {
          encoding: "utf8",
          windowsHide: true,
          env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: path },
        },
      ),
    ) as {
      digest: string;
      protected: boolean;
      privateRules: boolean;
      inheritable: boolean;
      inherited: boolean;
      everyone: boolean;
    };
  }
  const bytes = (path: string) =>
    Buffer.from(win32.toNamespacedPath(path), "utf16le");
  const parent = join(root, "broad-parent");
  assert.equal(native.createWindowsDirectories(bytes(parent)), 0);
  execFileSync(
    join(system, "icacls.exe"),
    [parent, "/grant", "*S-1-1-0:(OI)(CI)F"],
    { windowsHide: true },
  );
  const before = access(parent);
  assert(before.everyone, "Permissive parent must grant outsider read access");

  const inherited = join(parent, "default-directory");
  assert.equal(native.createWindowsDirectories(bytes(inherited)), 0);
  assert(
    access(inherited).everyone,
    "Default directory creation must still inherit permissions",
  );

  const first = join(parent, "private-parent");
  const state = join(first, "private-state");
  for (const path of [first, state]) {
    assert.equal(native.createPrivateWindowsDirectory(bytes(path)), 0);
    const permissions = access(path);
    assert(
      permissions.protected &&
        permissions.privateRules &&
        permissions.inheritable,
      "Every new directory must have only protected inheritable private grants",
    );
  }
  const file = join(state, "synthetic-state");
  writeFileSync(file, "synthetic private state\n");
  assert.equal(readFileSync(file, "utf8"), "synthetic private state\n");
  const permissions = access(file);
  assert(
    permissions.privateRules && permissions.inherited,
    "Files must inherit only the private directory grants",
  );
  assert.equal(native.createPrivateWindowsDirectory(bytes(parent)), 183);
  assert(
    access(parent).digest === before.digest,
    "Existing directory permissions must remain unchanged",
  );
  return true;
}
