$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class ScanOutputAccessProbe {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LogonUser(string user, string domain, string password,
        int logonType, int provider, out SafeAccessTokenHandle token);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFile(string existingName, string newName);

    public static bool Read(SafeAccessTokenHandle token, string path) {
        return WindowsIdentity.RunImpersonated(token, () => {
            try { File.ReadAllText(path); return true; }
            catch (UnauthorizedAccessException) { return false; }
        });
    }

    public static bool Write(SafeAccessTokenHandle token, string path) {
        return WindowsIdentity.RunImpersonated(token, () => {
            try { File.AppendAllText(path, "synthetic outsider write"); return true; }
            catch (UnauthorizedAccessException) { return false; }
        });
    }

    public static void ReplaceDirectory(SafeAccessTokenHandle token, string path) {
        WindowsIdentity.RunImpersonated(token, () => {
            Directory.Move(path, path + ".retained");
            Directory.Move(path + ".replacement", path);
            File.WriteAllText(Path.Combine(path, "marker.txt"), "replacement");
        });
    }

    public static bool CanRename(SafeAccessTokenHandle token, string path) {
        return WindowsIdentity.RunImpersonated(token, () => {
            if (!MoveFile(path, path + ".moved")) {
                int error = Marshal.GetLastWin32Error();
                if (error == 5) return false; // ERROR_ACCESS_DENIED
                throw new System.ComponentModel.Win32Exception(error);
            }
            Directory.Move(path + ".moved", path);
            return true;
        });
    }
}
'@

# Run only on disposable CI machines. The account and token are removed below;
# its generated password stays in this process and is never printed.
$name = 'csec' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$password = [Guid]::NewGuid().ToString('N') + 'aA1!'
$created = $false
$token = $null
try {
    $user = New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
    $created = $true
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    if (-not [ScanOutputAccessProbe]::LogonUser($name, '.', $password, 2, 0, [ref]$token)) {
        throw [System.ComponentModel.Win32Exception]::new([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    [ScanOutputAccessProbe]::ReplaceDirectory($token, $env:CODEX_SECURITY_TEST_REPLACE_DIRECTORY)
    $protected = $env:CODEX_SECURITY_TEST_DENIED_DIRECTORY
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $protected /grant "*$($user.SID.Value):(DE)" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not [ScanOutputAccessProbe]::CanRename($token, $protected)) {
        throw 'The named-user delete grant did not permit a directory rename.'
    }
    & $icacls $protected /deny '*S-1-5-11:(DE)' | Out-Null
    if ($LASTEXITCODE -ne 0 -or [ScanOutputAccessProbe]::CanRename($token, $protected)) {
        throw 'The Authenticated Users deny did not prevent the directory rename.'
    }
    # Exercise the SDK while the named account still exists for SID resolution.
    $env:CODEX_SECURITY_TEST_DENIED_OUTPUT = Join-Path $protected 'scan'
    $check = 'const { prepareOutputDir } = await import(process.env.CODEX_SECURITY_TEST_RUNTIME); await prepareOutputDir(process.env.CODEX_SECURITY_TEST_DENIED_OUTPUT, `fixture`);'
    & $env:CODEX_SECURITY_TEST_BUN -e $check | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The SDK rejected the protected output location.' }
    $results = @(
        foreach ($path in ($env:CODEX_SECURITY_TEST_ACCESS_PATHS | ConvertFrom-Json)) {
            [pscustomobject]@{
                read = [ScanOutputAccessProbe]::Read($token, $path)
                write = [ScanOutputAccessProbe]::Write($token, $path)
            }
        }
    )
    ConvertTo-Json -InputObject $results -Compress
} finally {
    if ($null -ne $token) { $token.Dispose() }
    if ($created) { Remove-LocalUser -Name $name }
}
