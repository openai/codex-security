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
