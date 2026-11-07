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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
        byte[] input, int inputLength, [Out] byte[] output, int outputLength,
        out int returned, IntPtr overlapped);

    private static SafeFileHandle OpenReparseDirectory(string path, uint access) {
        // OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
        var handle = CreateFile(path, access, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception();
        return handle;
    }

    public static void CopyJunction(SafeAccessTokenHandle token, string source,
        string destination, uint access) {
        byte[] data = new byte[16384]; // MAXIMUM_REPARSE_DATA_BUFFER_SIZE
        int length;
        using (var handle = OpenReparseDirectory(source, 0)) {
            if (!DeviceIoControl(handle, 0x900a8, null, 0, data, data.Length, out length, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(); // FSCTL_GET_REPARSE_POINT
        }
        WindowsIdentity.RunImpersonated(token, () => {
            using (var handle = OpenReparseDirectory(destination, access)) {
                int returned;
                if (!DeviceIoControl(handle, 0x900a4, data, length, null, 0, out returned, IntPtr.Zero))
                    throw new System.ComponentModel.Win32Exception(); // FSCTL_SET_REPARSE_POINT
            }
        });
    }

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

    public static void MoveDirectory(SafeAccessTokenHandle token, string source, string destination) {
        WindowsIdentity.RunImpersonated(token, () => {
            if (!MoveFile(source, destination)) throw new System.ComponentModel.Win32Exception();
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
    $reparseParent = $env:CODEX_SECURITY_TEST_REPARSE_PARENT
    $sourceJunction = Join-Path $reparseParent 'source junction'
    foreach ($leaf in @('write attributes', 'write data')) {
        if ([ScanOutputAccessProbe]::CanRename($token, (Join-Path $reparseParent $leaf))) {
            throw 'The leaf-only access fixture unexpectedly permitted a rename.'
        }
    }
    [ScanOutputAccessProbe]::CopyJunction($token, $sourceJunction, (Join-Path $reparseParent 'write attributes'), 0x100)
    [ScanOutputAccessProbe]::CopyJunction($token, $sourceJunction, (Join-Path $reparseParent 'write data'), 0x2)
    $intermediate = Join-Path $reparseParent 'intermediate'
    [ScanOutputAccessProbe]::MoveDirectory($token, (Join-Path $intermediate 'src'), $env:CODEX_SECURITY_TEST_RETAINED_CHILD)
    [ScanOutputAccessProbe]::CopyJunction($token, $sourceJunction, $intermediate, 0x100)
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
