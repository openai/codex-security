$ErrorActionPreference = 'Stop'
$path = Join-Path $env:USERPROFILE '.codex-security-ci-temp'
New-Item -ItemType Directory -Path $path -Force | Out-Null
$sid = (whoami /user /fo csv /nh | ConvertFrom-Csv -Header Name, Sid).Sid
& icacls $path /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the Windows test root' }
"path=$path" >> $env:GITHUB_OUTPUT
