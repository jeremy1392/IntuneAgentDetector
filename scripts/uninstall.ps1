<#
.SYNOPSIS
    Removes detectorAgent (Intune Win32 app uninstall command): scheduled task,
    binary, branding, report folder, install marker and Event Log source
    registration. Events already written stay in the Application log.

    Intune uninstall command:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'DetectorAgent'),
    [string]$DataDir = (Join-Path $env:ProgramData 'DetectorAgent')
)

# Relaunch in 64-bit PowerShell when Intune starts the command in 32-bit.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $forward = foreach ($kv in $PSBoundParameters.GetEnumerator()) { "-$($kv.Key)"; "$($kv.Value)" }
    & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @forward
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
if (-not (Test-Path -LiteralPath $logDir)) { $logDir = $env:TEMP }
Start-Transcript -Path (Join-Path $logDir 'DetectorAgent-install.log') -Append | Out-Null

try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'uninstall.ps1 must run elevated (administrator or SYSTEM).'
    }

    Unregister-ScheduledTask -TaskPath '\DetectorAgent\' -TaskName 'DetectorAgent Scan' -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process -Name 'detectoragent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    foreach ($path in @('HKLM:\SOFTWARE\DetectorAgent', $InstallDir, $DataDir)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    if ([System.Diagnostics.EventLog]::SourceExists('DetectorAgent')) {
        Remove-EventLog -Source 'DetectorAgent'
    }
    Write-Output 'detectorAgent removed.'
    $exitCode = 0
}
catch {
    Write-Output "detectorAgent removal FAILED: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit $exitCode
