<#
.SYNOPSIS
    Installs or updates detectorAgent on a device (Intune Win32 app install command).

.DESCRIPTION
    - copies detectoragent.exe to "C:\Program Files\DetectorAgent";
    - copies the branding folder (disclaimer texts, logo, AI policy) next to it
      and refuses an invalid branding file;
    - recreates "C:\ProgramData\DetectorAgent" with a strict ACL (the scan,
      running as SYSTEM, writes its last report there);
    - registers the "DetectorAgent" Event Log source;
    - creates the scheduled task "\DetectorAgent\DetectorAgent Scan" that runs
      the scan as SYSTEM at every logon (after 2 minutes) and every hour;
    - writes the install marker HKLM\SOFTWARE\DetectorAgent, read by the Intune
      detection rule: Package = "<file version>-b<branding version>-<mode>".

    Intune install command:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
    Silent pilot (no disclaimer window):
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoDisclaimer

    The log goes to C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DetectorAgent-install.log.
    Exit code 0 = installed; 1 = failed (the log says why).

.PARAMETER NoDisclaimer
    Pilot mode: detect and log, but never show the disclaimer window.
#>
[CmdletBinding()]
param(
    [string]$Source = (Join-Path $PSScriptRoot 'detectoragent.exe'),
    # Folder holding branding.yaml, the logo and the AI policy document.
    [string]$BrandingDir = (Join-Path $PSScriptRoot 'branding'),
    [string]$InstallDir = (Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'DetectorAgent'),
    [string]$DataDir = (Join-Path $env:ProgramData 'DetectorAgent'),
    [ValidateRange(15, 1440)]
    [int]$IntervalMinutes = 60,
    [switch]$NoDisclaimer
)

# Intune may start the install command in 32-bit PowerShell. Relaunch in 64-bit
# PowerShell so that Program Files, the registry and the task are the 64-bit ones.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $forward = foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { "-$($kv.Key)" }
        } else { "-$($kv.Key)"; "$($kv.Value)" }
    }
    & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @forward
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'
$TaskPath = '\DetectorAgent\'
$TaskName = 'DetectorAgent Scan'
$EventSource = 'DetectorAgent'
$MarkerKey = 'HKLM:\SOFTWARE\DetectorAgent'

$logDir = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
if (-not (Test-Path -LiteralPath $logDir)) { $logDir = $env:TEMP }
Start-Transcript -Path (Join-Path $logDir 'DetectorAgent-install.log') -Append | Out-Null

try {
    Write-Output "detectorAgent install: 64-bit PowerShell $([Environment]::Is64BitProcess), account $([Security.Principal.WindowsIdentity]::GetCurrent().Name), mode $(if ($NoDisclaimer) { 'silent' } else { 'disclaimer' })"
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'install.ps1 must run elevated (administrator or SYSTEM).'
    }
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "detectoragent.exe not found at $Source"
    }

    # The marker is removed first and written last: Intune detects the app only
    # once every step below has succeeded.
    if (Test-Path -LiteralPath $MarkerKey) { Remove-Item -LiteralPath $MarkerKey -Recurse -Force }

    # 1. Binary. Program Files is writable by administrators only. A scan that is
    #    running would lock the file, so it is stopped first.
    Get-Process -Name 'detectoragent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $exe = Join-Path $InstallDir 'detectoragent.exe'
    Copy-Item -LiteralPath $Source -Destination $exe -Force

    # 2. Disclaimer branding, next to the binary so that users cannot change it.
    #    An invalid file stops the installation instead of silently deploying the
    #    default texts.
    $installedBranding = Join-Path $InstallDir 'branding'
    if (Test-Path -LiteralPath $installedBranding) {
        Remove-Item -LiteralPath $installedBranding -Recurse -Force
    }
    if (Test-Path -LiteralPath (Join-Path $BrandingDir 'branding.yaml')) {
        Copy-Item -LiteralPath $BrandingDir -Destination $installedBranding -Recurse -Force
    }
    # Windows PowerShell 5.1 turns redirected native error output into errors,
    # fatal under 'Stop': run the check under 'Continue' and read its exit code.
    $ErrorActionPreference = 'Continue'
    $check = @(& $exe check-branding 2>&1 | ForEach-Object { "$_" })
    $checkCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($checkCode -ne 0) {
        if (Test-Path -LiteralPath $installedBranding) { Remove-Item -LiteralPath $installedBranding -Recurse -Force }
        throw "Invalid branding file:`n$($check -join "`n")"
    }
    Write-Output ($check -join "`n")
    $brandingVersion = 1
    $match = [regex]::Match(($check -join "`n"), 'version:\s*(\d+)')
    if ($match.Success) { $brandingVersion = [int]$match.Groups[1].Value }

    # 3. Report folder. Standard users can create folders under ProgramData, so a
    #    pre-existing folder is never trusted: it is removed and recreated with
    #    SYSTEM and Administrators as the only writers.
    if (Test-Path -LiteralPath $DataDir) {
        Remove-Item -LiteralPath $DataDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls could not set the permissions of $DataDir" }
    & icacls.exe $DataDir /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls could not set the owner of $DataDir" }

    # 4. Event Log source, so that events display without "description not found".
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName Application -Source $EventSource
    }

    # 5. Scheduled task, running as SYSTEM.
    $arguments = "scan --out `"$DataDir\last-scan.json`""
    if ($NoDisclaimer) {
        $arguments += ' --no-disclaimer'
    }
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $InstallDir
    # At logon, after 2 minutes so that the desktop is ready (Task Scheduler
    # LogonTrigger Delay).
    $atLogon = New-ScheduledTaskTrigger -AtLogOn
    $atLogon.Delay = 'PT2M'
    # Every day, repeated every $IntervalMinutes for 24 hours: an explicit
    # repetition duration, built only from documented parameters.
    $repeat = New-ScheduledTaskTrigger -Daily -At '00:00'
    $repeat.Repetition = (New-ScheduledTaskTrigger -Once -At '00:00' `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 1)).Repetition
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # StartWhenAvailable runs a missed hourly scan as soon as the device wakes up.
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger @($atLogon, $repeat) `
        -Principal $taskPrincipal -Settings $settings -Force `
        -Description 'detectorAgent: detects AI agents (detection only) and shows the AI usage disclaimer.' | Out-Null

    # 6. Install marker for the Intune detection rule.
    $version = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
    $mode = if ($NoDisclaimer) { 'silent' } else { 'disclaimer' }
    $package = "$version-b$brandingVersion-$mode"
    New-Item -Path $MarkerKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'Package' -Value $package
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'Version' -Value $version
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'BrandingVersion' -Value $brandingVersion -Type DWord
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'Mode' -Value $mode
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'IntervalMinutes' -Value $IntervalMinutes -Type DWord
    Set-ItemProperty -LiteralPath $MarkerKey -Name 'InstalledAt' -Value (Get-Date).ToUniversalTime().ToString('o')

    Write-Output "detectorAgent installed in $InstallDir (task $TaskPath$TaskName, every $IntervalMinutes min, mode $mode)."
    Write-Output "Intune detection value (HKLM\SOFTWARE\DetectorAgent, Package): $package"
    $exitCode = 0
}
catch {
    Write-Output "detectorAgent installation FAILED: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit $exitCode
