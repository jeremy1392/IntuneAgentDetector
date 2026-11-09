<#
.SYNOPSIS
    Runs the whole evaluation bench for the current privilege level, then scores it.

.DESCRIPTION
    Standard user: results go to results\standard. From an administrator
    PowerShell window: results go to results\admin, with BAM, Prefetch and
    the other users' processes readable, as for the SYSTEM scheduled task in
    production.
    Runs the episodes five times by default (about 80 minutes), then the
    cost benchmark, the intermittent agent at random scan times, the in-situ
    scan and the inventory (about 100 minutes in all). Close other heavy
    applications first. The DNS expiry experiment (dns-ttl.ps1) runs
    separately.

.EXAMPLE
    # In an administrator PowerShell window:
    Set-ExecutionPolicy -Scope Process Bypass
    C:\path\to\IntuneAgentDetector\paper\eval\run-all.ps1
#>
param([int]$Runs = 5)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
$mode = Get-Mode
# The transcript keeps the console output, errors included (results\*.log is
# not committed).
$log = Join-Path $PSScriptRoot ("results\transcript-{0}-{1}.log" -f $mode, (Get-Date).ToString('yyyyMMdd-HHmmss'))
Start-Transcript -Path $log | Out-Null
try {
    Write-Output "Running the evaluation bench as: $mode"
    & "$PSScriptRoot\run-episodes.ps1" -Runs $Runs
    & "$PSScriptRoot\bench-overhead.ps1" -Runs 100
    & "$PSScriptRoot\intermittent.ps1" -Scans 40
    & "$PSScriptRoot\insitu.ps1"
    & "$PSScriptRoot\inventory.ps1"
    & python "$PSScriptRoot\score.py"
    Write-Output "Done: results in $PSScriptRoot\results\$mode and results\tex"
}
finally {
    Stop-Transcript | Out-Null
}
