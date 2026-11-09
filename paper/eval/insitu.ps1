<#
.SYNOPSIS
    Scans the workstation itself, with the AI tools actually installed on it.

.DESCRIPTION
    Saves one Agent Detector report to results\<mode>\insitu.json. The
    findings are compared by hand with the ground truth in ground-truth.csv,
    established independently with inventory.ps1.
#>
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
$mode = Get-Mode
$dir = Join-Path $PSScriptRoot "results\$mode"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$rep = Invoke-AgentDetector (Join-Path $dir 'insitu.json')
Write-Output ("mode {0}: {1} findings ({2} actionable) in {3} ms" -f $mode, $rep.summary.findings, $rep.summary.actionable, $rep.duration_ms)
foreach ($f in $rep.findings) {
    Write-Output ("  {0,-10} {1,-7} {2}" -f $f.level, $f.confidence, $f.tool_name)
}
