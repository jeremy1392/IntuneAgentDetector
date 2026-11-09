<#
.SYNOPSIS
    Measures the cost of Agent Detector: N consecutive scans with --metrics.

.DESCRIPTION
    Writes one JSON line per scan to results\<mode>\overhead.jsonl: scan
    duration reported by the tool, wall-clock time seen from outside, CPU
    time, peak working set, time per collector, and the number of processes
    and connections on the machine. Run it on an idle machine, after the
    episodes.
#>
param([int]$Runs = 100)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
$mode = Get-Mode
$dir = Join-Path $PSScriptRoot "results\$mode"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$out = Join-Path $dir 'overhead.jsonl'
$tmp = Join-Path $env:TEMP 'agent-eval-overhead.json'
Remove-Item $out -ErrorAction SilentlyContinue

for ($i = 1; $i -le $Runs; $i++) {
    $rep = Invoke-AgentDetector $tmp
    $m = $rep.metrics
    $line = [ordered]@{
        run = $i; elevated = $rep.elevated; duration_ms = $rep.duration_ms; wall_ms = [math]::Round($rep.wall_ms, 1)
        cpu_time_ms = $m.cpu_time_ms; peak_working_set_mb = $m.peak_working_set_mb
        correlate_ms = $m.correlate_ms; collectors_ms = $m.collectors_ms
        processes = $m.processes; connections = $m.connections; findings = $rep.summary.findings
    }
    ($line | ConvertTo-Json -Compress -Depth 4) | Add-Content -Path $out -Encoding UTF8
}
Remove-Item $tmp -ErrorAction SilentlyContinue
Write-Output "mode $mode : $Runs scans written to $out"
