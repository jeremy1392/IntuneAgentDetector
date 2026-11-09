<#
.SYNOPSIS
    Measures the probability that one scan, taken at a random moment, sees an
    intermittent agent.

.DESCRIPTION
    The episodes bench scans three times on a fixed schedule; an agent that
    calls its model on a fixed schedule too is then seen or missed depending
    on the phase between the two schedules, the same way in every run. This
    script runs the intermittent agent of episode A12 (a call every 10 s, the
    connection closed 5 s after each call, one short shell per call) and
    scans it at random intervals, so that each scan falls at a random phase.

    Before each scan, the script records whether the agent had an
    established connection and a shell child; after it, whether Agent
    Detector attributed a finding to the agent, and which one.

    Output: results\<mode>\intermittent.jsonl. No account or API key is used.

.EXAMPLE
    .\intermittent.ps1 -Scans 40
#>
param(
    [int]$Scans = 40,
    [double]$MinGap = 4,
    [double]$MaxGap = 11,
    [int]$Warmup = 8
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"

$mode = Get-Mode
$outDir = Join-Path $PSScriptRoot "results\$mode"
$scanDir = Join-Path $outDir 'intermittent-scans'
New-Item -ItemType Directory -Force -Path $outDir, $scanDir | Out-Null
$out = Join-Path $outDir 'intermittent.jsonl'
if (Test-Path $out) { Remove-Item $out }

$py = (Get-Command python).Source
$agentArgs = @((Join-Path $PSScriptRoot 'agents\agent.py'), '--endpoint', 'https://api.anthropic.com/v1/models',
    '--shell', 'cmd-per-call', '--interval', '10', '--keepalive', '5')
$rng = New-Object System.Random
$agent = $null
try {
    $agent = Start-Detached -File $py -ArgList $agentArgs
    Start-Sleep -Seconds $Warmup
    $t0 = Get-Date
    for ($i = 1; $i -le $Scans; $i++) {
        $connected = [bool](Get-NetTCPConnection -State Established -RemotePort 443 -OwningProcess $agent -ErrorAction SilentlyContinue)
        $shell = [bool](Get-CimInstance Win32_Process -Filter "ParentProcessId = $agent AND Name = 'cmd.exe'")
        $file = Join-Path $scanDir ("scan-{0:000}.json" -f $i)
        $report = Invoke-AgentDetector $file
        $mine = @($report.findings | Where-Object { $_.evidence | Where-Object { [int]$_.pid -eq $agent } })
        [ordered]@{
            scan = $i; t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
            connected = $connected; shell = $shell
            llm_api = [bool]($mine | Where-Object { $_.tool_id -like 'llm-api:*' })
            probable_agent = [bool]($mine | Where-Object { $_.tool_id -like 'probable-agent:*' })
            actionable = [bool]($mine | Where-Object { $_.confidence -in 'medium', 'high' })
        } | ConvertTo-Json -Compress | Add-Content -Path $out -Encoding UTF8
        Start-Sleep -Milliseconds ([int](1000 * ($MinGap + ($MaxGap - $MinGap) * $rng.NextDouble())))
    }
}
finally {
    if ($agent) { & cmd.exe /c "taskkill /T /F /PID $agent >nul 2>&1" }
}
Write-Output "Done: $out"
