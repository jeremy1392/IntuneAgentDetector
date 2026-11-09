<#
.SYNOPSIS
    Measures how long Agent Detector can attribute a connection to a
    CDN-hosted LLM service through the DNS client cache.

.DESCRIPTION
    The DNS cache keeps a name only for the time-to-live of its answer (about
    a minute for some providers). An agent that keeps one connection open
    does not resolve the name again, so its connection can be attributed only
    while the entry lives. An agent whose connections are closed when idle
    resolves the name at every new connection, which refreshes the entry.

    Two phases, never mixed (agents of the same provider share the cache
    entry):
    - persistent: for four CDN-hosted providers, a synthetic agent keeps one
      connection open (a poll every 5 s); scans every 15 s for six minutes.
      Six minutes exceed the time-to-live of the four providers, so the next
      repetition starts with no cached entry and each agent resolves the name
      itself: the scan time is then the time since resolution.
    - reconnect: the agents' connections are closed two seconds after each
      poll (a poll every 10 s), as in clients whose pooled connections
      expire; scans every 15 s for three minutes.

    For every scan and agent the script records whether the agent had an
    established connection (TCP table) and whether Agent Detector attributed
    one of its connections to the provider's host name.

    Output: results\<mode>\dns-ttl.jsonl. No account or API key is used.

.EXAMPLE
    .\dns-ttl.ps1 -Repetitions 3
#>
param(
    [int]$Repetitions = 3,
    [int]$Every = 15
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"

$mode = Get-Mode
$outDir = Join-Path $PSScriptRoot "results\$mode"
$scanDir = Join-Path $outDir 'dns-ttl-scans'
New-Item -ItemType Directory -Force -Path $outDir, $scanDir | Out-Null
$out = Join-Path $outDir 'dns-ttl.jsonl'
if (Test-Path $out) { Remove-Item $out }

$py = (Get-Command python).Source
$agentPy = Join-Path $PSScriptRoot 'agents\agent.py'
$providers = @(
    @{ Id = 'openai'; Host = 'api.openai.com'; Url = 'https://api.openai.com/v1/models' }
    @{ Id = 'mistral'; Host = 'api.mistral.ai'; Url = 'https://api.mistral.ai/v1/models' }
    @{ Id = 'openrouter'; Host = 'openrouter.ai'; Url = 'https://openrouter.ai/api/v1/models' }
    @{ Id = 'groq'; Host = 'api.groq.com'; Url = 'https://api.groq.com/openai/v1/models' }
)
$phases = @(
    @{ Id = 'persistent'; Args = @('--interval', '5'); Duration = 360 }
    @{ Id = 'reconnect'; Args = @('--interval', '10', '--keepalive', '2'); Duration = 180 }
)

foreach ($phase in $phases) {
    for ($rep = 1; $rep -le $Repetitions; $rep++) {
        # Time-to-live of the answers as seen now (informative: a resolver may
        # serve a decremented value).
        $ttl = @{}
        foreach ($p in $providers) {
            $a = @(Resolve-DnsName $p.Host -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' })
            $ttl[$p.Id] = if ($a) { [int]($a | Measure-Object -Property TTL -Maximum).Maximum } else { $null }
        }
        $agents = @()
        try {
            foreach ($p in $providers) {
                $id = Start-Detached -File $py -ArgList (@($agentPy, '--endpoint', $p.Url, '--shell', 'none') + $phase.Args)
                $agents += @{ Provider = $p.Id; Host = $p.Host; Pid = $id }
            }
            Write-Output ("{0} {1}: TTL {2}" -f $phase.Id, $rep, (($providers | ForEach-Object { "$($_.Id)=$($ttl[$_.Id])" }) -join ' '))
            $t0 = Get-Date
            for ($t = 10; $t -le $phase.Duration; $t += $Every) {
                while (((Get-Date) - $t0).TotalSeconds -lt $t) { Start-Sleep -Milliseconds 200 }
                $conns = @(Get-NetTCPConnection -State Established -RemotePort 443 -ErrorAction SilentlyContinue)
                $file = Join-Path $scanDir ("{0}-{1}-t{2:000}.json" -f $phase.Id, $rep, $t)
                $report = Invoke-AgentDetector $file
                foreach ($a in $agents) {
                    $connected = [bool]($conns | Where-Object { $_.OwningProcess -eq $a.Pid })
                    $attributed = [bool]($report.findings | ForEach-Object { $_.evidence } | Where-Object {
                            $_.kind -eq 'network' -and [int]$_.pid -eq $a.Pid -and $_.detail -like "connected to $($a.Host) *" })
                    [ordered]@{
                        phase = $phase.Id; repetition = $rep; t = $t; provider = $a.Provider
                        connected = $connected; attributed = $attributed; ttl = $ttl[$a.Provider]
                    } | ConvertTo-Json -Compress | Add-Content -Path $out -Encoding UTF8
                }
            }
        }
        finally {
            foreach ($a in $agents) { & cmd.exe /c "taskkill /T /F /PID $($a.Pid) >nul 2>&1" }
        }
    }
}
Write-Output "Done: $out"
