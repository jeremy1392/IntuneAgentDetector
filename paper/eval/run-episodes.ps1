<#
.SYNOPSIS
    Runs the evaluation episodes: synthetic agents, robustness cases and
    benign developer workloads, each observed by three baseline detectors and
    by Agent Detector.

.DESCRIPTION
    For every episode: start its processes, wait for them to settle, then
    during the observation window sample the process tree and TLS connections
    every second (baselines D0, D1, D2, see lib.ps1) and run Agent Detector
    three times. Detections are attributed to the episode through its
    process tree. Each run goes to results\<mode>\runs\<run id>\: run.json
    (provenance: Windows build, commit, binary hash, catalog version) and
    episodes\<id>.json. The mode is "standard" or "admin" depending on how the
    script is started. score.py aggregates the complete runs.

    No account or API key is used: agents poll real endpoints with an invalid
    key and receive HTTP 401.

.EXAMPLE
    .\run-episodes.ps1 -Runs 5
    .\run-episodes.ps1 -Only A01,B01 -Window 20     # partial run, ignored by score.py
#>
param(
    [string[]]$Only,
    [int]$Warmup = 8,
    [int]$Window = 24,
    [int]$Scans = 3,
    [int]$Runs = 1
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"

$mode = Get-Mode
$modeDir = Join-Path $PSScriptRoot "results\$mode"

# A process left by an interrupted run would run in the background of every
# episode, and could hold port 11434: refuse to start until it is stopped.
$leftovers = @(Get-CimInstance Win32_Process -Property ProcessId, Name, CommandLine | Where-Object {
        $_.CommandLine -match 'agent-eval-chrome-|\\paper\\eval\\(agents|workloads)\\' } |
    ForEach-Object { "$($_.ProcessId) $($_.Name)" })
$leftovers += @(Get-NetTCPConnection -State Listen -LocalPort 11434 -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.OwningProcess) listening on port 11434" })
if ($leftovers) { throw "Stop the processes left by an earlier run first: $($leftovers -join '; ')" }

$work = Join-Path $env:TEMP 'agent-eval-work\fixtures'
New-Item -ItemType Directory -Force -Path $work, (Join-Path $work 'mcp-root') | Out-Null
# Fixtures: a module named like an inference runtime, and a renamed Node runtime.
$ggml = Join-Path $work 'ggml-base.dll'
if (-not (Test-Path $ggml)) { Copy-Item "$env:WINDIR\System32\version.dll" $ggml }
$updater = Join-Path $work 'updater.exe'
if (-not (Test-Path $updater)) { Copy-Item (Get-Command node).Source $updater }

$py = (Get-Command python).Source
$node = (Get-Command node).Source
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$agentPy = Join-Path $PSScriptRoot 'agents\agent.py'
$agentJs = Join-Path $PSScriptRoot 'agents\agent.js'
$agentPs = Join-Path $PSScriptRoot 'agents\agent.ps1'
$devLoop = Join-Path $PSScriptRoot 'workloads\dev-loop.ps1'
$wslAgent = '/mnt/' + ($agentPy.Substring(0, 1).ToLower()) + ($agentPy.Substring(2) -replace '\\', '/')

function S([string]$File, [string[]]$ArgList, [hashtable]$Env = @{}) { @{ File = $File; Args = $ArgList; Env = $Env } }
function PyAgent([string[]]$ArgList, [hashtable]$Env = @{}) { S $py (@($agentPy) + $ArgList) $Env }
function Loop([string]$Kind) { S $ps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $devLoop, '-Kind', $Kind) }

$anthropic = 'https://api.anthropic.com/v1/models'
$episodes = @(
    # ------------------------------------------------------------ agents (positives)
    @{ Id = 'A01'; Label = 'agent'; Scope = 'main'; Class = 'Model provider (CDN-hosted)'; Desc = 'Python agent, OpenAI API, persistent cmd'
        Starts = @(PyAgent @('--endpoint', 'https://api.openai.com/v1/models', '--shell', 'cmd')) }
    @{ Id = 'A02'; Label = 'agent'; Scope = 'main'; Class = 'Model provider (dedicated range)'; Desc = 'Python agent, Anthropic API, persistent cmd'
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'cmd')) }
    @{ Id = 'A03'; Label = 'agent'; Scope = 'main'; Class = 'Model provider (dedicated range)'; Desc = 'Node.js agent, Anthropic API, persistent PowerShell'
        Starts = @(S $node @($agentJs, '--endpoint', $anthropic, '--shell', 'powershell')) }
    @{ Id = 'A04'; Label = 'agent'; Scope = 'main'; Class = 'Model provider (CDN-hosted)'; Desc = 'PowerShell agent, Mistral API, persistent cmd'
        Starts = @(S $ps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $agentPs, '-Endpoint', 'https://api.mistral.ai/v1/models')) }
    @{ Id = 'A05'; Label = 'agent'; Scope = 'main'; Class = 'Aggregator'; Desc = 'Python agent, OpenRouter, persistent cmd'
        Starts = @(PyAgent @('--endpoint', 'https://openrouter.ai/api/v1/models', '--shell', 'cmd')) }
    @{ Id = 'A06'; Label = 'agent'; Scope = 'main'; Class = 'Inference platform'; Desc = 'Python agent, Groq API, persistent cmd'
        Starts = @(PyAgent @('--endpoint', 'https://api.groq.com/openai/v1/models', '--shell', 'cmd')) }
    @{ Id = 'A07'; Label = 'agent'; Scope = 'main'; Class = 'Unknown relay (declared)'; Desc = 'Python agent through a relay set in OPENAI_BASE_URL'
        Starts = @(PyAgent @('--endpoint', 'https://httpbin.org/anything/v1/models', '--shell', 'cmd') @{ OPENAI_BASE_URL = 'https://httpbin.org/anything/v1' }) }
    @{ Id = 'A08'; Label = 'agent'; Scope = 'main'; Class = 'Local LLM'; Desc = 'Local LLM-style server on port 11434 and an agent using it'
        Starts = @((PyAgent @('--no-network', '--shell', 'none', '--listen', '11434')),
            (PyAgent @('--endpoint', 'http://127.0.0.1:11434/api/tags', '--shell', 'cmd'))) }
    @{ Id = 'A09'; Label = 'agent'; Scope = 'main'; Class = 'Agent with MCP server'; Desc = 'Python agent, Anthropic API, reference MCP filesystem server'
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'cmd', '--mcp', (Join-Path $work 'mcp-root'))) }
    @{ Id = 'A10'; Label = 'agent'; Scope = 'main'; Class = 'Agent driving a browser'; Desc = 'Python agent, Anthropic API, headless Chrome with remote debugging, no shell'
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'none', '--browser', $chrome)) }
    @{ Id = 'A11'; Label = 'agent'; Scope = 'main'; Class = 'Renamed runtime'; Desc = 'Node.js agent run by a copy of node.exe renamed updater.exe'
        Starts = @(S $updater @($agentJs, '--endpoint', $anthropic, '--shell', 'powershell')) }
    @{ Id = 'A12'; Label = 'agent'; Scope = 'main'; Class = 'Intermittent agent'; Desc = 'Python agent, Anthropic API, a call every 10 s, connection closed after 5 s, one short shell per call'
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'cmd-per-call', '--interval', '10', '--keepalive', '5')) }
    # -------------------------------------------- AI components (positives, not agents)
    @{ Id = 'C01'; Label = 'component'; Scope = 'main'; Class = 'Inference runtime'; Desc = 'Process loading a module named like an inference runtime (ggml), no network'
        Starts = @(PyAgent @('--no-network', '--shell', 'none', '--module', $ggml)) }
    @{ Id = 'C02'; Label = 'component'; Scope = 'main'; Class = 'MCP server'; Desc = 'Reference MCP filesystem server alone, no LLM connection'
        Starts = @(PyAgent @('--no-network', '--shell', 'none', '--mcp', (Join-Path $work 'mcp-root'))) }
    @{ Id = 'C03'; Label = 'component'; Scope = 'main'; Class = 'LLM client without tools'; Desc = 'Python script polling the Anthropic API, no shell, no tools'
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'none')) }
    # ------------------------------------------------------- robustness (positives)
    @{ Id = 'R01'; Label = 'agent'; Scope = 'robustness'; Class = 'Undeclared relay'; Desc = 'Python agent through a relay hard-coded in the script'
        Starts = @(PyAgent @('--endpoint', 'https://httpbin.org/anything/v1/models', '--shell', 'cmd')) }
    @{ Id = 'R02'; Label = 'agent'; Scope = 'robustness'; Class = 'Ephemeral agent'; Desc = 'Python agent running 5 s, scanned after it exited'
        Ephemeral = $true
        Starts = @(PyAgent @('--endpoint', $anthropic, '--shell', 'cmd', '--duration', '5')) }
    @{ Id = 'R03'; Label = 'agent'; Scope = 'robustness'; Class = 'Agent inside WSL 2'; Desc = 'Python agent running in the Ubuntu WSL 2 distribution'
        Starts = @(S "$env:WINDIR\System32\wsl.exe" @('-d', 'Ubuntu', '--', 'python3', $wslAgent, '--endpoint', $anthropic, '--shell', 'cmd'))
        # Make sure the agent does not survive inside the WSL virtual machine.
        Cleanup = "wsl.exe -d Ubuntu -- pkill -f paper/eval/agents/agent.py" }
    # ------------------------------------------------------------ benign (negatives)
    @{ Id = 'B01'; Label = 'benign'; Scope = 'main'; Class = 'Behavioural twin'; Desc = 'Twin of A02: Python script, PyPI JSON API, persistent cmd'
        Starts = @(PyAgent @('--endpoint', 'https://pypi.org/pypi/requests/json', '--shell', 'cmd')) }
    @{ Id = 'B02'; Label = 'benign'; Scope = 'main'; Class = 'Behavioural twin'; Desc = 'Twin of A03: Node.js script, npm registry, persistent PowerShell'
        Starts = @(S $node @($agentJs, '--endpoint', 'https://registry.npmjs.org/', '--shell', 'powershell')) }
    @{ Id = 'B03'; Label = 'benign'; Scope = 'main'; Class = 'Behavioural twin'; Desc = 'Twin of A04: PowerShell script, Microsoft Graph, persistent cmd'
        Starts = @(S $ps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $agentPs, '-Endpoint', 'https://graph.microsoft.com/v1.0/me')) }
    @{ Id = 'B04'; Label = 'benign'; Scope = 'main'; Class = 'Developer workload'; Desc = 'npm install with install script (cmd)'; Starts = @(Loop 'npm') }
    @{ Id = 'B05'; Label = 'benign'; Scope = 'main'; Class = 'Developer workload'; Desc = 'git clone over HTTPS'; Starts = @(Loop 'git') }
    @{ Id = 'B06'; Label = 'benign'; Scope = 'main'; Class = 'Developer workload'; Desc = 'pip download of a large wheel'; Starts = @(Loop 'pip') }
    @{ Id = 'B07'; Label = 'benign'; Scope = 'main'; Class = 'Developer workload'; Desc = 'dotnet restore and build'; Starts = @(Loop 'dotnet') }
    @{ Id = 'B08'; Label = 'benign'; Scope = 'main'; Class = 'Developer workload'; Desc = 'go build with module download'; Starts = @(Loop 'go') }
    @{ Id = 'B09'; Label = 'benign'; Scope = 'main'; Class = 'Inherited base URL'; Desc = 'git loop in a PowerShell that inherited OPENAI_BASE_URL from the user environment'
        Starts = @(S $ps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $devLoop, '-Kind', 'git') @{ OPENAI_BASE_URL = 'https://llm-gateway.example.com/v1' }) }
)
# -Only A01,B01 arrives as one string when the script is started with -File.
$Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ($Only) { $episodes = @($episodes | Where-Object { $Only -contains $_.Id }) }

$signatures = Get-SignatureImages
Write-Output "mode: $mode   episodes: $($episodes.Count)   window: ${Window}s   scans/episode: $Scans"

# Provenance of a run: what was measured, on what, with which build.
function Get-Provenance {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $exe = Join-Path $script:RepoRoot 'dist\detectoragent.exe'
    $commit = (& cmd.exe /c "git -C ""$script:RepoRoot"" rev-parse --short HEAD 2>nul")
    $dirty = (& cmd.exe /c "git -C ""$script:RepoRoot"" status --porcelain --untracked-files=no 2>nul")
    $probe = Join-Path $env:TEMP 'agent-eval-probe.json'
    $rep = Invoke-AgentDetector $probe
    Remove-Item $probe -ErrorAction SilentlyContinue
    [ordered]@{
        mode = $mode; elevated = (Test-Elevated)
        os = [ordered]@{ caption = $os.Caption; edition = $cv.EditionID; display_version = $cv.DisplayVersion
            build = "$($cv.CurrentBuild).$($cv.UBR)" }
        commit = $(if ($commit) { "$commit" + $(if ($dirty) { '-dirty' } else { '' }) } else { $null })
        binary_sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
        tool_version = $rep.version; catalog_version = $rep.catalog_version
        warmup_s = $Warmup; window_s = $Window; scans_per_episode = $Scans
        partial = [bool]$Only; episodes = @($episodes | ForEach-Object { $_.Id })
    }
}

function Observe($procs, $tls, [int[]]$roots, [datetime]$since, $flagged, $treeSet, $background) {
    $children = Get-ChildMap $procs
    foreach ($p in (Get-Descendants $procs $children $roots $since)) { $treeSet[$p] = $procs[$p].Name }
    # Chrome relaunches itself, so an agent's browser is not its descendant;
    # agent.py names the browser profile folder after its own PID.
    foreach ($p in $procs.Values) {
        if ($p.Cmd -match 'agent-eval-chrome-(\d+)' -and $treeSet.ContainsKey([int]$Matches[1])) { $treeSet[$p.Pid] = $p.Name }
    }
    $flags = Get-BaselineFlags $procs $children $tls $signatures
    foreach ($d in 'D0', 'D1', 'D2') {
        foreach ($p in $flags[$d]) {
            if ($treeSet.ContainsKey($p)) { $flagged[$d][$p] = $procs[$p].Name }
            else { $background[$d][$procs[$p].Name.ToLower()] = $true }
        }
    }
}

for ($run = 1; $run -le $Runs; $run++) {
$runId = (Get-Date).ToString('yyyyMMdd-HHmmss')
$runDir = Join-Path $modeDir "runs\$runId"
$outDir = Join-Path $runDir 'episodes'
$scanDir = Join-Path $runDir 'scans'
New-Item -ItemType Directory -Force -Path $outDir, $scanDir | Out-Null
$prov = Get-Provenance
$prov.run_id = $runId; $prov.started = (Get-Date).ToString('o'); $prov.complete = $false
$prov | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $runDir 'run.json') -Encoding UTF8
Write-Output "run $run of $Runs`: $runId"

foreach ($ep in $episodes) {
    Write-Output ("[{0}] {1}" -f $ep.Id, $ep.Desc)
    $start = Get-Date
    $rootList = New-Object System.Collections.ArrayList
    $treeSet = @{}
    $flagged = @{ D0 = @{}; D1 = @{}; D2 = @{} }
    $background = @{ D0 = @{}; D1 = @{}; D2 = @{} }
    $adHits = New-Object System.Collections.ArrayList
    $scanFiles = @()
    $samples = 0
    # The finally block stops the episode's processes even when the run is
    # interrupted (Ctrl+C or error), so that no agent outlives its episode.
    try {
        foreach ($s in $ep.Starts) {
            # Detached: no living ancestor in the bench's process tree (see lib.ps1).
            try { [void]$rootList.Add((Start-Detached -File $s.File -ArgList $s.Args -Env $s.Env)) }
            catch { Write-Output "  start failed: $($_.Exception.Message)" }
        }
        $roots = [int[]]@($rootList)

        if ($ep.Ephemeral) {
            # Watch the agent while it lives (to know its processes), then scan once it has exited.
            while ((Get-Process -Id $roots -ErrorAction SilentlyContinue) -and ((Get-Date) - $start).TotalSeconds -lt 30) {
                Observe (Get-ProcTable) (Get-TlsTable) $roots $start @{ D0 = @{}; D1 = @{}; D2 = @{} } $treeSet $background
                Start-Sleep -Milliseconds 500
            }
            Start-Sleep -Seconds 5
        }
        else {
            Start-Sleep -Seconds $Warmup
        }

        $windowEnd = (Get-Date).AddSeconds($Window)
        $scanEvery = $Window / $Scans
        $nextScan = Get-Date
        $scanIndex = 0
        while ((Get-Date) -lt $windowEnd -or $scanIndex -lt $Scans) {
            Observe (Get-ProcTable) (Get-TlsTable) $roots $start $flagged $treeSet $background
            $samples++
            if ($scanIndex -lt $Scans -and (Get-Date) -ge $nextScan) {
                $scanIndex++
                $file = Join-Path $scanDir ("{0}-{1}.json" -f $ep.Id, $scanIndex)
                $rep = Invoke-AgentDetector $file
                $scanFiles += (Split-Path $file -Leaf)
                foreach ($f in $rep.findings) {
                    $evPids = @($f.evidence | Where-Object { $_.pid } | ForEach-Object { [int]$_.pid })
                    if (-not ($evPids | Where-Object { $treeSet.ContainsKey($_) })) { continue }
                    [void]$adHits.Add([ordered]@{
                            scan = $scanIndex; tool_id = $f.tool_id; tool_name = $f.tool_name; category = $f.category
                            level = $f.level; confidence = $f.confidence; approved = $f.approved
                            kinds = @($f.evidence | ForEach-Object { $_.kind } | Select-Object -Unique)
                        })
                }
                $nextScan = (Get-Date).AddSeconds($scanEvery)
            }
            Start-Sleep -Milliseconds 700
        }
    }
    finally {
        # Stop the whole tree, including processes whose parent already exited.
        # Through cmd.exe: in Windows PowerShell 5.1, the error text of taskkill for
        # a process that already exited would be a terminating error under 'Stop'.
        foreach ($r in @($rootList)) { & cmd.exe /c "taskkill /T /F /PID $r >nul 2>&1" }
        foreach ($p in @($treeSet.Keys)) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
        if ($ep.Cleanup) { & cmd.exe /c "$($ep.Cleanup) >nul 2>&1" }
    }
    Start-Sleep -Seconds 3

    $actionable = @($adHits | Where-Object { $_.confidence -in 'medium', 'high' })
    $record = [ordered]@{
        id = $ep.Id; label = $ep.Label; scope = $ep.Scope; class = $ep.Class; description = $ep.Desc
        mode = $mode; run_id = $runId; started = $start.ToString('o'); samples = $samples
        processes = @($treeSet.GetEnumerator() | ForEach-Object { [ordered]@{ pid = $_.Key; name = $_.Value } })
        baseline = [ordered]@{
            D0 = ($flagged.D0.Count -gt 0); D1 = ($flagged.D1.Count -gt 0); D2 = ($flagged.D2.Count -gt 0)
            flagged = [ordered]@{ D0 = @($flagged.D0.Values | Select-Object -Unique); D1 = @($flagged.D1.Values | Select-Object -Unique); D2 = @($flagged.D2.Values | Select-Object -Unique) }
        }
        background = [ordered]@{ D0 = @($background.D0.Keys); D1 = @($background.D1.Keys); D2 = @($background.D2.Keys) }
        agent_detector = [ordered]@{
            detected = ($actionable.Count -gt 0); any_finding = ($adHits.Count -gt 0)
            findings = @($adHits); scans = $scanFiles
        }
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $outDir "$($ep.Id).json") -Encoding UTF8
    Write-Output ("  processes {0}  D0 {1}  D1 {2}  D2 {3}  AgentDetector {4}" -f $treeSet.Count, $record.baseline.D0, $record.baseline.D1, $record.baseline.D2, $record.agent_detector.detected)
}

$prov.finished = (Get-Date).ToString('o'); $prov.complete = $true
$prov | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $runDir 'run.json') -Encoding UTF8
}
