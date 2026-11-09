# Shared helpers for the evaluation bench (Windows PowerShell 5.1).
# Dot-source it: . "$PSScriptRoot\lib.ps1"

$script:EvalRoot = $PSScriptRoot
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Test-Elevated {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Mode { if (Test-Elevated) { 'admin' } else { 'standard' } }

function ConvertTo-ArgString([string[]]$ArgList) {
    ($ArgList | ForEach-Object {
            if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
        }) -join ' '
}

# Starts a hidden process with optional extra environment variables.
function Start-Hidden {
    param([string]$File, [string[]]$ArgList = @(), [hashtable]$Env = @{}, [string]$Cwd)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ConvertTo-ArgString $ArgList
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    if ($Cwd) { $psi.WorkingDirectory = $Cwd }
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    return [System.Diagnostics.Process]::Start($psi)
}

# Starts a process detached from the bench's own process tree: a short-lived
# launcher starts it and exits, so the process has no living ancestor. This
# matters because the bench itself may run under an AI agent; without it,
# ancestry-based attribution (MCP servers, automated browsers) could climb to
# that agent. Returns the process id.
function Start-Detached {
    param([string]$File, [string[]]$ArgList = @(), [hashtable]$Env = @{})
    $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
    # The launcher reports the process id through a file, not through a pipe:
    # the started process would inherit the pipe and keep it open.
    $pidFile = Join-Path $env:TEMP ("agent-eval-pid-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    $script = "`$psi = New-Object System.Diagnostics.ProcessStartInfo; " +
    "`$psi.FileName = $(& $q $File); `$psi.Arguments = $(& $q (ConvertTo-ArgString $ArgList)); " +
    "`$psi.UseShellExecute = `$false; `$psi.CreateNoWindow = `$true; " +
    "`$p = [System.Diagnostics.Process]::Start(`$psi); " +
    "[IO.File]::WriteAllText($(& $q $pidFile), [string]`$p.Id)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $launcher = [System.Diagnostics.Process]::Start($psi)
    if (-not $launcher.WaitForExit(30000)) { throw "launcher did not exit for $File" }
    if (-not (Test-Path $pidFile)) { throw "launcher reported no process id for $File" }
    $id = [int](Get-Content $pidFile -Raw).Trim()
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    return $id
}

# Process table: PID -> @{ Pid; Ppid; Name; Cmd; Created }.
function Get-ProcTable {
    $t = @{}
    foreach ($p in Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, CommandLine, CreationDate) {
        $t[[int]$p.ProcessId] = @{
            Pid = [int]$p.ProcessId; Ppid = [int]$p.ParentProcessId; Name = [string]$p.Name
            Cmd = [string]$p.CommandLine; Created = $p.CreationDate
        }
    }
    return $t
}

# Established, non-loopback TLS (port 443) connections: PID -> count.
function Get-TlsTable {
    $t = @{}
    foreach ($c in Get-NetTCPConnection -State Established -RemotePort 443 -ErrorAction SilentlyContinue) {
        if ($c.RemoteAddress -match '^(127\.|::1$)') { continue }
        $k = [int]$c.OwningProcess
        $t[$k] = 1 + [int]$t[$k]
    }
    return $t
}

function Get-ChildMap($Procs) {
    $m = @{}
    foreach ($p in $Procs.Values) {
        if (-not $m.ContainsKey($p.Ppid)) { $m[$p.Ppid] = New-Object System.Collections.ArrayList }
        [void]$m[$p.Ppid].Add($p.Pid)
    }
    return $m
}

# Descendants of the roots created after $Since (guards against PID reuse).
function Get-Descendants($Procs, $ChildMap, [int[]]$Roots, [datetime]$Since) {
    $seen = @{}
    $queue = New-Object System.Collections.Queue
    foreach ($r in $Roots) { if ($Procs.ContainsKey($r)) { $queue.Enqueue($r); $seen[$r] = $true } }
    while ($queue.Count) {
        $pid0 = $queue.Dequeue()
        if (-not $ChildMap.ContainsKey($pid0)) { continue }
        foreach ($c in $ChildMap[$pid0]) {
            if ($seen.ContainsKey($c)) { continue }
            $cp = $Procs[$c]
            if ($cp.Created -and $cp.Created -lt $Since.AddSeconds(-2)) { continue }
            $seen[$c] = $true
            $queue.Enqueue($c)
        }
    }
    return [int[]]@($seen.Keys)
}

# ---------------------------------------------------------------- baselines
# Three baseline detectors, independent of Agent Detector's code:
#   D0 signature: the process image is a known agent executable (the image
#      names of the catalog, used alone);
#   D1 behaviour (interpreter): an interpreter or runtime host with an
#      established TLS connection and a shell among its descendants;
#   D2 behaviour (any process): any process with an established TLS
#      connection and a shell among its descendants.

$script:Interpreters = @('python.exe', 'pythonw.exe', 'py.exe', 'node.exe', 'deno.exe', 'bun.exe',
    'powershell.exe', 'pwsh.exe', 'ruby.exe', 'java.exe', 'javaw.exe', 'dotnet.exe')
$script:Shells = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'bash.exe', 'sh.exe', 'wsl.exe')

function Get-SignatureImages {
    $names = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content (Join-Path $script:RepoRoot 'rules\catalog.yaml') -Encoding UTF8) {
        if ($line -match '^\s+images:\s*\[(.+)\]') {
            foreach ($n in $Matches[1].Split(',')) { [void]$names.Add($n.Trim().Trim('"', "'")) }
        }
    }
    return $names
}

function Test-ShellDescendant($Procs, $ChildMap, [int]$Pid0, [int]$Depth = 2) {
    if ($Depth -le 0 -or -not $ChildMap.ContainsKey($Pid0)) { return $false }
    foreach ($c in $ChildMap[$Pid0]) {
        if ($script:Shells -contains $Procs[$c].Name.ToLower()) { return $true }
        if (Test-ShellDescendant $Procs $ChildMap $c ($Depth - 1)) { return $true }
    }
    return $false
}

# Returns @{ D0 = pids; D1 = pids; D2 = pids } for one sample.
function Get-BaselineFlags($Procs, $ChildMap, $Tls, $Signatures) {
    $d0 = New-Object System.Collections.ArrayList
    $d1 = New-Object System.Collections.ArrayList
    $d2 = New-Object System.Collections.ArrayList
    foreach ($p in $Procs.Values) {
        $name = $p.Name.ToLower()
        if ($Signatures.Contains($name)) { [void]$d0.Add($p.Pid) }
        if (-not $Tls.ContainsKey($p.Pid)) { continue }
        if (-not (Test-ShellDescendant $Procs $ChildMap $p.Pid 2)) { continue }
        [void]$d2.Add($p.Pid)
        if ($script:Interpreters -contains $name) { [void]$d1.Add($p.Pid) }
    }
    return @{ D0 = [int[]]$d0; D1 = [int[]]$d1; D2 = [int[]]$d2 }
}

# Runs one Agent Detector scan and returns the parsed report.
function Invoke-AgentDetector([string]$OutFile) {
    $exe = Join-Path $script:RepoRoot 'dist\detectoragent.exe'
    $begin = Get-Date
    & $exe scan --format json --no-disclaimer --no-eventlog --metrics --out $OutFile 2>$null | Out-Null
    $wall = ((Get-Date) - $begin).TotalMilliseconds
    $rep = Get-Content $OutFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $rep | Add-Member -NotePropertyName wall_ms -NotePropertyValue $wall -Force
    return $rep
}
