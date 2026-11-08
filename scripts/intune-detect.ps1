<#
.SYNOPSIS
    Intune Remediations detection script (detection only, no remediation).

.DESCRIPTION
    Runs a fresh scan as SYSTEM without disclaimer and without Event Log
    output (the scheduled task already logs), then prints one summary line,
    shown by Intune as the detection output (2,048 characters at most).

    Remediations treat exit code 1 as "issue found": the script exits 1 only
    when an unapproved AI tool is at least installed and detected with medium
    or high confidence. Every other path, errors included, exits 0 with a line
    that says why.
#>
param(
    # Intune runs the script without arguments; the parameter exists for tests.
    [string]$ExePath = (Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'DetectorAgent\detectoragent.exe')
)

try {
    if (-not (Test-Path -LiteralPath $ExePath)) {
        Write-Output 'detectorAgent is not installed'
        exit 0
    }

    # Windows PowerShell 5.1 turns redirected native error output into errors;
    # with 'Continue' they never stop the script. The exit code decides.
    $ErrorActionPreference = 'Continue'
    $raw = & $ExePath scan --no-disclaimer --no-eventlog --format json 2>$null
    $code = $LASTEXITCODE
    if ($code -eq 2 -or -not $raw) {
        Write-Output "detectorAgent scan failed (exit code $code)"
        exit 0
    }

    $report = ($raw | Out-String) | ConvertFrom-Json
    $tools = @($report.findings | Where-Object {
            -not $_.approved -and $_.level -in @('active', 'recent', 'installed') -and $_.confidence -in @('medium', 'high')
        } | ForEach-Object { '{0} ({1})' -f $_.tool_name, $_.level } | Select-Object -Unique)

    if ($code -eq 1 -and $tools.Count -gt 0) {
        $line = 'Unapproved AI tools: ' + ($tools -join '; ')
        if ($line.Length -gt 2000) {
            $line = $line.Substring(0, 1997) + '...'
        }
        Write-Output $line
        exit 1
    }
    Write-Output ('No unapproved AI tool ({0} findings, all approved or low confidence)' -f $report.summary.findings)
    exit 0
}
catch {
    Write-Output "detectorAgent detection script error: $($_.Exception.Message)"
    exit 0
}
