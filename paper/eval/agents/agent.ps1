<#
.SYNOPSIS
    Synthetic AI agent for the evaluation bench, PowerShell variant.

.DESCRIPTION
    Same footprint as agent.py: a keep-alive HTTPS connection polled with an
    INVALID key (the server answers 401: nothing is sent or billed) and a
    persistent cmd.exe child fed one harmless command per poll.

.EXAMPLE
    powershell -File agent.ps1 -Endpoint https://api.mistral.ai/v1/models
#>
param(
    [string]$Endpoint = 'https://api.mistral.ai/v1/models',
    [double]$Interval = 5,
    [double]$Duration = 0,
    [ValidateSet('cmd', 'none')]
    [string]$Shell = 'cmd'
)

Add-Type -AssemblyName System.Net.Http
$handler = New-Object System.Net.Http.HttpClientHandler
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
$client.DefaultRequestHeaders.TryAddWithoutValidation('Authorization', 'Bearer sk-invalid-key-for-detection-research') | Out-Null
$client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', 'agent-detector-eval/1.0') | Out-Null

# A warm TLS connection kept open between polls, as connection pools do, so
# that one connection is always established even when the server closes the
# request connection (for example after a 401).
$uri = [Uri]$Endpoint
$script:warm = $null
$script:warmSsl = $null
function Update-WarmConnection {
    if ($script:warm) {
        $s = $script:warm.Client
        if ($s.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $s.Available -eq 0) {
            $script:warm.Close(); $script:warm = $null
        }
    }
    if (-not $script:warm) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient($uri.Host, 443)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
            $ssl.AuthenticateAsClient($uri.Host)
            $script:warm = $tcp
            $script:warmSsl = $ssl
        }
        catch { $script:warm = $null }
    }
}

$child = $null
if ($Shell -eq 'cmd') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = '/Q /K'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $child = [System.Diagnostics.Process]::Start($psi)
    $child.BeginOutputReadLine()
}

Write-Output "agent pid $PID running"
$deadline = if ($Duration -gt 0) { (Get-Date).AddSeconds($Duration) } else { [datetime]::MaxValue }
try {
    while ((Get-Date) -lt $deadline) {
        try { $client.GetAsync($Endpoint).Result.Dispose() } catch { }
        Update-WarmConnection
        if ($child -and -not $child.HasExited) {
            $child.StandardInput.WriteLine('echo tool-call')
            $child.StandardInput.Flush()
        }
        Start-Sleep -Milliseconds ([int]($Interval * 1000))
    }
}
finally {
    $client.Dispose()
    if ($script:warm) { $script:warm.Close() }
    if ($child -and -not $child.HasExited) { $child.Kill() }
}
