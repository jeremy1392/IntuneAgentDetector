<#
.SYNOPSIS
    Independent inventory of AI tools on this workstation, for the ground truth.

.DESCRIPTION
    Uses only standard Windows and package-manager commands, none of Agent
    Detector's code: packaged apps, installed programs, IDE extensions, global
    npm and pip packages, configuration folders in the profile, and running
    processes. The output (results\inventory.json) is reviewed by hand to
    write ground-truth.csv.
#>
$ErrorActionPreference = 'Continue'
$pattern = '(?i)claude|anthropic|openai|codex|chatgpt|copilot|cursor|windsurf|codeium|kiro|trae|gemini|ollama|lm.?studio|lmstudio|jan\b|gpt4all|anythingllm|llama|aider|goose|opencode|cline|roo|kilo|continue|tabnine|qodo|augment|perplexity|comet|langchain|crewai|autogen|litellm|mcp'

$inv = [ordered]@{}
$inv.appx = @(Get-AppxPackage | Where-Object { $_.Name -match $pattern } | ForEach-Object { "$($_.Name) $($_.Version)" })
$inv.programs = @(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match $pattern } | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" } | Sort-Object -Unique)
$inv.vscode_extensions = @(Get-ChildItem "$env:USERPROFILE\.vscode\extensions" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $pattern } | ForEach-Object { $_.Name })
$npm = & npm.cmd ls -g --depth=0 --json 2>$null | Out-String
if ($npm) { $inv.npm_global = @((($npm | ConvertFrom-Json).dependencies.PSObject.Properties.Name) | Where-Object { $_ -match $pattern }) }
$pip = & py -3 -m pip list --format json 2>$null | Out-String
if ($pip) { $inv.pip = @(($pip | ConvertFrom-Json) | Where-Object { $_.name -match $pattern } | ForEach-Object { "$($_.name) $($_.version)" }) }
$inv.profile_folders = @(Get-ChildItem $env:USERPROFILE -Force -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $pattern } | ForEach-Object { "{0} (modified {1:yyyy-MM-dd})" -f $_.Name, $_.LastWriteTime })
$inv.localappdata_programs = @(Get-ChildItem "$env:LOCALAPPDATA\Programs", "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $pattern } | ForEach-Object { $_.FullName } | Sort-Object -Unique)
$inv.processes = @(Get-Process | Where-Object { $_.ProcessName -match $pattern } | Group-Object ProcessName | ForEach-Object { "$($_.Name) x$($_.Count)" })

$out = Join-Path $PSScriptRoot 'results\inventory.json'
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$inv | ConvertTo-Json -Depth 4 | Set-Content $out -Encoding UTF8
Write-Output "inventory written to $out"
