<#
.SYNOPSIS
    Benign developer workloads for the evaluation bench.

.DESCRIPTION
    Repeats a common developer task until stopped, in a private temporary
    folder. These tasks open TLS connections and, for some, start shells:
    the same gestures as an AI agent, with no AI involved.

      npm     npm install esbuild with a fresh cache (registry over TLS,
              install script run through cmd.exe)
      git     shallow clone of a public repository (git-remote-https over TLS)
      pip     download of a large wheel (PyPI over TLS)
      dotnet  NuGet restore without cache, then build (nuget.org over TLS)
      go      go build with an empty module cache (proxy.golang.org over TLS)
#>
param(
    [Parameter(Mandatory)][ValidateSet('npm', 'git', 'pip', 'dotnet', 'go')]
    [string]$Kind,
    [double]$Duration = 0
)

$ErrorActionPreference = 'Continue'
$work = Join-Path $env:TEMP ("agent-eval-work\{0}-{1}" -f $Kind, $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
$deadline = if ($Duration -gt 0) { (Get-Date).AddSeconds($Duration) } else { [datetime]::MaxValue }

switch ($Kind) {
    'npm' {
        Set-Content package.json '{ "name": "eval-npm", "version": "1.0.0", "private": true }'
    }
    'dotnet' {
        & dotnet new console -o app --force *> $null
        Set-Location app
        & dotnet add package Newtonsoft.Json *> $null
    }
    'go' {
        Set-Content go.mod "module evalgo`n`ngo 1.21`n`nrequire rsc.io/quote v1.5.2`n"
        Set-Content main.go "package main`n`nimport (`"fmt`"; `"rsc.io/quote`")`n`nfunc main() { fmt.Println(quote.Go()) }`n"
    }
}

while ((Get-Date) -lt $deadline) {
    switch ($Kind) {
        'npm' {
            $cache = Join-Path $work ("cache-" + [guid]::NewGuid().ToString('N'))
            & npm.cmd install esbuild --no-audit --no-fund --loglevel=error --cache $cache *> $null
            Remove-Item -Recurse -Force node_modules, package-lock.json, $cache -ErrorAction SilentlyContinue
        }
        'git' {
            & git clone --depth 1 --quiet https://github.com/expressjs/express.git repo *> $null
            Remove-Item -Recurse -Force repo -ErrorAction SilentlyContinue
        }
        'pip' {
            & py -3 -m pip download numpy --no-deps --no-cache-dir --quiet -d wheels *> $null
            Remove-Item -Recurse -Force wheels -ErrorAction SilentlyContinue
        }
        'dotnet' {
            $packages = Join-Path $work ("pkgs-" + [guid]::NewGuid().ToString('N'))
            & dotnet restore --force --no-cache --packages $packages *> $null
            & dotnet build --no-restore -nologo -v q *> $null
            Remove-Item -Recurse -Force $packages, bin, obj -ErrorAction SilentlyContinue
        }
        'go' {
            $env:GOMODCACHE = Join-Path $work ("modcache-" + [guid]::NewGuid().ToString('N'))
            $env:GOFLAGS = '-mod=mod'
            & go build -o app.exe . *> $null
            & go clean -modcache *> $null
            Remove-Item -Force app.exe, go.sum -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 300
}
