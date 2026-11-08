<#
.SYNOPSIS
    Tests, builds, signs and packages detectorAgent for Intune.

.DESCRIPTION
    1. go vet and go test;
    2. embeds the Windows manifest, icon and version resource (go-winres);
    3. recreates dist\ from scratch: dist\detectoragent.exe with the version
       stamped in, the deployment scripts, and a copy of the branding folder
       (Intune Win32 app content). Edit branding\, never dist\branding:
       dist\ is emptied at every build;
    4. optionally signs the binary and the scripts with the company
       code-signing certificate (Set-AuthenticodeSignature: no Windows SDK
       needed);
    5. validates dist\branding\branding.yaml and prints the Intune detection
       values;
    6. optionally wraps dist\ into out\detectorAgent-<version>.intunewin with
       the Microsoft Win32 Content Prep Tool.

.EXAMPLE
    .\build.ps1 -Version 1.0.0
    .\build.ps1 -Version 1.0.0 -CertThumbprint 0123ABCD... -IntuneWinAppUtil C:\Tools\IntuneWinAppUtil.exe
#>
[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    # Thumbprint of a code-signing certificate in Cert:\CurrentUser\My or
    # Cert:\LocalMachine\My, with its private key.
    [string]$CertThumbprint,
    # Time-stamp server (an http:// URL). Empty: no time stamp.
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    # Path to IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool).
    [string]$IntuneWinAppUtil
)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $numeric = ($Version -replace '[^0-9.]', '').Trim('.')
    while (($numeric.Split('.')).Count -lt 4) { $numeric += '.0' }

    go vet ./...
    if ($LASTEXITCODE) { throw 'go vet failed' }
    go test ./...
    if ($LASTEXITCODE) { throw 'tests failed' }

    $winres = Join-Path (go env GOPATH) 'bin\go-winres.exe'
    if (-not (Test-Path $winres)) {
        go install github.com/tc-hib/go-winres@latest
    }
    & $winres make --arch amd64 --product-version $numeric --file-version $numeric
    if ($LASTEXITCODE) { throw 'go-winres failed' }

    # dist\ is the package: it is emptied first so that it holds exactly the
    # files of this build, never leftovers of an earlier one.
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    try { Get-ChildItem dist -Force | Remove-Item -Recurse -Force -ErrorAction Stop }
    catch { throw "cannot empty dist\ (close any program using it, such as a preview window): $($_.Exception.Message)" }
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o dist\detectoragent.exe .
    if ($LASTEXITCODE) { throw 'go build failed' }

    $scripts = 'install.ps1', 'uninstall.ps1', 'intune-detect.ps1'
    foreach ($s in $scripts) { Copy-Item (Join-Path scripts $s) dist\ -Force }
    # Disclaimer branding: branding\ is the only place to edit it.
    Copy-Item branding -Destination dist\branding -Recurse -Force

    # Sign the binary and the scripts. Set-AuthenticodeSignature signs
    # executables as well as scripts. A Group Policy execution policy such as
    # AllSigned overrides "-ExecutionPolicy Bypass": unsigned scripts would not run.
    if ($CertThumbprint) {
        # A thumbprint copied from the certificate dialog can hold spaces and an
        # invisible leading character.
        $thumbprint = $CertThumbprint -replace '[^0-9A-Fa-f]', ''
        $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
            Where-Object Thumbprint -eq $thumbprint | Select-Object -First 1
        if (-not $cert) {
            throw "no code-signing certificate with thumbprint $thumbprint and its private key in Cert:\CurrentUser\My or Cert:\LocalMachine\My"
        }
        $signing = @{ Certificate = $cert; HashAlgorithm = 'SHA256' }
        if ($TimestampUrl) { $signing.TimestampServer = $TimestampUrl }
        foreach ($f in @('detectoragent.exe') + $scripts) {
            $sig = Set-AuthenticodeSignature -FilePath (Join-Path dist $f) @signing
            if ($sig.Status -ne 'Valid') { throw "signing $f failed: $($sig.StatusMessage)" }
        }
        Write-Output "Signed detectoragent.exe and the scripts with $($cert.Subject)"
    }

    # The package must not ship an invalid branding file: install.ps1 would refuse it.
    $ErrorActionPreference = 'Continue' # native error output must not stop the build early
    $check = @(& .\dist\detectoragent.exe check-branding 2>&1 | ForEach-Object { "$_" })
    $checkCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($checkCode) { throw "invalid branding\branding.yaml:`n$($check -join "`n")" }
    if (($check -join "`n") -match 'company:\s*ACME Corporation') {
        Write-Warning 'branding\ holds the ACME demo: replace it with your own branding before deploying.'
    }
    $brandingVersion = 1
    $match = [regex]::Match(($check -join "`n"), 'version:\s*(\d+)')
    if ($match.Success) { $brandingVersion = [int]$match.Groups[1].Value }
    $fileVersion = (Get-Item dist\detectoragent.exe).VersionInfo.FileVersion

    if ($IntuneWinAppUtil) {
        # Full paths, as in Microsoft's examples; the output file is looked up
        # rather than assumed.
        $distFull = (Resolve-Path dist).Path
        $outFull = (New-Item -ItemType Directory -Force -Path out).FullName
        $started = Get-Date
        & $IntuneWinAppUtil -c $distFull -s (Join-Path $distFull 'install.ps1') -o $outFull -q
        if ($LASTEXITCODE) { throw 'IntuneWinAppUtil failed' }
        $made = Get-ChildItem $outFull -Filter *.intunewin | Where-Object LastWriteTime -ge $started.AddSeconds(-5) |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $made) { throw "IntuneWinAppUtil produced no .intunewin file in $outFull" }
        $package = Join-Path $outFull "detectorAgent-$Version.intunewin"
        if ($made.FullName -ne $package) { Move-Item -Force $made.FullName $package }
        Write-Output "Intune package: $package"
    }

    Write-Output "Built dist\detectoragent.exe $Version (file version $fileVersion, branding version $brandingVersion)"
    Write-Output 'Intune detection rule: HKEY_LOCAL_MACHINE\SOFTWARE\DetectorAgent, value Package, Equals:'
    Write-Output "  production app (disclaimer):  $fileVersion-b$brandingVersion-disclaimer"
    Write-Output "  pilot app (-NoDisclaimer):    $fileVersion-b$brandingVersion-silent"
}
finally {
    Pop-Location
}
