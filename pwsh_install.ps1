#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and installs the latest stable RustClip release from GitHub.
.DESCRIPTION
    Fetches the latest release from https://github.com/advenimus/rust-clip,
    detects the preferred installer type (MSI or NSIS EXE), downloads it to
    a temp directory, and optionally launches it.
.PARAMETER Type
    Installer format to download: 'msi' (default) or 'exe' (NSIS).
.PARAMETER DownloadOnly
    Download the installer but do not launch it.
.PARAMETER Destination
    Directory to save the installer. Defaults to the system temp folder.
.EXAMPLE
    irm https://raw.githubusercontent.com/advenimus/rust-clip/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1 -Type exe -DownloadOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('msi', 'exe')]
    [string]$Type = 'msi',

    [switch]$DownloadOnly,

    [string]$Destination = $env:TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo    = 'advenimus/rust-clip'
$ApiUrl  = "https://api.github.com/repos/$Repo/releases/latest"
$Headers = @{ 'User-Agent' = 'rustclip-installer/1.0' }

Write-Host "RustClip Installer" -ForegroundColor Cyan
Write-Host "------------------"

# Fetch release metadata
Write-Host "Fetching latest release info from GitHub..."
try {
    $release = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers
} catch {
    Write-Error "Failed to fetch release info: $_"
    exit 1
}

$version = $release.tag_name
Write-Host "Latest stable release: $version" -ForegroundColor Green

# Select asset based on requested type
$assets = $release.assets

$asset = switch ($Type) {
    'msi' { $assets | Where-Object { $_.name -match '\.msi$' } | Select-Object -First 1 }
    'exe' { $assets | Where-Object { $_.name -match '-setup\.exe$' } | Select-Object -First 1 }
}

if (-not $asset) {
    Write-Error "No $Type installer found in release $version. Available assets:`n$(($assets | Select-Object -ExpandProperty name) -join "`n")"
    exit 1
}

$fileName    = $asset.browser_download_url -replace '.+/', ''
$outPath     = Join-Path $Destination $fileName
$downloadUrl = $asset.browser_download_url

Write-Host "Downloading: $fileName ($([math]::Round($asset.size / 1MB, 1)) MB)"
Write-Host "From: $downloadUrl"
Write-Host "To:   $outPath"

# Download with progress
$ProgressPreference = 'SilentlyContinue'   # speeds up Invoke-WebRequest significantly
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $outPath -Headers $Headers
} catch {
    Write-Error "Download failed: $_"
    exit 1
}
$ProgressPreference = 'Continue'

# Verify size
$downloaded = (Get-Item $outPath).Length
if ($downloaded -ne $asset.size) {
    Write-Warning "Size mismatch — expected $($asset.size) bytes, got $downloaded bytes."
}

Write-Host "Download complete." -ForegroundColor Green

if ($DownloadOnly) {
    Write-Host "Installer saved to: $outPath"
    exit 0
}

# Launch installer
Write-Host "Launching installer..."
try {
    if ($Type -eq 'msi') {
        Start-Process msiexec.exe -ArgumentList "/i `"$outPath`"" -Wait
    } else {
        Start-Process -FilePath $outPath -Wait
    }
    Write-Host "Installation complete." -ForegroundColor Green
} catch {
    Write-Error "Failed to launch installer: $_"
    Write-Host "You can run it manually: $outPath"
    exit 1
}
