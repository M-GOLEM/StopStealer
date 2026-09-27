<#
.SYNOPSIS
    StopStealer - Advanced Anti-Stealer Protection Installer
.DESCRIPTION
    Installs the StopStealer protection service and GUI application.
    Must be run as Administrator.
.NOTES
    Version: 1.0
#>

param(
    [switch]$Uninstall,
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$ServiceName = "StopStealerProtection"
$ServiceDisplay = "StopStealer Protection Service"
$InstallDir = "$env:LOCALAPPDATA\StopStealer"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Header {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "    StopStealer - Anti-Stealer Protection  " -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Build-Project {
    Write-Host "[*] Building project..." -ForegroundColor Yellow

    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Host "[!] .NET SDK not found. Please install .NET 8 SDK." -ForegroundColor Red
        exit 1
    }

    $solutionPath = Join-Path $ScriptDir "StopStealer.sln"
    if (-not (Test-Path $solutionPath)) {
        Write-Host "[!] Solution file not found at: $solutionPath" -ForegroundColor Red
        exit 1
    }

    Write-Host "    Restoring packages..." -ForegroundColor Gray
    & dotnet restore $solutionPath

    Write-Host "    Building Release..." -ForegroundColor Gray
    & dotnet build $solutionPath -c Release --no-restore

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Build failed." -ForegroundColor Red
        exit 1
    }

    Write-Host "[+] Build successful!" -ForegroundColor Green
}

function Install-StopStealer {
    Write-Host "[*] Installing StopStealer..." -ForegroundColor Yellow

    if (-not (Test-Admin)) {
        Write-Host "[!] This script must be run as Administrator." -ForegroundColor Red
        exit 1
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $buildOutput = Join-Path $ScriptDir "StopStealer.Service\bin\Release\net8.0-windows"
    $guiOutput = Join-Path $ScriptDir "StopStealer.GUI\bin\Release\net8.0-windows"

    if (-not (Test-Path $buildOutput)) {
        Write-Host "[!] Build output not found. Run with -Build first." -ForegroundColor Red
        exit 1
    }

    Write-Host "    Copying files..." -ForegroundColor Gray
    Copy-Item -Path "$buildOutput\*" -Destination $InstallDir -Recurse -Force
    Copy-Item -Path "$guiOutput\*" -Destination $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "    Installing Windows Service..." -ForegroundColor Gray
    $serviceExe = Join-Path $InstallDir "StopStealer.Service.exe"

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "    Service already exists. Updating..." -ForegroundColor Gray
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    New-Service -Name $ServiceName `
        -DisplayName $ServiceDisplay `
        -BinaryPathName $serviceExe `
        -StartupType Automatic `
        -Description "StopStealer Advanced Anti-Stealer Protection Service" | Out-Null

    Write-Host "    Starting service..." -ForegroundColor Gray
    Start-Service -Name $ServiceName

    Write-Host "    Creating AutoStart shortcut..." -ForegroundColor Gray
    $startupFolder = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolder "StopStealer GUI.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallDir "StopStealer.GUI.exe"
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "StopStealer Protection Dashboard"
    $shortcut.Save()

    $guiExe = Join-Path $InstallDir "StopStealer.GUI.exe"
    if (Test-Path $guiExe) {
        Write-Host "    Starting GUI..." -ForegroundColor Gray
        Start-Process $guiExe
    }

    Write-Host ""
    Write-Host "[+] StopStealer installed successfully!" -ForegroundColor Green
    Write-Host "    Service: $ServiceDisplay (Running)" -ForegroundColor Cyan
    Write-Host "    Install: $InstallDir" -ForegroundColor Cyan
    Write-Host "    AutoStart: Enabled" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    All protection modules are active:" -ForegroundColor White
    Write-Host "    - Browser Data Protection" -ForegroundColor Gray
    Write-Host "    - Token Stealer Detection" -ForegroundColor Gray
    Write-Host "    - Process Guard" -ForegroundColor Gray
    Write-Host "    - Clipboard Protection" -ForegroundColor Gray
    Write-Host "    - Screenshot Monitor" -ForegroundColor Gray
    Write-Host "    - Camera Monitor" -ForegroundColor Gray
    Write-Host ""
}

function Uninstall-StopStealer {
    Write-Host "[*] Uninstalling StopStealer..." -ForegroundColor Yellow

    if (-not (Test-Admin)) {
        Write-Host "[!] This script must be run as Administrator." -ForegroundColor Red
        exit 1
    }

    Write-Host "    Stopping service..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

    Write-Host "    Removing service..." -ForegroundColor Gray
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "    Removing AutoStart shortcut..." -ForegroundColor Gray
    $startupFolder = [Environment]::GetFolderPath("Startup")
    Remove-Item -Path (Join-Path $startupFolder "StopStealer GUI.lnk") -Force -ErrorAction SilentlyContinue

    Write-Host "    Removing install directory..." -ForegroundColor Gray
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "[+] StopStealer uninstalled successfully!" -ForegroundColor Green
    Write-Host ""
}

Write-Header

if ($Uninstall) {
    Uninstall-StopStealer
} elseif ($Build) {
    Build-Project
    Install-StopStealer
} else {
    Install-StopStealer
}
