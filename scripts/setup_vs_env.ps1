# Visual Studio Developer PowerShell Environment Setup
# This script finds and launches the VS Developer Shell
# Can be used directly or as Cursor's default terminal profile

# Try to find Visual Studio installation
# Priority: VS 18 (2024) first, then VS 2022, then VS 2019
$vsPaths = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2019\Professional\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"
)

$vsDevShellPath = $null
foreach ($path in $vsPaths) {
    if (Test-Path $path) {
        $vsDevShellPath = $path
        Write-Host "Found Visual Studio at: $path" -ForegroundColor Green
        break
    }
}

if (-not $vsDevShellPath) {
    Write-Host "Error: Visual Studio Developer PowerShell not found!" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2019 or 2022 with C++ build tools." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Tried paths:" -ForegroundColor Yellow
    foreach ($path in $vsPaths) {
        Write-Host "  - $path" -ForegroundColor Gray
    }
    exit 1
}

# Launch VS Developer Shell
Write-Host "Launching Visual Studio Developer PowerShell..." -ForegroundColor Cyan
& $vsDevShellPath -Arch amd64

# If we get here, the shell was closed
Write-Host "VS Developer Shell closed." -ForegroundColor Yellow
