# Build a minimal Windows PE boot media tree for CrabEFI smoke testing.
#
# This script is intended to run on a Windows GitHub Actions runner. It downloads
# the official Microsoft ADK and Windows PE add-on, creates amd64 WinPE media,
# and customizes startnet.cmd to emit a deterministic marker on COM1.
#
# Output layout:
#   windows-assets/x86_64/media/EFI/BOOT/BOOTX64.EFI
#   windows-assets/x86_64/media/sources/boot.wim

param(
    [string]$Arch = "x86_64",
    [string]$OutputDir = "windows-assets/x86_64/media",
    [string]$SuccessMarker = "CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS"
)

$ErrorActionPreference = "Stop"

if ($Arch -ne "x86_64") {
    throw "Only x86_64/amd64 WinPE smoke media is supported today"
}

$adkUrl = "https://go.microsoft.com/fwlink/?linkid=2289980"
$winpeUrl = "https://go.microsoft.com/fwlink/?linkid=2289981"
$workRoot = Join-Path $env:TEMP "crabefi-winpe-smoke"
$adkSetup = Join-Path $workRoot "adksetup.exe"
$winpeSetup = Join-Path $workRoot "adkwinpesetup.exe"
$winpeWork = Join-Path $workRoot "WinPE_amd64"
$mountDir = Join-Path $workRoot "mount"

New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

function Invoke-Download {
    param([string]$Url, [string]$OutFile)
    if (Test-Path $OutFile) {
        Write-Host "Using cached download: $OutFile"
        return
    }
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -MaximumRedirection 10
}

function Invoke-LoggedProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$Description
    )

    Write-Host "==> $Description"
    Write-Host "$FilePath $($Arguments -join ' ')"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$Description failed with exit code $($process.ExitCode)"
    }
}

Invoke-Download -Url $adkUrl -OutFile $adkSetup
Invoke-Download -Url $winpeUrl -OutFile $winpeSetup

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$copype = Join-Path $kitsRoot "Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd"
$makeWinPeMedia = Join-Path $kitsRoot "Assessment and Deployment Kit\Windows Preinstallation Environment\MakeWinPEMedia.cmd"

if (!(Test-Path $copype) -or !(Test-Path $makeWinPeMedia)) {
    Invoke-LoggedProcess `
        -FilePath $adkSetup `
        -Arguments @("/quiet", "/norestart", "/features", "OptionId.DeploymentTools") `
        -Description "Install Windows ADK Deployment Tools"

    Invoke-LoggedProcess `
        -FilePath $winpeSetup `
        -Arguments @("/quiet", "/norestart", "/features", "OptionId.WindowsPreinstallationEnvironment") `
        -Description "Install Windows ADK WinPE add-on"
}

if (!(Test-Path $copype)) {
    throw "copype.cmd not found after ADK install: $copype"
}
if (!(Test-Path $makeWinPeMedia)) {
    throw "MakeWinPEMedia.cmd not found after ADK install: $makeWinPeMedia"
}

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $winpeWork, $mountDir
Invoke-LoggedProcess `
    -FilePath $copype `
    -Arguments @("amd64", $winpeWork) `
    -Description "Create WinPE amd64 working tree"

New-Item -ItemType Directory -Force -Path $mountDir | Out-Null
$bootWim = Join-Path $winpeWork "media\sources\boot.wim"
Invoke-LoggedProcess `
    -FilePath "dism.exe" `
    -Arguments @("/Mount-Image", "/ImageFile:$bootWim", "/Index:1", "/MountDir:$mountDir") `
    -Description "Mount WinPE boot.wim"

try {
    $startnet = Join-Path $mountDir "Windows\System32\startnet.cmd"
    @"
wpeinit
mode COM1 BAUD=115200 PARITY=n DATA=8 STOP=1
<nul set /p dummy=$SuccessMarker > COM1
wpeutil shutdown
"@ | Set-Content -Path $startnet -Encoding ASCII

    Invoke-LoggedProcess `
        -FilePath "dism.exe" `
        -Arguments @("/Unmount-Image", "/MountDir:$mountDir", "/Commit") `
        -Description "Commit WinPE boot.wim customization"
} catch {
    dism.exe /Unmount-Image /MountDir:$mountDir /Discard | Out-Null
    throw
}

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $OutputDir
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputDir) | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $winpeWork "media") -Destination $OutputDir

Write-Host "WinPE smoke media created at $OutputDir"
Get-ChildItem -Recurse $OutputDir | Select-Object -First 20 | Format-Table FullName, Length
