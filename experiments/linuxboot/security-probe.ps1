# Disposable offline VM only. Never print recovery passwords or TPM owner secrets.
$ErrorActionPreference = 'Stop'
$root = 'S:\crabefi-installed'
New-Item -ItemType Directory -Force $root | Out-Null
$result = [ordered]@{ Phase = 'observe'; SecureBoot = $null; Tpm = $null; BitLocker = $null; Error = $null }
try {
    if (Test-Path "$root\security-phase.txt") { $result.Phase = (Get-Content "$root\security-phase.txt" -Raw).Trim() }
    try { $result.SecureBoot = [bool](Confirm-SecureBootUEFI) } catch { $result.SecureBootError = $_.Exception.Message }
    $tpm = Get-Tpm
    $result.Tpm = $tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,RestartPending,AutoProvisioning,ManufacturerIdTxt,ManufacturerVersion,ManagedAuthLevel
    tpmtool.exe getdeviceinformation 2>&1 | Out-File -Encoding UTF8 "$root\tpm.txt"
    if ($result.Phase -eq 'provision') {
        $result.Provision = Initialize-Tpm | Select-Object TpmReady,RestartRequired,ShutdownRequired,ClearRequired,PhysicalPresenceRequired
        $result.Tpm = Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,RestartPending,AutoProvisioning,ManufacturerIdTxt,ManufacturerVersion
    }
    if ($result.Phase -in @('encrypt','verify') -and $result.SecureBoot -ne $true) { throw 'Secure Boot is not enabled; refusing combined-security test' }
    if ($result.Phase -eq 'encrypt') {
        if (-not (Get-Tpm).TpmReady) { throw 'TPM is not ready; refusing non-TPM encryption fallback' }
        Enable-BitLocker -MountPoint C: -UsedSpaceOnly -TpmProtector -SkipHardwareTest -EncryptionMethod XtsAes128 | Out-Null
        # TPM-only: no recovery password, clear-key protector or key file on the ESP.
        # The disposable VM has plaintext source-image and private TPM-state backups.
        $deadline = (Get-Date).AddMinutes(15)
        while ((Get-BitLockerVolume C:).VolumeStatus -ne 'FullyEncrypted') {
            if ((Get-Date) -gt $deadline) { throw 'Encryption did not complete before the test deadline' }
            Start-Sleep -Seconds 5
        }
    }
    $volume = Get-BitLockerVolume C:
    $result.BitLocker = [ordered]@{ MountPoint = $volume.MountPoint; VolumeStatus = $volume.VolumeStatus.ToString(); EncryptionPercentage = $volume.EncryptionPercentage; ProtectionStatus = $volume.ProtectionStatus.ToString(); LockStatus = $volume.LockStatus.ToString(); EncryptionMethod = $volume.EncryptionMethod.ToString() }
    $result.Protectors = @($volume.KeyProtector | Select-Object KeyProtectorId,@{Name='KeyProtectorType';Expression={$_.KeyProtectorType.ToString()}})
    $profiles = @()
    foreach ($protector in @($volume.KeyProtector | Where-Object KeyProtectorType -eq Tpm)) {
        $cim = Get-CimInstance -Namespace 'Root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'"
        $profile = Invoke-CimMethod -InputObject $cim -MethodName GetKeyProtectorPlatformValidationProfile -Arguments @{ VolumeKeyProtectorID = $protector.KeyProtectorId }
        $profiles += [ordered]@{ ProtectorId = $protector.KeyProtectorId; ReturnValue = $profile.ReturnValue; PCRs = @($profile.PlatformValidationProfile) }
    }
    $result.ValidationProfiles = $profiles
    manage-bde.exe -status C: 2>&1 | Out-File -Encoding UTF8 "$root\bitlocker.txt"
    if ($result.Phase -eq 'verify') {
        if ($volume.VolumeStatus -ne 'FullyEncrypted' -or $volume.ProtectionStatus -ne 'On') { throw 'BitLocker encryption/protection is not active' }
        if (-not ($volume.KeyProtector | Where-Object KeyProtectorType -eq Tpm)) { throw 'No TPM-only protector present' }
    }
} catch {
    $result.Error = $_.Exception.Message
    $result.Error | Set-Content -Encoding UTF8 "$root\security-error.txt"
} finally {
    $result | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 "$root\security.json"
}
if ($result.Error) { exit 1 }
