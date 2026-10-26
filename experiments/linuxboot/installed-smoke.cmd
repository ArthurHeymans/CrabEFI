@echo off
setlocal
rem This file runs only inside the disposable, network-isolated installed guest.
reg query HKLM\SYSTEM\CurrentControlSet\Control\MiniNT >nul 2>&1
if not errorlevel 1 exit /b 20
if /i "%SystemDrive%"=="X:" exit /b 21
if not exist "%WINDIR%\explorer.exe" exit /b 22
mountvol S: /S >nul 2>&1
if not exist S:\EFI exit /b 23
if not exist S:\crabefi-installed mkdir S:\crabefi-installed
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallationType >S:\crabefi-installed\installation-type.txt
findstr /c:"Client" S:\crabefi-installed\installation-type.txt >nul
if errorlevel 1 exit /b 24
rem Use native tools: PowerShell startup can delay an otherwise ready desktop.
for /l %%I in (1,1,60) do (
    tasklist /fo csv /nh /fi "IMAGENAME eq explorer.exe" >S:\crabefi-installed\desktop.txt 2>&1
    findstr /i /c:"explorer.exe" S:\crabefi-installed\desktop.txt >nul && goto desktop_ready
    ping -n 3 127.0.0.1 >nul
)
exit /b 25
:desktop_ready
ver >S:\crabefi-installed\version.txt
echo SYSTEMDRIVE=%SystemDrive%>S:\crabefi-installed\environment.txt
echo SYSTEMROOT=%SystemRoot%>>S:\crabefi-installed\environment.txt
echo SESSIONNAME=%SESSIONNAME%>>S:\crabefi-installed\environment.txt
whoami >>S:\crabefi-installed\environment.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion >>S:\crabefi-installed\version.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionID >>S:\crabefi-installed\version.txt
bcdedit /enum {current} >S:\crabefi-installed\boot-loader.txt 2>&1
rem Re-run the same proof after subsequent automatic logons, not only OOBE.
schtasks /Create /SC ONLOGON /RU SYSTEM /RL HIGHEST /TN CrabEFIInstalledSmoke /TR "%WINDIR%\System32\cmd.exe /c %WINDIR%\Setup\Scripts\installed-smoke.cmd" /F >S:\crabefi-installed\task.txt 2>&1
if errorlevel 1 exit /b 26
powercfg /h off >nul 2>&1
echo CRABEFI_INSTALLED_WINDOWS_BOOT_SUCCESS>S:\crabefi-installed\success.txt
shutdown.exe /s /t 0
