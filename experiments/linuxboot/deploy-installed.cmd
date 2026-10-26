@echo off
setlocal
rem DESTRUCTIVE INSIDE THE TEST VM: target is its sole 64-GiB blank disk 0.
rem The harness attaches only new regular image files, never host block devices.
wpeinit
set SOURCE=
for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%D:\sources\install.wim set SOURCE=%%D:
if not defined SOURCE goto failed
(echo select disk 0&echo clean&echo convert gpt&echo create partition efi size=512&echo format quick fs=fat32 label=CRABEFI_ESP&echo assign letter=S&echo create partition msr size=16&echo create partition primary&echo format quick fs=ntfs label=CRABEFI_WINDOWS&echo assign letter=W&echo exit)>X:\partition-installed.txt
diskpart /s X:\partition-installed.txt >X:\partition-installed.log 2>&1
if not exist S:\ goto failed
if not exist W:\ goto failed
mkdir S:\crabefi-installed
copy X:\partition-installed.log S:\crabefi-installed\partition.txt
echo APPLYING_WINDOWS_PRO>S:\crabefi-installed\deployment-stage.txt
dism /Apply-Image /ImageFile:%SOURCE%\sources\install.wim /Index:6 /ApplyDir:W:\ /CheckIntegrity >S:\crabefi-installed\apply-image.txt 2>&1
if errorlevel 1 goto failed
if not exist W:\Windows\explorer.exe goto failed
if not exist W:\Windows\Panther mkdir W:\Windows\Panther
copy X:\Windows\System32\installed-unattend.xml W:\Windows\Panther\Unattend.xml
if errorlevel 1 goto failed
if not exist W:\Windows\Setup\Scripts mkdir W:\Windows\Setup\Scripts
copy X:\Windows\System32\installed-smoke.cmd W:\Windows\Setup\Scripts\installed-smoke.cmd
if errorlevel 1 goto failed
bcdboot W:\Windows /s S: /f UEFI >S:\crabefi-installed\bcdboot.txt 2>&1
if errorlevel 1 goto failed
if not exist S:\EFI\Boot mkdir S:\EFI\Boot
copy S:\EFI\Microsoft\Boot\bootmgfw.efi S:\EFI\Boot\bootx64.efi
if errorlevel 1 goto failed
echo WINDOWS_PRO_DEPLOYED>S:\crabefi-installed\deployment-stage.txt
echo CRABEFI_INSTALLED_WINDOWS_DEPLOYED>S:\crabefi-installed\deployed.txt
wpeutil shutdown
exit /b
:failed
if exist S:\crabefi-installed echo DEPLOYMENT_FAILED>S:\crabefi-installed\deployment-stage.txt
rem Stay in a command shell for QEMU diagnostics instead of claiming success.
cmd.exe
