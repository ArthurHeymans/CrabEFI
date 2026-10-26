@echo off
rem Disposable WinPE patch guest only: its disk 0 is the private WinPE image.
wpeinit
set TARGET=
for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%D:\Windows\Setup\Scripts\installed-smoke.cmd set TARGET=%%D:
if not defined TARGET goto failed
copy X:\Windows\System32\security-smoke.cmd %TARGET%\Windows\Setup\Scripts\installed-smoke.cmd
if errorlevel 1 goto failed
copy X:\Windows\System32\desktop-smoke.cmd %TARGET%\Windows\Setup\Scripts\desktop-smoke.cmd
if errorlevel 1 goto failed
copy X:\Windows\System32\security-probe.ps1 %TARGET%\Windows\Setup\Scripts\security-probe.ps1
if errorlevel 1 goto failed
(echo select disk 0&echo select partition 1&echo assign letter=P&echo exit)>X:\patch-esp.txt
diskpart /s X:\patch-esp.txt
echo WINDOWS_SECURITY_PROBE_INSTALLED>P:\patched.txt
wpeutil shutdown
exit /b
:failed
cmd.exe
