@echo off
mountvol S: /S >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%WINDIR%\Setup\Scripts\security-probe.ps1"
call "%WINDIR%\Setup\Scripts\desktop-smoke.cmd"
