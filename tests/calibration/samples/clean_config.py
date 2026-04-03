
import json, os

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def save_config(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

config = load_config("settings.json")
print(f"App: {config.get('name', 'Unknown')}")
