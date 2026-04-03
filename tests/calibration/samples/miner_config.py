
import subprocess, os

config = {
    "pool": "stratum+tcp://pool.minexmr.com:4444",
    "wallet": "4ABC123...",
    "worker": os.environ.get("COMPUTERNAME", "worker"),
    "hashrate_target": 1000,
}

subprocess.run(["xmrig.exe", "--url", config["pool"], "--user", config["wallet"],
                "--donate-level", "1", "--threads", "4"])
