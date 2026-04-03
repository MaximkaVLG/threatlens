"""Download community YARA rules for ThreatLens.

Run once after installation:
    python scripts/download_yara_rules.py

Downloads ~1500 rules from the YARA-Rules community project.
"""

import os
import subprocess
import sys

DEST = os.path.join(os.path.dirname(__file__), "..", "threatlens", "rules", "yara_community")


def main():
    if os.path.exists(DEST) and os.listdir(DEST):
        print(f"Community rules already exist at {DEST}")
        print("To update, delete the directory and run again.")
        return

    print("Downloading YARA community rules (~1500 rules)...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/Yara-Rules/rules.git", DEST],
            check=True,
        )
        # Count rules
        total = 0
        for root, dirs, files in os.walk(DEST):
            for f in files:
                if f.endswith((".yar", ".yara")):
                    total += 1
        print(f"Done! Downloaded {total} rule files.")
    except FileNotFoundError:
        print("Error: git not found. Install git and try again.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
