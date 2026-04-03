<p align="center">
  <h1 align="center">ThreatLens</h1>
  <p align="center">
    <strong>AI-Powered File Threat Analyzer</strong>
  </p>
  <p align="center">
    Upload any file. Get a clear explanation of what it does and why it's dangerous.
  </p>
</p>

---

Unlike traditional antivirus that says "Trojan.Generic", ThreatLens **explains** threats in human language. It tells you exactly what a suspicious file does, which data it targets, and what you should do about it.

## Features

- **Static Analysis** --- PE imports, strings, entropy, YARA rules, packer detection
- **Script Analysis** --- Python, JavaScript, PowerShell, Batch, VBScript
- **AI Explanations** --- Ollama (free, local), OpenAI, YandexGPT
- **Threat Scoring** --- LOW / MEDIUM / HIGH / CRITICAL with detailed breakdown
- **Beautiful CLI** --- Colored output with rich formatting
- **Multi-format** --- Text reports, JSON output, Web UI

## Quick Start

```bash
git clone https://github.com/MaximkaVLG/threatlens.git
cd threatlens
pip install -r requirements.txt

# Scan a file
python -m threatlens scan suspicious.exe

# Scan with AI explanation
python -m threatlens scan suspicious.exe --ai --provider ollama

# Scan a directory
python -m threatlens scan ./downloads/ --recursive

# JSON output
python -m threatlens scan file.exe --format json
```

## What It Detects

| Category | Examples |
|----------|----------|
| **Password Theft** | Chrome/Firefox credential access, wallet.dat |
| **Code Injection** | CreateRemoteThread, WriteProcessMemory |
| **Keyloggers** | GetAsyncKeyState, keyboard hooks |
| **Network Activity** | HTTP requests, C2 communication |
| **Persistence** | Registry autorun, scheduled tasks, startup |
| **Obfuscation** | Base64, eval/exec, packed binaries |
| **Data Exfiltration** | Telegram bots, Discord webhooks, email |
| **Privilege Escalation** | Token manipulation, service creation |

## AI Providers

| Provider | Cost | Setup |
|----------|------|-------|
| **Ollama** (recommended) | Free | `ollama serve` + `ollama pull llama3.1` |
| **OpenAI** | Paid | Set `OPENAI_API_KEY` in `.env` |
| **YandexGPT** | Paid | Set `YANDEX_OAUTH_TOKEN` in `.env` |

## Example Output

```
+---------- Threat Assessment ----------+
|  RISK: ##########  CRITICAL  (100/100) |
|                                        |
|  This file is almost certainly         |
|  malicious.                            |
+----------------------------------------+

Findings:
  !! Imports CreateRemoteThread (code injection)
  !! String: "AppData\Chrome\Login Data" (password theft)
  !  Base64 encoding (obfuscation)
  !  HTTP requests to external server
  !  Registry autorun persistence

AI Explanation:
  This file is a password stealer that:
  1. Injects code into running processes
  2. Reads saved passwords from Chrome
  3. Sends stolen data to a remote server

  Recommendation: DELETE immediately.
```

## License

MIT License
