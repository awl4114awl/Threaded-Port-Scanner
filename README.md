# ⚓ Threaded Port Scanner

![Python](https://img.shields.io/badge/Python-3.14-blue?style=for-the-badge&logo=python)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Prototype-orange?style=for-the-badge)

---

## 🧠 Overview

A lightweight, educational **multithreaded port scanner** with a dark-mode Tkinter GUI.  
Designed for laboratory and learning use to demonstrate network enumeration basics (TCP/UDP scanning, banner grabbing, concurrent scanning) in a safe and ethical way.

> ⚠️ **Ethical Use Notice**
> ---
> This tool is intended **only** for authorized testing — your own devices, lab VMs, or explicitly permitted hosts such as `scanme.nmap.org`. Do **not** scan any system without permission.

---

## 🖼 GUI Preview

<p align="left">
  <img src="screenshots/Screenshot 2025-11-18 141219.png" width="650">
</p>

---

## 🧩 App Icon

<p align="left">
  <img src="screenshots/icon.ico" width="50">
  <img src="screenshots/icon.png" width="200">
</p>

---

## 🚀 Features

- **Multithreaded scanning** using `concurrent.futures.ThreadPoolExecutor`
- **TCP / UDP support**
- **Flexible target input:** single IPs, IP ranges, CIDR notation, hostnames
- **Flexible ports:** comma-separated lists or ranges (`22,80,443,8000-8100`)
- **Optional TCP banner grabbing** (best-effort, non-intrusive)
- **Dark-mode Tkinter GUI** with presets
- **Export results** to CSV or JSON
- **Detailed logging** via `port_scanner.log`
- **Error handling & safe threading**
- **Presets** (built-in + persistent user presets)
- **Fixed window size** for consistent demos
- **Standard-library only** — no external dependencies (Python 3.8+ / 3.14 tested)

---

## 📁 Project Structure

```
Threaded-Port-Scanner/
│
├── screenshots/
│   ├── Screenshot 2025-11-18 141219.png     # Main UI screenshot
│   ├── Screenshot 2025-11-18 141552.png     # Scan results example
│   ├── icon.ico                             # Application window/taskbar icon
│   └── icon.png                             # README / branding icon
│
├── .gitignore                               # Excludes venvs, logs, and IDE files
├── LICENSE                                  # MIT license
├── README.md                                # Documentation and usage guide
└── port_scanner.py                          # Main threaded port scanner script
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.8 – 3.14  
- `tkinter` (usually included with Python on Windows)

### Clone the Repository
```bash
git clone https://github.com/awl4114awl/Threaded-Port-Scanner.git
cd Threaded-Port-Scanner
````

### Optional: Create a Virtual Environment (recommended)

```bash
python -m venv .venv
# PowerShell
.venv\Scripts\Activate.ps1
# cmd
.venv\Scripts\activate.bat
```

### Run the Application

```bash
python port_scanner.py
```

---

## 🧭 Usage

### GUI Fields

| Field                                   | Description                                            |
| --------------------------------------- | ------------------------------------------------------ |
| **Target IP / Range / CIDR**            | Example: `127.0.0.1`, `192.168.1.10-20`, `10.0.0.0/28` |
| **Ports**                               | Example: `22,80,443,8000-8100`                         |
| **Protocol**                            | TCP (default) or UDP                                   |
| **Timeout (s)**                         | Connection timeout per probe                           |
| **Threads**                             | Number of concurrent workers (e.g. 25)                 |
| **Banner Grab**                         | Optional TCP banner read                               |
| **Presets**                             | Quick-select common targets/port-sets, save/delete     |
| **Start / Stop / Save Results / Clear** | Main controls                                          |

### Example Safe Scan

1. Target: `scanme.nmap.org`
2. Ports: `22,80,443,8080`
3. Protocol: `TCP`
4. Timeout: `1`
5. Threads: `10`
6. Click **Start Scan**

---

## 📊 Output

* **CSV / JSON export** includes: `ip, port, protocol, status, banner, duration, ts`
* **Log file:** `port_scanner.log` — contains runtime info and errors
* **Statuses explained:**

  * `Open` — connection succeeded
  * `Closed` — connection refused
  * `Closed/Filtered` — timed-out or filtered (likely firewall)
  * `Open|Filtered` — UDP probe with no reply (ambiguous)
  * `Error` — network / permission issue

---

## 🔍 Sample scan (safe demo)

Example result from scanning `scanme.nmap.org` (allowed for testing):

| ip              | port | protocol | status | banner                                             |
| --------------- | ---- | -------- | ------ | -------------------------------------------------- |
| scanme.nmap.org | 22   | TCP      | Open   | `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`       |
| scanme.nmap.org | 80   | TCP      | Open   | *(no immediate banner — use `curl -I` to inspect)* |

> Exported CSV filename example: `scanme_sample_results.csv` (`ip,port,protocol,status,banner,duration,ts`)

---

## 🔧 PyCharm Quick Setup

1. Open the project in PyCharm.
2. Configure interpreter: use `.venv\Scripts\python.exe` or system Python 3.14.
3. Right-click `port_scanner.py` → **Run** (or create a Run configuration).
4. If venv activation blocked in PowerShell:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
.venv\Scripts\Activate.ps1
```

---

## 🧠 Technical Overview

* **Target parsing:** expands CIDR / ranges and hostnames into individual targets
* **Port parsing:** handles mixed comma + range syntax and validates 1–65535
* **Scanning engine:** `socket` with per-connection timeout; TCP connect + optional banner; best-effort UDP probe
* **Threading:** ThreadPoolExecutor manages worker threads; results queued to main thread via `queue.Queue` and `tkinter.after()` for thread-safe UI updates
* **Presets:** built-in safe presets + user-saved presets persisted to `presets.json` (user presets can be added/deleted)
* **GUI:** styled dark-mode `ttk` theme, fixed window size for consistent demos
* **Logging & export:** `port_scanner.log` and CSV/JSON exports for audit and reporting

---

## .gitignore (suggested)

Add a `.gitignore` file to the repo root to avoid committing artifacts:

```
# Virtualenv
.venv/
venv/
__pycache__/

# Logs and exports
*.log
*.csv
*.json

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

---

## presets.json (optional example)

If you want to include sample presets, add a `presets.json` (or let users create it at runtime):

```json
{
  "My-Local-VulnHub": {
    "target": "192.168.56.101",
    "ports": "22,80,443,445,8080",
    "protocol": "TCP",
    "threads": "20",
    "timeout": "1"
  }
}
```

*(Add `presets.json` to `.gitignore` if you prefer not to include user presets in the repo.)*

---

## License

This project is released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---
