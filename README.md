# Threaded Port Scanner

## ⓘ Overview

The Threaded Port Scanner is a modern, dark-themed Windows desktop application built in Python 3.14 using the standard Tkinter framework. It provides an intuitive interface for performing TCP / UDP network scans, banner grabbing, and multi-threaded enumeration. This project is part of my cybersecurity & Python development portfolio, showcasing practical knowledge of network programming, concurrency, and secure software design principles.

> ⚠️ This tool is intended only for authorized testing on your own devices, lab environments, or explicitly permitted hosts such as `scanme.nmap.org`. Please do not scan any system without consent.

---

## GUI Preview

<p align="left">
  <img src="screenshots/Screenshot 2025-11-18 141219.png" width="900">
</p>

---

## App Icon

<p align="left">
  <img src="screenshots/icon.ico" width="50">
  <img src="screenshots/icon.png" width="200">
</p>

---

## Features

* Multithreaded scanning using `concurrent.futures.ThreadPoolExecutor`
* TCP / UDP support
* Flexible target input: single IPs, IP ranges, CIDR notation, hostnames
* Flexible ports: comma-separated lists or ranges (`22,80,443,8000-8100`)
* Optional TCP banner grabbing (best-effort, non-intrusive)
* Dark-mode Tkinter GUI with presets
* Export results to CSV or JSON
* Detailed logging via `port_scanner.log`
* Error handling & safe threading
* Presets (built-in + persistent user presets)
* Fixed window size for consistent demos
* Standard-library only — no external dependencies (Python 3.8+ / 3.14 tested)

---

## Project Structure

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

## Installation

Prerequisites
- Python 3.8 – 3.14  
- `tkinter` (usually included with Python on Windows)

Clone the Repository
```bash
git clone https://github.com/awl4114awl/Threaded-Port-Scanner.git
cd Threaded-Port-Scanner
````

Optional: Create a Virtual Environment (this is recommended)

```bash
python -m venv .venv
# PowerShell
.venv\Scripts\Activate.ps1
# cmd
.venv\Scripts\activate.bat
```

## Running the Application

```bash
python port_scanner.py
```

_Hopefully, the GUI will launch._

---

## How the Scanner Works

The Threaded Port Scanner performs fast, concurrent port checks using Python’s built-in `socket` and `concurrent.futures` modules. There are no external dependencies required.

1. Input Parsing

   * Accepts single IPs, IP ranges (`192.168.1.10–20`), or CIDR blocks (`10.0.0.0/28`).
   * Expands ports entered as comma-separated lists or ranges (`22,80,443,8000-8100`).

2. Threaded Execution

   * Uses a `ThreadPoolExecutor` to probe multiple ports and hosts in parallel.
   * Each worker runs a lightweight TCP or UDP check with timeout control.

3. Port Probing

   * TCP: Attempts to connect and, if enabled, performs simple banner grabbing to identify services.
   * UDP: Sends empty datagrams and listens for responses or timeouts (open/filtered detection).

4. Result Collection

   * Each thread pushes results to a thread-safe queue.
   * The GUI polls the queue to update the live table in real-time (non-blocking).

5. Data Logging & Export

   * Results include IP, port, protocol, status, banner, duration, and timestamp.
   * Scans can be exported to CSV or JSON for further analysis.

6. User Experience

   * Fully asynchronous UI — stays responsive even with hundreds of concurrent probes.
   * Supports dark mode, fixed window size, and custom presets for common scan configurations.

---

## Output Overview — What You Can Expect to See

* CSV / JSON export includes: `ip, port, protocol, status, banner, duration, ts`
* Log file: `port_scanner.log` — contains runtime info and errors
* Statuses explained:

  * `Open` — connection succeeded
  * `Closed` — connection refused
  * `Closed/Filtered` — timed-out or filtered (likely firewall)
  * `Open|Filtered` — UDP probe with no reply (ambiguous)
  * `Error` — network / permission issue

Example result from scanning `scanme.nmap.org` (allowed for testing):

| ip              | port | protocol | status | banner                                             |
| --------------- | ---- | -------- | ------ | -------------------------------------------------- |
| scanme.nmap.org | 22   | TCP      | Open   | `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`       |
| scanme.nmap.org | 80   | TCP      | Open   | *(no immediate banner — use `curl -I` to inspect)* |

> Exported CSV filename example: `scanme_sample_results.csv` (`ip,port,protocol,status,banner,duration,ts`)

---

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE) for details.

---
