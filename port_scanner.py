#!/usr/bin/env python3
"""
Threaded Port Scanner - consolidated version
Features included:
 - TCP / UDP probes
 - Banner grabbing (TCP, best-effort)
 - concurrent.futures ThreadPoolExecutor
 - Dark-mode ttk styling (pure stdlib)
 - Presets (built-in + persistent user presets.json)
 - Export CSV / JSON
 - Fixed window size (Option A) -- change FIXED_WIDTH / FIXED_HEIGHT below
 - Thread-safe UI updates via queue + after()
 - Logging to port_scanner.log
 - No external dependencies (Python stdlib only)
"""
__author__ = "You"
__version__ = "1.1"

import ipaddress
import socket
import threading
import concurrent.futures
import queue
import csv
import json
import time
import datetime
import logging
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# ---------- Configuration ----------
PORT_SCANNER_LOG = "port_scanner.log"
PRESETS_FILE = "presets.json"
FIXED_WIDTH = 900
FIXED_HEIGHT = 520

# ---------- Logging ----------
logging.basicConfig(
    filename=PORT_SCANNER_LOG,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

def now_ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

# ---------- Utils: parse targets & ports ----------
def expand_targets(target_text):
    """
    Accepts comma-separated items:
      - single IP or hostname
      - range: 192.168.1.10-20 or 192.168.1.10-192.168.1.20
      - CIDR: 192.168.1.0/28
    Returns list of IPs/hostnames (strings).
    """
    targets = []
    if not target_text:
        return targets
    for part in target_text.split(","):
        p = part.strip()
        if not p:
            continue
        # CIDR
        if "/" in p:
            try:
                net = ipaddress.ip_network(p, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
            except Exception:
                logging.exception("Failed to parse CIDR target: %s", p)
                continue
        # range with dash
        elif "-" in p:
            try:
                a, b = p.split("-", 1)
                a = a.strip(); b = b.strip()
                # if end contains dot => full ip range
                if "." in b:
                    start = int(ipaddress.IPv4Address(a))
                    end = int(ipaddress.IPv4Address(b))
                    for ip_int in range(start, end + 1):
                        targets.append(str(ipaddress.IPv4Address(ip_int)))
                else:
                    # shorthand last-octet range: 192.168.1.10-20
                    base = ".".join(a.split(".")[:-1])
                    start_octet = int(a.split(".")[-1])
                    end_octet = int(b)
                    for o in range(start_octet, end_octet + 1):
                        targets.append(f"{base}.{o}")
            except Exception:
                logging.exception("Failed to parse range target: %s", p)
                continue
        else:
            targets.append(p)
    return targets

def expand_ports(port_text):
    """
    Parse ports text like "22,80,443,8000-8100"
    Return sorted list of unique ints.
    """
    ports = set()
    if not port_text:
        return []
    for part in port_text.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a.strip()); b = int(b.strip())
                for x in range(a, b+1):
                    if 1 <= x <= 65535:
                        ports.add(x)
            except Exception:
                logging.exception("Failed to parse port range: %s", p)
                continue
        else:
            try:
                n = int(p)
                if 1 <= n <= 65535:
                    ports.add(n)
            except Exception:
                logging.exception("Failed to parse port number: %s", p)
                continue
    return sorted(ports)

# ---------- Scanning primitives ----------
def tcp_scan(ip, port, timeout, do_banner=False):
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((ip, port))
        status = "Open"
        if do_banner:
            try:
                s.settimeout(min(0.8, timeout))
                data = s.recv(1024)
                if isinstance(data, bytes):
                    try:
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        banner = repr(data)
            except Exception:
                banner = ""
    except socket.timeout:
        status = "Closed/Filtered"
    except ConnectionRefusedError:
        status = "Closed"
    except Exception as e:
        status = f"Error: {e}"
        logging.debug("tcp_scan error: %s", e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    duration = round(time.time() - start, 3)
    return {"ip": ip, "port": port, "protocol": "TCP", "status": status, "banner": banner, "duration": duration, "ts": now_ts()}

def udp_scan(ip, port, timeout):
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.sendto(b"", (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            if isinstance(data, bytes):
                try:
                    banner = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = repr(data)
            status = "Open (recv)"
        except socket.timeout:
            status = "Open|Filtered"
    except PermissionError:
        status = "PermissionError"
    except Exception as e:
        status = f"Error: {e}"
        logging.debug("udp_scan error: %s", e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    duration = round(time.time() - start, 3)
    return {"ip": ip, "port": port, "protocol": "UDP", "status": status, "banner": banner, "duration": duration, "ts": now_ts()}

# ---------- GUI & Controller ----------
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Threaded Port Scanner")
        # fixed size (Option A)
        self.root.geometry(f"{FIXED_WIDTH}x{FIXED_HEIGHT}")
        self.root.resizable(False, False)
        self.root.minsize(FIXED_WIDTH, FIXED_HEIGHT)
        self.root.maxsize(FIXED_WIDTH, FIXED_HEIGHT)
        # center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (FIXED_WIDTH // 2)
        y = (self.root.winfo_screenheight() // 2) - (FIXED_HEIGHT // 2)
        self.root.geometry(f"+{x}+{y}")

        self.result_q = queue.Queue()
        self.stop_event = threading.Event()
        self.executor = None
        self.active_futures = []
        self.results = []

        self._setup_style()
        self._build_ui()

        # poll queue
        self.root.after(150, self._poll_queue)

    def _setup_style(self):
        # Dark theme using ttk "clam"
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        bg = "#0f0f0f"
        fieldbg = "#1a1a1a"
        fg = "#e6e6e6"
        button_bg = "#1f1f1f"

        self.root.configure(bg=bg)
        style.configure(".", background=bg, foreground=fg, fieldbackground=fieldbg, borderwidth=0)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=button_bg, foreground=fg, relief="flat")
        style.map("TButton", background=[("active", "#2a2a2a")])
        style.configure("TEntry", foreground=fg, fieldbackground=fieldbg)
        style.configure("Treeview", background=fieldbg, foreground=fg, fieldbackground=fieldbg, rowheight=22)
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="#ffffff")
        style.map("Treeview", background=[("selected", "#0078d7")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=8)
        frm.pack(fill="both", expand=True)

        # ---------- Presets row ----------
        self.presets_file = PRESETS_FILE
        self.default_presets = {
            "Loopback": {"target": "127.0.0.1", "ports": "8000", "protocol": "TCP", "threads": "10", "timeout": "1"},
            "Scanme (safe)": {"target": "scanme.nmap.org", "ports": "22,80,443,8080", "protocol": "TCP", "threads": "10", "timeout": "1"},
            "Common-Quick": {"target": "127.0.0.1", "ports": "22,80,443,3389,8080", "protocol": "TCP", "threads": "25", "timeout": "1"}
        }
        presets_row = ttk.Frame(frm)
        presets_row.pack(fill="x", pady=2)
        ttk.Label(presets_row, text="Presets:").pack(side="left")
        self.preset_var = tk.StringVar()
        # load persisted presets if available
        try:
            if os.path.exists(self.presets_file):
                with open(self.presets_file, "r", encoding="utf-8") as pf:
                    user_presets = json.load(pf)
            else:
                user_presets = {}
        except Exception:
            logging.exception("Failed to load presets.json")
            user_presets = {}
        self.presets = dict(self.default_presets)
        self.presets.update(user_presets)
        self.preset_menu = ttk.Combobox(presets_row, textvariable=self.preset_var, values=list(self.presets.keys()), state="readonly", width=32)
        self.preset_menu.pack(side="left", padx=6)
        self.preset_menu.bind("<<ComboboxSelected>>", lambda e: self._apply_preset(self.preset_var.get()))
        self.save_preset_btn = ttk.Button(presets_row, text="Save Preset", command=self._save_current_preset)
        self.save_preset_btn.pack(side="left", padx=4)
        self.delete_preset_btn = ttk.Button(presets_row, text="Delete Preset", command=self._delete_preset)
        self.delete_preset_btn.pack(side="left", padx=4)

        # Row: Targets
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Target IP / Range / CIDR:").pack(side="left")
        self.target_entry = ttk.Entry(row, width=38)
        self.target_entry.pack(side="left", padx=6)
        self.target_entry.insert(0, "127.0.0.1")

        # Row: Ports
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="Ports (e.g. 22,80,8000-8100):").pack(side="left")
        self.ports_entry = ttk.Entry(row, width=30)
        self.ports_entry.pack(side="left", padx=6)
        self.ports_entry.insert(0, "8000")

        # Row: timeout/protocol/threads/banner
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Timeout (s):").pack(side="left")
        self.timeout_spin = tk.Spinbox(row, from_=0.2, to=30.0, increment=0.1, width=6)
        self.timeout_spin.pack(side="left", padx=4)
        self.timeout_spin.delete(0, "end"); self.timeout_spin.insert(0, "1")

        ttk.Label(row, text="Protocol:").pack(side="left", padx=(8,0))
        self.protocol_var = tk.StringVar(value="TCP")
        self.protocol_menu = ttk.OptionMenu(row, self.protocol_var, "TCP", "TCP", "UDP")
        self.protocol_menu.pack(side="left", padx=4)

        ttk.Label(row, text="Threads:").pack(side="left", padx=(8,0))
        self.threads_spin = tk.Spinbox(row, from_=1, to=500, width=6)
        self.threads_spin.pack(side="left", padx=4)
        self.threads_spin.delete(0, "end"); self.threads_spin.insert(0, "25")

        self.banner_var = tk.BooleanVar(value=False)
        self.banner_check = ttk.Checkbutton(row, text="Grab banner (TCP)", variable=self.banner_var)
        self.banner_check.pack(side="left", padx=(8,0))

        # Row: Buttons
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=6)
        self.start_btn = ttk.Button(row, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(row, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        self.save_btn = ttk.Button(row, text="Save Results", command=self.save_results, state="disabled")
        self.save_btn.pack(side="left", padx=4)
        self.clear_btn = ttk.Button(row, text="Clear Results", command=self.clear_results)
        self.clear_btn.pack(side="left", padx=4)

        # Row: Status
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=2)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(row, textvariable=self.status_var).pack(side="left")

        # Row: Treeview
        row = ttk.Frame(frm)
        row.pack(fill="both", expand=True, pady=6)
        cols = ("ip", "port", "protocol", "status", "banner", "duration")
        self.tree = ttk.Treeview(row, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=120, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        self.vscroll = ttk.Scrollbar(row, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.vscroll.set)
        self.vscroll.pack(side="right", fill="y")

    # ---------- Preset helpers ----------
    def _apply_preset(self, name):
        p = self.presets.get(name)
        if not p:
            return
        self.target_entry.delete(0, "end"); self.target_entry.insert(0, p.get("target", ""))
        self.ports_entry.delete(0, "end"); self.ports_entry.insert(0, p.get("ports", ""))
        prot = p.get("protocol", "TCP").upper()
        if prot in ("TCP", "UDP"):
            self.protocol_var.set(prot)
        self.threads_spin.delete(0, "end"); self.threads_spin.insert(0, str(p.get("threads", "25")))
        self.timeout_spin.delete(0, "end"); self.timeout_spin.insert(0, str(p.get("timeout", "1")))

    def _save_current_preset(self):
        name = simpledialog.askstring("Preset name", "Enter a name for this preset:")
        if not name:
            return
        entry = {
            "target": self.target_entry.get().strip(),
            "ports": self.ports_entry.get().strip(),
            "protocol": self.protocol_var.get(),
            "threads": self.threads_spin.get(),
            "timeout": self.timeout_spin.get()
        }
        self.presets[name] = entry
        try:
            user_presets = {k: v for k, v in self.presets.items() if k not in self.default_presets}
            with open(self.presets_file, "w", encoding="utf-8") as fh:
                json.dump(user_presets, fh, indent=2)
            self.preset_menu['values'] = list(self.presets.keys())
            self.preset_var.set(name)
            messagebox.showinfo("Preset saved", f"Saved preset '{name}'")
        except Exception as e:
            logging.exception("Failed to save preset")
            messagebox.showerror("Save failed", f"Could not save preset: {e}")

    def _delete_preset(self):
        name = self.preset_var.get()
        if not name:
            messagebox.showinfo("No preset", "Select a preset to delete.")
            return
        if name in self.default_presets:
            messagebox.showwarning("Protected", "Cannot delete built-in presets.")
            return
        confirm = messagebox.askyesno("Delete preset", f"Delete preset '{name}'?")
        if not confirm:
            return
        try:
            self.presets.pop(name, None)
            user_presets = {k: v for k, v in self.presets.items() if k not in self.default_presets}
            with open(self.presets_file, "w", encoding="utf-8") as fh:
                json.dump(user_presets, fh, indent=2)
            self.preset_menu['values'] = list(self.presets.keys())
            self.preset_var.set("")
            messagebox.showinfo("Deleted", f"Preset '{name}' deleted.")
        except Exception as e:
            logging.exception("Failed to delete preset")
            messagebox.showerror("Delete failed", f"Could not delete preset: {e}")

    # ---------- Scanning control ----------
    def start_scan(self):
        if self.executor:
            messagebox.showinfo("Scan running", "A scan is already running.")
            return
        target_text = self.target_entry.get().strip()
        port_text = self.ports_entry.get().strip()
        if not target_text or not port_text:
            messagebox.showwarning("Input required", "Please enter target(s) and port(s).")
            return
        targets = expand_targets(target_text)
        ports = expand_ports(port_text)
        if not targets or not ports:
            messagebox.showwarning("Parse error", "Couldn't parse targets or ports. Check format.")
            return
        try:
            timeout = float(self.timeout_spin.get())
        except Exception:
            timeout = 1.0
        try:
            threads = int(self.threads_spin.get())
        except Exception:
            threads = 25
        protocol = self.protocol_var.get().upper()
        do_banner = bool(self.banner_var.get()) and protocol == "TCP"

        # reset control state
        self.stop_event.clear()
        self.results.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.save_btn.config(state="disabled")
        self.status_var.set(f"Scanning {len(targets)} targets × {len(ports)} ports...")
        logging.info("Scan started: targets=%d ports=%d protocol=%s threads=%d", len(targets), len(ports), protocol, threads)

        total_tasks = len(targets) * len(ports)
        self._progress = {"done": 0, "total": total_tasks, "start": time.time()}

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads))
        self.active_futures = []

        for ip in targets:
            for p in ports:
                if self.stop_event.is_set():
                    break
                if protocol == "TCP":
                    fut = self.executor.submit(self._worker_tcp, ip, p, timeout, do_banner)
                else:
                    fut = self.executor.submit(self._worker_udp, ip, p, timeout)
                fut.add_done_callback(self._future_done)
                self.active_futures.append(fut)

        threading.Thread(target=self._monitor_completion, daemon=True).start()

    def _worker_tcp(self, ip, port, timeout, do_banner):
        if self.stop_event.is_set():
            return None
        # try to resolve hostname to IP for sockets (but keep ip label as given)
        try:
            # if ip is hostname, let socket.connect resolve it
            return tcp_scan(ip, port, timeout, do_banner)
        except Exception:
            logging.exception("Exception in _worker_tcp")
            return {"ip": ip, "port": port, "protocol": "TCP", "status": "Error", "banner": "", "duration": 0, "ts": now_ts()}

    def _worker_udp(self, ip, port, timeout):
        if self.stop_event.is_set():
            return None
        try:
            return udp_scan(ip, port, timeout)
        except Exception:
            logging.exception("Exception in _worker_udp")
            return {"ip": ip, "port": port, "protocol": "UDP", "status": "Error", "banner": "", "duration": 0, "ts": now_ts()}

    def _future_done(self, fut):
        try:
            res = fut.result()
            if res is None:
                return
            self.result_q.put({"_type": "result", "data": res})
        except Exception as e:
            logging.exception("Future callback error")
            self.result_q.put({"_type": "status", "msg": f"Worker error: {e}"})
        finally:
            self._progress["done"] += 1
            done = self._progress["done"]
            total = self._progress["total"]
            elapsed = time.time() - self._progress["start"]
            self.result_q.put({"_type": "status", "msg": f"Progress: {done}/{total} — {elapsed:.1f}s"})

    def _monitor_completion(self):
        if not self.active_futures:
            self._cleanup_after_scan()
            return
        try:
            concurrent.futures.wait(self.active_futures, return_when=concurrent.futures.ALL_COMPLETED)
        except Exception:
            logging.exception("Monitor completion wait failed")
        self._cleanup_after_scan()

    def _cleanup_after_scan(self):
        if self.executor:
            try:
                self.executor.shutdown(wait=False)
            except Exception:
                pass
            self.executor = None
        self.stop_event.clear()
        self.active_futures = []
        self.result_q.put({"_type": "status", "msg": "Scan complete."})
        if self.results:
            self.result_q.put({"_type": "status", "msg": f"Scan complete. {len(self.results)} results."})
            self.root.after(200, lambda: self.save_btn.config(state="normal"))
        self.root.after(200, lambda: self.start_btn.config(state="normal"))
        self.root.after(200, lambda: self.stop_btn.config(state="disabled"))

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping scan...")
        for f in list(self.active_futures):
            try:
                f.cancel()
            except Exception:
                pass
        if self.executor:
            try:
                self.executor.shutdown(wait=False)
            except Exception:
                pass
            self.executor = None
        self.result_q.put({"_type": "status", "msg": "Scan stopped by user."})
        self.root.after(200, lambda: self.start_btn.config(state="normal"))
        self.root.after(200, lambda: self.stop_btn.config(state="disabled"))
        if self.results:
            self.root.after(200, lambda: self.save_btn.config(state="normal"))

    def _poll_queue(self):
        try:
            while True:
                item = self.result_q.get_nowait()
                if item.get("_type") == "result":
                    r = item["data"]
                    self._append_result_to_ui(r)
                    self.results.append(r)
                    logging.info("Result: %s:%s %s", r.get("ip"), r.get("port"), r.get("status"))
                elif item.get("_type") == "status":
                    self.status_var.set(item["msg"])
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _append_result_to_ui(self, r):
        banner_text = (r.get("banner") or "")[:140]
        try:
            self.tree.insert("", "end", values=(r["ip"], r["port"], r["protocol"], r["status"], banner_text, r.get("duration")))
        except Exception:
            logging.exception("Failed to insert tree row")

    def clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.results.clear()
        self.save_btn.config(state="disabled")
        self.status_var.set("Cleared results.")

    def save_results(self):
        if not self.results:
            messagebox.showinfo("No results", "No results to save.")
            return
        ftypes = [("CSV file", "*.csv"), ("JSON file", "*.json"), ("All files", "*.*")]
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=ftypes, title="Save results")
        if not file:
            return
        try:
            if file.lower().endswith(".csv"):
                with open(file, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=["ip", "port", "protocol", "status", "banner", "duration", "ts"])
                    writer.writeheader()
                    for r in self.results:
                        writer.writerow({k: r.get(k, "") for k in writer.fieldnames})
            else:
                with open(file, "w", encoding="utf-8") as fh:
                    json.dump(self.results, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"Saved {len(self.results)} results to {file}")
        except Exception as e:
            logging.exception("Save results failed")
            messagebox.showerror("Save failed", f"Could not save file: {e}")

# ---------- Run ----------
def main():
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Unhandled exception in main: %s", e)
        raise
