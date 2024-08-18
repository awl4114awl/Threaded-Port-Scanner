import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import logging
import csv
from datetime import datetime

# Setup logging
logging.basicConfig(filename='port_scanner.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for scan control and history
stop_flag = False
scan_history = []

# Function to validate IP address
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid IP address.")
        return False

# Function to scan a single port and update the result in the Treeview widget
def scan_port(ip, port, result_tree):
    global stop_flag
    if stop_flag:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        status = "Open" if result == 0 else "Closed"
        result_tree.insert("", "end", values=(port, status))
        logging.info(f"Scanned {ip} on port {port}: {status}")
        scan_history.append((ip, port, status, datetime.now()))
        sock.close()
    except socket.timeout:
        messagebox.showerror("Timeout Error", f"Connection timed out for port {port}.")
    except socket.error as e:
        messagebox.showerror("Network Error", f"Network error occurred: {e}")

# Function to scan multiple ports using threading and update the result in the Treeview widget
def scan_ports(ip, ports, result_tree, num_threads):
    threads = []
    for i in range(num_threads):
        port_slice = ports[i::num_threads]  # Distribute ports across threads
        for port in port_slice:
            t = threading.Thread(target=scan_port, args=(ip, port, result_tree))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

# Function to start the port scan in a new thread
def start_scan():
    global stop_flag, timeout
    stop_flag = False
    ip = entry_ip.get()
    ports_str = entry_ports.get()
    protocol = protocol_var.get()

    if not validate_ip(ip):
        return

    if not ports_str:
        messagebox.showerror("Input Error", "Please enter ports to scan.")
        return

    try:
        ports = list(map(int, ports_str.split(',')))
        timeout = float(entry_timeout.get()) if entry_timeout.get() else 1.0
        num_threads = int(entry_threads.get()) if entry_threads.get() else 10

        # Clear the result Treeview and update status label
        for item in result_tree.get_children():
            result_tree.delete(item)
        label_status.config(text="Status: Scanning...")

        def scan_and_update():
            scan_ports(ip, ports, result_tree, num_threads)
            if not stop_flag:
                label_status.config(text="Status: Scan Complete")

        # Log the start of the scan
        logging.info(f"Starting scan on {ip} for ports {ports_str} with {num_threads} threads.")

        # Start the scan in a new thread
        scan_thread = threading.Thread(target=scan_and_update)
        scan_thread.start()

    except ValueError:
        messagebox.showerror("Input Error", "Please enter valid port numbers separated by commas.")

# Function to stop the scan
def stop_scan():
    global stop_flag
    stop_flag = True
    label_status.config(text="Status: Scan Stopped")
    logging.info("Scan stopped by user.")

# Function to save the results to a file
def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")])
    if file_path:
        if file_path.endswith('.csv'):
            save_results_as_csv(file_path)
        else:
            save_results_as_txt(file_path)

def save_results_as_txt(file_path):
    with open(file_path, "w") as file:
        for item in result_tree.get_children():
            port, status = result_tree.item(item, "values")
            file.write(f"Port {port}: {status}\n")
    messagebox.showinfo("Saved", "Results have been saved successfully!")

def save_results_as_csv(file_path):
    with open(file_path, "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Port", "Status"])
        for item in result_tree.get_children():
            writer.writerow(result_tree.item(item, "values"))
    messagebox.showinfo("Saved", "Results have been saved successfully!")

# Function to show an About dialog
def show_about():
    messagebox.showinfo("About", "Threaded Port Scanner\nVersion 1.0\nDeveloped by Jordan Calvert")

# Function to compare historical scan results
def compare_scans():
    # In this example, we're just showing a message box, but you could implement a full comparison tool.
    messagebox.showinfo("Comparison", "Feature to compare historical scans coming soon!")

# Create the main window
root = tk.Tk()
root.title("Threaded Port Scanner")
root.geometry("600x550")
root.resizable(False, False)  # Disable window resizing

# Apply styles for dark mode with Consolas font and visible entry text
style = ttk.Style(root)
style.configure("TFrame", background="#555")
style.configure("TLabel", background="#555", foreground="#DDD", font=("Consolas", 10))
style.configure("TButton", background="#555", foreground="#333", font=("Consolas", 10))  # Dark grey text for Start Scan button
style.configure("TEntry", foreground="#FFF", fieldbackground="#333", font=("Consolas", 10))  # White text with dark grey background for Entry widgets

# Create a frame for the content with padding adjusted for dark mode
frame = ttk.Frame(root, padding="10", style="TFrame")
frame.pack(fill="both", expand=True)

# Create and place widgets
label_ip = ttk.Label(frame, text="Target IP:", style="TLabel")
label_ip.grid(row=0, column=0, pady=5, padx=5, sticky="w")

# Adjusting the Entry widget manually for dark mode
entry_ip = tk.Entry(frame, font=("Consolas", 10), bg="#333", fg="#FFF", insertbackground="#FFF")
entry_ip.grid(row=0, column=1, pady=5, padx=5, sticky="e")

label_ports = ttk.Label(frame, text="Ports to scan (comma-separated):", style="TLabel")
label_ports.grid(row=1, column=0, pady=5, padx=5, sticky="w")

# Adjusting the Entry widget manually for dark mode
entry_ports = tk.Entry(frame, font=("Consolas", 10), bg="#333", fg="#FFF", insertbackground="#FFF")
entry_ports.grid(row=1, column=1, pady=5, padx=5, sticky="e")

# Add timeout entry
label_timeout = ttk.Label(frame, text="Timeout (seconds):", style="TLabel")
label_timeout.grid(row=2, column=0, pady=5, padx=5, sticky="w")

entry_timeout = tk.Entry(frame, font=("Consolas", 10), bg="#333", fg="#FFF", insertbackground="#FFF")
entry_timeout.grid(row=2, column=1, pady=5, padx=5, sticky="e")

# Add protocol option (TCP/UDP)
label_protocol = ttk.Label(frame, text="Protocol:", style="TLabel")
label_protocol.grid(row=3, column=0, pady=5, padx=5, sticky="w")

protocol_var = tk.StringVar(value="TCP")
option_protocol = ttk.OptionMenu(frame, protocol_var, "TCP", "TCP", "UDP")
option_protocol.grid(row=3, column=1, pady=5, padx=5, sticky="e")

# Add thread entry for multithreading
label_threads = ttk.Label(frame, text="Number of Threads:", style="TLabel")
label_threads.grid(row=4, column=0, pady=5, padx=5, sticky="w")

entry_threads = tk.Entry(frame, font=("Consolas", 10), bg="#333", fg="#FFF", insertbackground="#FFF")
entry_threads.grid(row=4, column=1, pady=5, padx=5, sticky="e")

button_scan = ttk.Button(frame, text="Start Scan", command=start_scan, style="TButton")
button_scan.grid(row=5, column=1, pady=10, padx=5, sticky="e")

button_stop = ttk.Button(frame, text="Stop Scan", command=stop_scan, style="TButton")
button_stop.grid(row=5, column=0, pady=10, padx=5, sticky="w")

label_status = ttk.Label(frame, text="Status: Ready", style="TLabel")
label_status.grid(row=6, column=0, columnspan=2, pady=5, padx=5, sticky="w")

# Create a Treeview widget to display the results
result_tree = ttk.Treeview(frame, columns=("Port", "Status"), show="headings")
result_tree.heading("Port", text="Port")
result_tree.heading("Status", text="Status")
result_tree.column("Port", anchor="center")
result_tree.column("Status", anchor="center")
result_tree.grid(row=7, column=0, columnspan=2, pady=5, padx=5, sticky="w")

# Add the Save Results button to the UI
button_save = ttk.Button(frame, text="Save Results", command=save_results, style="TButton")
button_save.grid(row=8, column=1, pady=10, padx=5, sticky="e")

# Menu for Help and About
menu_bar = tk.Menu(root)
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menu_bar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menu_bar)

# Add comparison of historical scan results
button_compare = ttk.Button(frame, text="Compare Scans", command=compare_scans, style="TButton")
button_compare.grid(row=8, column=0, pady=10, padx=5, sticky="w")

# Tooltips for user guidance
def create_tooltip(widget, text):
    tooltip = tk.Toplevel(widget)
    tooltip.wm_overrideredirect(True)
    tooltip_label = ttk.Label(tooltip, text=text, background="#333", foreground="#FFF", font=("Consolas", 8), padding=5)
    tooltip_label.pack()
    tooltip.withdraw()

    def show_tooltip(event):
        tooltip.geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
        tooltip.deiconify()

    def hide_tooltip(event):
        tooltip.withdraw()

    widget.bind("<Enter>", show_tooltip)
    widget.bind("<Leave>", hide_tooltip)

create_tooltip(entry_ip, "Enter the target IP address.")
create_tooltip(entry_ports, "Enter ports to scan, separated by commas (e.g., 80,443,8080).")
create_tooltip(entry_timeout, "Specify the timeout in seconds for each port scan.")
create_tooltip(entry_threads, "Specify the number of threads to use for faster scanning.")
create_tooltip(option_protocol, "Select the protocol to use for scanning (TCP or UDP).")

# Run the main loop
root.mainloop()
