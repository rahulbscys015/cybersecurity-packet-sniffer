import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import threading
from scapy.all import sniff, DNS, DNSQR, IP
from datetime import datetime
import json
import ipaddress
import os
from collections import Counter
import matplotlib.pyplot as plt
import csv

# GeoIP setup
try:
    import geoip2.database
    GEOIP_DB = "GeoLite2-City.mmdb"
    geoip_reader = geoip2.database.Reader(GEOIP_DB) if os.path.exists(GEOIP_DB) else None
except ImportError:
    geoip_reader = None

# Load blacklists
malicious_domains = ["malicious.com", "phishing.net", "badsite.org"]
malicious_ips = ["45.33.32.156", "123.45.67.89", "198.51.100.23"]

# GeoIP function
def get_geoip(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Local IP (not public)"
        if geoip_reader:
            res = geoip_reader.city(ip)
            city = res.city.name or "Unknown City"
            country = res.country.name or "Unknown Country"
            return f"{city}, {country}"
        return "GeoIP DB not loaded"
    except:
        return "GeoIP lookup failed"

# Packet callback
sniffing = False

def packet_callback(packet, log_box):
    log = {
        "timestamp": str(datetime.now()),
        "summary": packet.summary(),
    }
    is_critical = False

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode()
        log["type"] = "DNS"
        log["query"] = domain
        if any(bad in domain for bad in malicious_domains):
            log["alert"] = f"Suspicious domain detected: {domain}"
            is_critical = True

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        log["src_ip"] = src_ip
        log["dst_ip"] = dst_ip
        log["src_location"] = get_geoip(src_ip)
        log["dst_location"] = get_geoip(dst_ip)
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            log["alert"] = f"Malicious IP detected: {src_ip if src_ip in malicious_ips else dst_ip}"
            is_critical = True

    line = json.dumps(log, indent=2)
    log_box.insert(tk.END, line + "\n")
    log_box.yview(tk.END)

    with open("network_log.json", "a") as f:
        f.write(json.dumps(log) + "\n")
    if is_critical:
        with open("alerts.json", "a") as f:
            f.write(json.dumps(log) + "\n")

def start_sniffing(filter_value, log_box):
    global sniffing
    sniffing = True
    sniff(filter=filter_value, prn=lambda pkt: packet_callback(pkt, log_box), store=False, stop_filter=lambda x: not sniffing)

def stop_sniffing():
    global sniffing
    sniffing = False
    messagebox.showinfo("Stopped", "Packet sniffing stopped.")

# Summary Pie Chart
def show_traffic_summary():
    if not os.path.exists("network_log.json"):
        messagebox.showinfo("Summary", "No logs available.")
        return
    try:
        with open("network_log.json", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
        type_counts = Counter(log.get("type", "Other") for log in logs)
        labels = list(type_counts.keys())
        sizes = list(type_counts.values())
        if not sizes:
            messagebox.showinfo("Summary", "No packet types found in logs.")
            return
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("Traffic Type Summary")
        plt.axis("equal")
        plt.show()
    except Exception as e:
        messagebox.showerror("Error", f"Could not generate summary.\n{str(e)}")

# Export Logs to CSV
def export_logs_to_csv():
    try:
        with open("network_log_fixed.json", "r") as f:
            logs = json.load(f)
        with open("exported_logs.csv", "w", newline="") as csvfile:
            fieldnames = list(logs[0].keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for log in logs:
                writer.writerow(log)
        messagebox.showinfo("Success", "Logs exported to exported_logs.csv")
    except Exception as e:
        messagebox.showerror("Error", f"Export failed:\n{str(e)}")

# Editable Blacklist

def edit_blacklists():
    editor = tk.Toplevel()
    editor.title("Edit Blacklists")
    editor.geometry("600x300")

    domain_label = ttk.Label(editor, text="Malicious Domains (comma-separated):")
    domain_label.pack(pady=5)
    domain_entry = tk.Text(editor, height=3)
    domain_entry.insert(tk.END, ", ".join(malicious_domains))
    domain_entry.pack(fill=tk.X, padx=10)

    ip_label = ttk.Label(editor, text="Malicious IPs (comma-separated):")
    ip_label.pack(pady=5)
    ip_entry = tk.Text(editor, height=3)
    ip_entry.insert(tk.END, ", ".join(malicious_ips))
    ip_entry.pack(fill=tk.X, padx=10)

    def save_lists():
        global malicious_domains, malicious_ips
        malicious_domains = [d.strip() for d in domain_entry.get("1.0", tk.END).split(",") if d.strip()]
        malicious_ips = [i.strip() for i in ip_entry.get("1.0", tk.END).split(",") if i.strip()]
        messagebox.showinfo("Saved", "Blacklists updated.")
        editor.destroy()

    ttk.Button(editor, text="Save", command=save_lists).pack(pady=10)

# Filter by Date
def filter_logs_by_date():
    date = simpledialog.askstring("Filter", "Enter date (YYYY-MM-DD):")
    try:
        if not date:
            return
        with open("network_log.json", "r") as f:
            logs = [json.loads(line) for line in f.readlines() if line.strip()]
        matched = [log for log in logs if log['timestamp'].startswith(date)]
        if not matched:
            messagebox.showinfo("No Matches", "No logs found for that date.")
            return
        filename = f"logs_{date}.json"
        with open(filename, "w") as f:
            json.dump(matched, f, indent=2)
        messagebox.showinfo("Success", f"Filtered logs saved as {filename}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
def launch_gui():
    password = simpledialog.askstring("Admin Login", "Enter Admin Password:", show="*")
    if password != "bscys015":
        messagebox.showerror("Access Denied", "Incorrect admin password.")
        return

    root = tk.Tk()
    root.title("Cybersecurity Packet Sniffer - GUI Edition")
    root.geometry("820x650")

    ttk.Label(root, text="Packet Filter:").pack(pady=5)
    filter_var = tk.StringVar(value="udp port 53 or tcp port 80 or tcp port 443")
    filter_entry = ttk.Combobox(root, textvariable=filter_var, values=[
        "udp port 53", "tcp port 80", "tcp port 443", "udp port 53 or tcp port 80 or tcp port 443"
    ], width=60)
    filter_entry.pack(pady=5)

    log_box = scrolledtext.ScrolledText(root, height=25, width=95)
    log_box.pack(padx=10, pady=10)

    def start_threaded():
        threading.Thread(target=start_sniffing, args=(filter_var.get(), log_box), daemon=True).start()

    ttk.Button(root, text="Start Sniffing", command=start_threaded).pack(pady=5)
    ttk.Button(root, text="Stop Sniffing", command=stop_sniffing).pack(pady=5)
    ttk.Button(root, text="View Alerts", command=lambda: messagebox.showinfo("Alerts", open("alerts.json").read() if os.path.exists("alerts.json") else "No alerts found.")).pack(pady=5)
    ttk.Button(root, text="Show Traffic Summary", command=show_traffic_summary).pack(pady=5)
    ttk.Button(root, text="Export Logs to CSV", command=export_logs_to_csv).pack(pady=5)
    ttk.Button(root, text="Edit Blacklists", command=edit_blacklists).pack(pady=5)
    ttk.Button(root, text="Filter Logs by Date", command=filter_logs_by_date).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
# ... (previous imports remain unchanged)

# GUI Setup
def launch_gui():
    password = simpledialog.askstring("Admin Login", "Enter Admin Password:", show="*")
    if password != "bscys015":
        messagebox.showerror("Access Denied", "Incorrect admin password.")
        return

    root = tk.Tk()
    root.title("Cybersecurity Packet Sniffer - GUI Edition | Rahul Kumar - BSCSY015")
    root.geometry("820x680")

    ttk.Label(root, text="Packet Filter:").pack(pady=5)
    filter_var = tk.StringVar(value="udp port 53 or tcp port 80 or tcp port 443")
    filter_entry = ttk.Combobox(root, textvariable=filter_var, values=[
        "udp port 53", "tcp port 80", "tcp port 443", "udp port 53 or tcp port 80 or tcp port 443"
    ], width=60)
    filter_entry.pack(pady=5)

    log_box = scrolledtext.ScrolledText(root, height=25, width=95)
    log_box.pack(padx=10, pady=10)

    def start_threaded():
        threading.Thread(target=start_sniffing, args=(filter_var.get(), log_box), daemon=True).start()

    # All buttons
    ttk.Button(root, text="Start Sniffing", command=start_threaded).pack(pady=3)
    ttk.Button(root, text="Stop Sniffing", command=stop_sniffing).pack(pady=3)
    ttk.Button(root, text="View Alerts", command=lambda: messagebox.showinfo("Alerts", open("alerts.json").read() if os.path.exists("alerts.json") else "No alerts found.")).pack(pady=3)
    ttk.Button(root, text="Show Traffic Summary", command=show_traffic_summary).pack(pady=3)
    ttk.Button(root, text="Export Logs to CSV", command=export_logs_to_csv).pack(pady=3)
    ttk.Button(root, text="Edit Blacklists", command=edit_blacklists).pack(pady=3)
    ttk.Button(root, text="Filter Logs by Date", command=filter_logs_by_date).pack(pady=3)

    # Footer with your name & roll number
    footer = tk.Label(root, text="Developed by Rahul Kumar - BSCSY015", bd=1, relief=tk.SUNKEN, anchor=tk.CENTER)
    footer.pack(side=tk.BOTTOM, fill=tk.X)

    root.mainloop()

# Main
if __name__ == "__main__":
    launch_gui()
