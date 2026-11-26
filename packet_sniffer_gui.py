#!/usr/bin/env python3
"""Packet Sniffer and Analyzer with GUI.

A threaded Tkinter application for live network packet capture and analysis
using Scapy. It provides protocol/BPF filtering, blacklist alerting, optional
GeoIP lookup, JSONL logging, CSV/JSON export, and graphical traffic summaries.

Author: Rahul Kumar (BSCSY015)
License: MIT
"""

from __future__ import annotations

import ctypes
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import sys
import threading
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP, sniff
except ImportError as exc:  # pragma: no cover - dependency guard
    print(
        "Scapy is required. Install dependencies with: pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
BLACKLIST_FILE = CONFIG_DIR / "blacklists.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
NETWORK_LOG = LOG_DIR / "network_log.jsonl"
ALERT_LOG = LOG_DIR / "alerts.jsonl"

DEFAULT_BLACKLIST: dict[str, list[str]] = {
    "domains": ["malicious.com", "phishing.net", "badsite.org"],
    "ip_addresses": ["45.33.32.156", "123.45.67.89", "198.51.100.23"],
}

PROTOCOL_FILTERS = {
    "ALL": "",
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "ARP": "arp",
    "DNS": "port 53",
}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ")


@dataclass
class PacketRecord:
    """Normalised representation of one captured packet."""

    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    summary: str
    info: str = ""
    src_location: str = "Unknown"
    dst_location: str = "Unknown"
    alert: Optional[str] = None


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    """Read a JSON object from *path*, returning *fallback* on any problem."""
    if not path.is_file():
        return dict(fallback)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            merged = dict(fallback)
            merged.update(data)
            return merged
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[config] Could not read {path.name}: {exc}", file=sys.stderr)
    return dict(fallback)


def _split_entries(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,\n]", text) if part.strip()]


class Blacklist:
    """Editable domain/IP blocklist persisted to config/blacklists.json."""

    def __init__(self, path: Path = BLACKLIST_FILE) -> None:
        self.path = path
        self.domains: list[str] = []
        self.ips: list[str] = []
        self._domains: set[str] = set()
        self._ips: set[str] = set()
        self.reload()

    def reload(self) -> None:
        data = _load_json(self.path, DEFAULT_BLACKLIST)
        self.domains = sorted({d.lower().rstrip(".") for d in data.get("domains", [])})
        clean_ips: list[str] = []
        for value in data.get("ip_addresses", []):
            try:
                clean_ips.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        self.ips = sorted(set(clean_ips))
        self._domains = set(self.domains)
        self._ips = set(self.ips)

    def matches_domain(self, domain: str) -> bool:
        value = domain.lower().rstrip(".")
        return any(indicator and indicator in value for indicator in self._domains)

    def matches_ip(self, address: str) -> bool:
        return address in self._ips

    def update(self, domains: list[str], ips: list[str]) -> None:
        self.domains = sorted({d.lower().rstrip(".") for d in domains if d.strip()})
        clean_ips: list[str] = []
        for value in ips:
            try:
                clean_ips.append(str(ipaddress.ip_address(value)))
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: {value}") from exc
        self.ips = sorted(set(clean_ips))
        self._domains = set(self.domains)
        self._ips = set(self.ips)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {"domains": self.domains, "ip_addresses": self.ips}, indent=2
            )
            + "\n",
            encoding="utf-8",
        )


def admin_password_hash() -> str:
    """Return the SHA-256 hash of the accepted admin password.

    The password can be supplied through the PACKET_SNIFFER_ADMIN_PASSWORD
    environment variable or stored as a hash in config/settings.json. If
    neither is present a one-time random password is generated and printed.
    """
    env_password = os.environ.get("PACKET_SNIFFER_ADMIN_PASSWORD")
    if env_password:
        return hashlib.sha256(env_password.encode("utf-8")).hexdigest()

    settings = _load_json(SETTINGS_FILE, {})
    stored_hash = settings.get("admin_password_sha256")
    if isinstance(stored_hash, str) and re.fullmatch(r"[0-9a-f]{64}", stored_hash):
        return stored_hash

    temporary = secrets.token_urlsafe(12)
    print(
        f"[admin] No password configured. Temporary password: {temporary}",
        file=sys.stderr,
    )
    return hashlib.sha256(temporary.encode("utf-8")).hexdigest()


def is_administrator() -> bool:
    """Best-effort administrator/root detection."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ---------------------------------------------------------------------------
# GeoIP (optional)
# ---------------------------------------------------------------------------


class GeoIPLookup:
    """Thin wrapper around geoip2 with a safe, dependency-free fallback."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.reader: Any = None
        self.error: Optional[str] = None
        settings = _load_json(SETTINGS_FILE, {})
        path = Path(db_path or settings.get("geoip_db_path") or "GeoLite2-City.mmdb")
        if not path.is_absolute():
            path = BASE_DIR / path
        if not path.is_file():
            self.error = "GeoLite2-City.mmdb not found (optional)"
            return
        try:
            import geoip2.database  # optional dependency

            self.reader = geoip2.database.Reader(str(path))
        except Exception as exc:  # pragma: no cover - optional dependency
            self.error = str(exc)

    @property
    def status(self) -> str:
        return "GeoIP active" if self.reader else self.error or "GeoIP unavailable"

    def locate(self, address: str) -> str:
        try:
            if ipaddress.ip_address(address).is_private:
                return "Private / local address"
        except ValueError:
            return "Invalid address"
        if not self.reader:
            return "GeoIP database unavailable"
        try:
            result = self.reader.city(address)
            city = result.city.name or "Unknown city"
            country = result.country.name or "Unknown country"
            return f"{city}, {country}"
        except Exception:
            return "Lookup failed"

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None


# ---------------------------------------------------------------------------
# Packet parsing and persistence
# ---------------------------------------------------------------------------


def _decode_qname(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def parse_packet(
    packet: Any, geoip: GeoIPLookup, blacklist: Blacklist
) -> PacketRecord:
    """Convert a Scapy packet into a :class:`PacketRecord`."""
    timestamp = datetime.now().astimezone().isoformat(timespec="microseconds")
    protocol = "OTHER"
    src_ip = dst_ip = "-"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info = ""
    alert: Optional[str] = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(ARP):
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        protocol = "DNS"
        domain = _decode_qname(packet[DNSQR].qname)
        info = f"DNS query: {domain}"
        if blacklist.matches_domain(domain):
            alert = f"Suspicious domain: {domain}"

    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if any(payload.startswith(method) for method in HTTP_METHODS):
            first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            info = f"HTTP: {first_line[:160]}"
        elif not info:
            info = f"Payload: {len(payload)} bytes"

    for address in (src_ip, dst_ip):
        if blacklist.matches_ip(address):
            alert = alert or f"Blocklisted IP: {address}"

    return PacketRecord(
        timestamp=timestamp,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=len(packet),
        summary=packet.summary()[:200],
        info=info,
        src_location=geoip.locate(src_ip) if src_ip not in ("-", "") else "Unknown",
        dst_location=geoip.locate(dst_ip) if dst_ip not in ("-", "") else "Unknown",
        alert=alert,
    )


def build_bpf_filter(custom: str, protocol: str) -> str:
    """Combine a user filter and a protocol preset into one BPF expression."""
    custom = custom.strip()
    preset = PROTOCOL_FILTERS.get(protocol, "")
    if custom and preset:
        return f"({custom}) and ({preset})"
    return custom or preset


class LogStore:
    """Thread-safe JSONL log store with export helpers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def append(self, record: PacketRecord) -> None:
        line = json.dumps(asdict(record), default=str) + "\n"
        with self._lock:
            with NETWORK_LOG.open("a", encoding="utf-8") as handle:
                handle.write(line)
            if record.alert:
                with ALERT_LOG.open("a", encoding="utf-8") as handle:
                    handle.write(line)

    def read(self, path: Path = NETWORK_LOG) -> list[dict[str, Any]]:
        with self._lock:
            if not path.is_file():
                return []
            records: list[dict[str, Any]] = []
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            records.append(entry)
                    except json.JSONDecodeError:
                        continue
            return records

    def alerts(self) -> list[dict[str, Any]]:
        return self.read(ALERT_LOG)

    def clear(self) -> None:
        with self._lock:
            for path in (NETWORK_LOG, ALERT_LOG):
                path.write_text("", encoding="utf-8")

    @staticmethod
    def export_csv(records: list[dict[str, Any]], destination: Path) -> None:
        if not records:
            raise ValueError("There are no records to export.")
        fields = sorted({key for record in records for key in record})
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=fields, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(records)

    @staticmethod
    def export_json(records: list[dict[str, Any]], destination: Path) -> None:
        with destination.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, default=str)
            handle.write("\n")


class CaptureController:
    """Owns the Scapy capture thread and reports records through a callback."""

    def __init__(
        self,
        emit: Callable[[str, Any], None],
        geoip: GeoIPLookup,
        blacklist: Blacklist,
    ) -> None:
        self.emit = emit
        self.geoip = geoip
        self.blacklist = blacklist
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.captured = 0
        self.alerts = 0
        self._count_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def start(self, bpf_filter: str, packet_limit: int) -> None:
        if self.running:
            raise RuntimeError("Capture is already running.")
        self.stop_event.clear()
        self.captured = 0
        self.alerts = 0

        def worker() -> None:
            try:
                sniff(
                    filter=bpf_filter,
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda _: self.stop_event.is_set()
                    or (packet_limit > 0 and self.captured >= packet_limit),
                )
            except Exception as exc:  # pragma: no cover - runtime dependency
                self.emit("error", f"Capture failed: {exc}")
            finally:
                self.emit("finished", None)

        self.thread = threading.Thread(target=worker, name="capture-thread", daemon=True)
        self.thread.start()

    def _handle_packet(self, packet: Any) -> None:
        try:
            record = parse_packet(packet, self.geoip, self.blacklist)
        except Exception as exc:  # never let one malformed packet kill capture
            self.emit("error", f"Packet parse error: {exc}")
            return
        with self._count_lock:
            self.captured += 1
            if record.alert:
                self.alerts += 1
        self.emit("record", record)

    def stop(self) -> None:
        self.stop_event.set()


# ---------------------------------------------------------------------------
# Graphical interface
# ---------------------------------------------------------------------------


class PacketSnifferApp:
    def __init__(self, password_hash: str) -> None:
        self.password_hash = password_hash
        self.blacklist = Blacklist()
        self.geoip = GeoIPLookup()
        self.store = LogStore()
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.controller = CaptureController(self._emit, self.geoip, self.blacklist)
        self.authenticated = False

        self.root = tk.Tk()
        self.root.withdraw()
        if not self._authenticate():
            self.root.destroy()
            return
        self.authenticated = True
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.deiconify()
        self.root.after(100, self._poll_events)
        if not is_administrator():
            messagebox.showwarning(
                "Privilege notice",
                "Raw packet capture normally requires administrator/root "
                "privileges. If capture fails, restart the application as an "
                "administrator (or with sudo).",
                parent=self.root,
            )

    # -- authentication ---------------------------------------------------
    def _authenticate(self) -> bool:
        for _ in range(3):
            password = simpledialog.askstring(
                "Admin login",
                "Enter the admin password to start the packet sniffer:",
                show="*",
                parent=self.root,
            )
            if password is None:
                return False
            digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
            if hmac.compare_digest(digest, self.password_hash):
                return True
            messagebox.showerror("Access denied", "Incorrect password.", parent=self.root)
        return False

    # -- UI construction --------------------------------------------------
    def _build_ui(self) -> None:
        root = self.root
        root.title("Packet Sniffer and Analyzer with GUI - Rahul Kumar (BSCSY015)")
        root.geometry("1120x760")
        root.minsize(900, 620)

        main = ttk.Frame(root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        controls = ttk.LabelFrame(main, text="Capture controls", padding=10)
        controls.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(controls, text="BPF filter:").grid(row=0, column=0, sticky="w")
        self.filter_var = tk.StringVar(value="udp port 53 or tcp port 80 or tcp port 443")
        ttk.Entry(controls, textvariable=self.filter_var, width=48).grid(
            row=0, column=1, columnspan=3, sticky="ew", padx=6
        )

        ttk.Label(controls, text="Protocol:").grid(row=1, column=0, sticky="w", pady=6)
        self.protocol_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            controls,
            textvariable=self.protocol_var,
            values=list(PROTOCOL_FILTERS),
            state="readonly",
            width=14,
        ).grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(controls, text="Packet limit (0 = unlimited):").grid(
            row=1, column=2, sticky="e", pady=6
        )
        self.limit_var = tk.StringVar(value="0")
        ttk.Spinbox(controls, from_=0, to=100000, textvariable=self.limit_var, width=10).grid(
            row=1, column=3, sticky="w", padx=6, pady=6
        )

        self.start_button = ttk.Button(controls, text="Start capture", command=self.start_capture)
        self.start_button.grid(row=0, column=4, padx=6)
        self.stop_button = ttk.Button(
            controls, text="Stop capture", command=self.stop_capture, state="disabled"
        )
        self.stop_button.grid(row=1, column=4, padx=6)
        controls.columnconfigure(1, weight=1)

        body = ttk.Frame(main)
        body.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.LabelFrame(body, text="Live packet log", padding=6)
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_box = scrolledtext.ScrolledText(log_frame, height=22, wrap="none")
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.tag_configure("alert", foreground="#b00020", background="#fff3cd")
        self.log_box.configure(state="disabled")

        stats_frame = ttk.LabelFrame(body, text="Session statistics", padding=10)
        stats_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(8, 0))
        self.stats_text = tk.Text(stats_frame, width=30, height=18, state="disabled")
        self.stats_text.pack(fill=tk.Y, expand=True)

        actions = ttk.LabelFrame(main, text="Tools", padding=8)
        actions.pack(fill=tk.X, pady=(8, 0))
        buttons = [
            ("View alerts", self.view_alerts),
            ("Traffic summary", self.show_summary),
            ("Export CSV", self.export_csv),
            ("Export JSON", self.export_json),
            ("Edit blacklists", self.edit_blacklists),
            ("Filter by date", self.filter_by_date),
            ("Clear logs", self.clear_logs),
        ]
        for index, (label, command) in enumerate(buttons):
            ttk.Button(actions, text=label, command=command).grid(
                row=0, column=index, padx=4, pady=2
            )

        self.status_var = tk.StringVar(value=f"Ready | {self.geoip.status}")
        ttk.Label(
            root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padding=4
        ).pack(side=tk.BOTTOM, fill=tk.X)
        self._refresh_stats()

    # -- event bridge -----------------------------------------------------
    def _emit(self, kind: str, payload: Any) -> None:
        self.events.put((kind, payload))

    def _poll_events(self) -> None:
        processed = False
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            processed = True
            if kind == "record":
                self._display_record(payload)
            elif kind == "error":
                messagebox.showerror("Capture error", str(payload), parent=self.root)
            elif kind == "finished":
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self._set_status("Capture stopped")
        if processed:
            self._refresh_stats()
        self.root.after(100, self._poll_events)

    def _display_record(self, record: PacketRecord) -> None:
        self.store.append(record)
        line = (
            f"{record.timestamp}  {record.protocol:<5}  "
            f"{record.src_ip}:{record.src_port or '-'} -> "
            f"{record.dst_ip}:{record.dst_port or '-'}  "
            f"{record.length}B  {record.info or record.summary}"
        )
        if record.alert:
            line += f"\n    [ALERT] {record.alert}"
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, line + "\n", "alert" if record.alert else ())
        if int(self.log_box.index("end-1c").split(".")[0]) > 2000:
            self.log_box.delete("1.0", "500.0")
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def _set_status(self, text: str) -> None:
        self.status_var.set(f"{text} | {self.geoip.status}")

    def _refresh_stats(self) -> None:
        records = self.store.read()
        protocols = Counter(record.get("protocol", "OTHER") for record in records)
        top_talkers = Counter(record.get("src_ip", "-") for record in records).most_common(5)
        lines = [
            f"Captured : {self.controller.captured}",
            f"Alerts   : {self.controller.alerts}",
            f"Stored   : {len(records)}",
            "",
            "Protocols:",
        ]
        lines += [f"  {name}: {count}" for name, count in protocols.most_common()] or ["  none"]
        lines += ["", "Top sources:"]
        lines += [f"  {ip}: {count}" for ip, count in top_talkers] or ["  none"]
        lines += ["", f"Admin    : {'yes' if is_administrator() else 'no'}"]
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", "\n".join(lines))
        self.stats_text.configure(state="disabled")

    # -- actions ----------------------------------------------------------
    def start_capture(self) -> None:
        try:
            limit = int(self.limit_var.get())
            if limit < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid input", "Packet limit must be a positive integer or 0.")
            return
        bpf_filter = build_bpf_filter(self.filter_var.get(), self.protocol_var.get())
        try:
            self.controller.start(bpf_filter, limit)
        except RuntimeError as exc:
            messagebox.showwarning("Capture", str(exc))
            return
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self._set_status(f"Capturing [{bpf_filter or 'all packets'}]")

    def stop_capture(self) -> None:
        self.controller.stop()
        self.stop_button.configure(state="disabled")
        self._set_status("Stopping...")

    def view_alerts(self) -> None:
        alerts = self.store.alerts()
        window = tk.Toplevel(self.root)
        window.title(f"Alerts ({len(alerts)})")
        window.geometry("820x480")
        text = scrolledtext.ScrolledText(window, wrap="none")
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        if not alerts:
            text.insert("1.0", "No alerts recorded in this session.\n")
        for alert in alerts:
            text.insert(
                tk.END,
                f"{alert.get('timestamp', '')}  {alert.get('alert', '')}\n"
                f"    {alert.get('src_ip', '')}:{alert.get('src_port') or '-'} -> "
                f"{alert.get('dst_ip', '')}:{alert.get('dst_port') or '-'}\n\n",
            )
        text.configure(state="disabled")

    def show_summary(self) -> None:
        records = self.store.read()
        if not records:
            messagebox.showinfo("Summary", "No captured packets available yet.")
            return
        try:
            import matplotlib

            matplotlib.use("TkAgg")
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
        except ImportError:
            messagebox.showerror("Summary", "matplotlib is required for charts.")
            return

        protocols = Counter(record.get("protocol", "OTHER") for record in records)
        sources = Counter(record.get("src_ip", "-") for record in records).most_common(6)
        window = tk.Toplevel(self.root)
        window.title("Traffic summary")
        window.geometry("900x520")
        figure = Figure(figsize=(9, 5), dpi=100)
        axes_protocol = figure.add_subplot(1, 2, 1)
        axes_sources = figure.add_subplot(1, 2, 2)
        axes_protocol.bar(protocols.keys(), protocols.values(), color="#2b6cb0")
        axes_protocol.set_title("Packets by protocol")
        axes_protocol.tick_params(axis="x", rotation=45)
        axes_sources.bar([name for name, _ in sources], [count for _, count in sources], color="#38a169")
        axes_sources.set_title("Top source addresses")
        axes_sources.tick_params(axis="x", rotation=45)
        figure.tight_layout()
        canvas = FigureCanvasTkAgg(figure, master=window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def export_csv(self) -> None:
        destination = filedialog.asksaveasfilename(
            title="Export packets as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="packet_capture.csv",
            parent=self.root,
        )
        if not destination:
            return
        try:
            self.store.export_csv(self.store.read(), Path(destination))
            messagebox.showinfo("Export complete", f"Saved to {destination}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def export_json(self) -> None:
        destination = filedialog.asksaveasfilename(
            title="Export packets as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="packet_capture.json",
            parent=self.root,
        )
        if not destination:
            return
        try:
            self.store.export_json(self.store.read(), Path(destination))
            messagebox.showinfo("Export complete", f"Saved to {destination}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def edit_blacklists(self) -> None:
        window = tk.Toplevel(self.root)
        window.title("Edit blacklists")
        window.geometry("620x360")
        ttk.Label(window, text="Malicious domains (comma or newline separated):").pack(
            anchor="w", padx=10, pady=(10, 2)
        )
        domains = scrolledtext.ScrolledText(window, height=5)
        domains.pack(fill=tk.X, padx=10)
        domains.insert("1.0", ", ".join(self.blacklist.domains))
        ttk.Label(window, text="Malicious IP addresses:").pack(
            anchor="w", padx=10, pady=(10, 2)
        )
        ips = scrolledtext.ScrolledText(window, height=5)
        ips.pack(fill=tk.X, padx=10)
        ips.insert("1.0", ", ".join(self.blacklist.ips))

        def save() -> None:
            try:
                self.blacklist.update(
                    _split_entries(domains.get("1.0", tk.END)),
                    _split_entries(ips.get("1.0", tk.END)),
                )
            except ValueError as exc:
                messagebox.showerror("Invalid entry", str(exc), parent=window)
                return
            messagebox.showinfo("Saved", "Blacklists saved to config/blacklists.json", parent=window)
            window.destroy()

        ttk.Button(window, text="Save blacklists", command=save).pack(pady=12)

    def filter_by_date(self) -> None:
        date = simpledialog.askstring("Filter logs", "Enter date (YYYY-MM-DD):", parent=self.root)
        if not date:
            return
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Invalid date", "Use the format YYYY-MM-DD.")
            return
        matches = [
            record
            for record in self.store.read()
            if str(record.get("timestamp", "")).startswith(date)
        ]
        if not matches:
            messagebox.showinfo("No matches", f"No packets captured on {date}.")
            return
        destination = filedialog.asksaveasfilename(
            title="Save filtered logs",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"logs_{date}.json",
            parent=self.root,
        )
        if destination:
            self.store.export_json(matches, Path(destination))
            messagebox.showinfo("Saved", f"Saved {len(matches)} records to {destination}")

    def clear_logs(self) -> None:
        if messagebox.askyesno("Clear logs", "Delete all captured logs and alerts?"):
            self.store.clear()
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", tk.END)
            self.log_box.configure(state="disabled")
            self._refresh_stats()

    def _on_close(self) -> None:
        if self.controller.running:
            self.controller.stop()
        self.geoip.close()
        self.root.destroy()

    def run(self) -> None:
        if self.authenticated:
            self.root.mainloop()


def main() -> None:
    app = PacketSnifferApp(admin_password_hash())
    app.run()


if __name__ == "__main__":
    main()
