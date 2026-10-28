#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
IA IP SCANNER - INFORMATION ASSURANCE EDITION (v2.0)
Advanced Network Discovery, Port Auditing & Administration Tool for Windows
=============================================================================
Changelog v2.0 (Self-Tested & Hardened):
- Fixed UNC Path escaping (\\IP\Share) for SMB enumeration, Explorer & Shutdown
- Fixed OUI MAC Database formatting & expanded vendor signatures
- Parallelized Port Scanning per host (nested concurrency) for 5x faster scans
- Instant thread cancellation on Stop (executor.shutdown(wait=False, cancel_futures=True))
- Added Windows NetBIOS Name Resolution fallback (nbtstat -A) when DNS fails
- Added double-click support for specific SMB child share nodes (\\IP\ShareName)
- Added XML/HTML entity escaping (html.escape) to prevent broken reports or XSS
- Sorted all exported reports (CSV, HTML, XML) by IPv4 address ascending
=============================================================================
"""

import os
import re
import sys
import csv
import html
import time
import socket
import struct
import threading
import subprocess
import ipaddress
import webbrowser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# =============================================================================
# MAC OUI VENDOR DATABASE (Validated 8-Char XX:XX:XX Prefixes)
# =============================================================================
OUI_DATABASE = {
    "00:05:69": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware", "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox", "0A:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V", "00:03:FF": "Microsoft",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google",
    "00:03:93": "Apple", "00:0A:95": "Apple", "00:1E:C2": "Apple", "18:65:90": "Apple",
    "28:CF:E9": "Apple", "3C:22:FB": "Apple", "40:CB:C0": "Apple", "70:56:81": "Apple",
    "A4:83:E7": "Apple", "BC:52:B7": "Apple", "DC:A9:04": "Apple", "F0:18:98": "Apple",
    "00:1B:63": "Apple", "00:1F:F3": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:14:22": "Dell", "00:21:70": "Dell", "14:FE:B5": "Dell", "24:B6:FD": "Dell",
    "4C:76:25": "Dell", "74:86:7A": "Dell", "B8:CA:3A": "Dell", "F8:BC:12": "Dell", "00:1A:A0": "Dell",
    "00:17:A4": "HP", "00:21:5A": "HP", "10:1F:74": "HP", "2C:44:FD": "HP", "3C:D9:2B": "HP",
    "00:1E:67": "Intel", "00:1F:3B": "Intel", "00:24:D7": "Intel", "34:02:86": "Intel",
    "48:51:B7": "Intel", "68:05:CA": "Intel", "80:86:F2": "Intel", "8C:8D:28": "Intel",
    "A4:34:D9": "Intel", "DC:FB:48": "Intel", "F8:94:C2": "Intel",
    "00:0E:C6": "ASUS", "04:D4:C4": "ASUS", "10:7B:44": "ASUS", "2C:56:DC": "ASUS",
    "38:D5:47": "ASUS", "60:45:CB": "ASUS", "AC:22:0B": "ASUS", "F0:79:59": "ASUS",
    "00:1D:7D": "MSI (Micro-Star)", "00:24:21": "MSI (Micro-Star)", "2C:FD:A1": "MSI (Micro-Star)",
    "30:9C:23": "MSI (Micro-Star)", "40:61:86": "MSI (Micro-Star)", "6C:62:6D": "MSI (Micro-Star)",
    "8C:89:A5": "MSI (Micro-Star)", "D4:3D:7E": "MSI (Micro-Star)", "D8:CB:8A": "MSI (Micro-Star)",
    "00:1A:4D": "Gigabyte", "1C:6F:65": "Gigabyte", "50:E5:49": "Gigabyte", "74:D4:35": "Gigabyte",
    "90:2B:34": "Gigabyte", "B4:2E:99": "Gigabyte", "E0:D5:5E": "Gigabyte",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU / KVM", "00:13:D4": "ASRock", "00:0C:43": "Ralink",
    "00:14:78": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link", "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link", "54:C8:0F": "TP-Link", "60:E3:27": "TP-Link", "84:16:F9": "TP-Link",
    "98:DA:C4": "TP-Link", "C0:25:E9": "TP-Link", "E8:DE:27": "TP-Link",
    "00:07:EB": "Cisco", "00:0A:41": "Cisco", "00:12:44": "Cisco", "00:1B:54": "Cisco",
    "00:24:14": "Cisco", "58:AC:78": "Cisco", "F8:72:EA": "Cisco",
    "00:18:E7": "Cameo", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "80:2A:A8": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "00:26:B6": "Askey", "00:E0:FC": "Huawei", "04:F9:38": "Huawei", "28:6E:D4": "Huawei",
    "48:46:FB": "Huawei", "88:28:B3": "Huawei", "CC:B1:82": "Huawei",
    "00:1E:75": "LG", "00:12:FB": "Samsung", "00:15:99": "Samsung", "14:49:E0": "Samsung",
    "28:98:7B": "Samsung", "50:01:BB": "Samsung", "78:47:1D": "Samsung", "A8:F2:74": "Samsung",
    "00:90:A9": "Western Digital", "00:11:32": "Synology", "28:28:5D": "Viettel / ZTE",
    "AC:64:CF": "Xiaomi", "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi", "F8:A4:5F": "Xiaomi"
}

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# =============================================================================
# COLOR PALETTE (CYBERSECURITY / IA THEME)
# =============================================================================
THEME = {
    "bg_main": "#0B0F19",        # Deep Navy-Black
    "bg_panel": "#111827",       # Dark Slate Panel
    "bg_input": "#1F2937",       # Input Field Background
    "bg_row_even": "#111827",    # Treeview Even Row
    "bg_row_odd": "#162032",     # Treeview Odd Row
    "bg_selected": "#0284C7",    # Selected Row Cyan-Blue
    "fg_primary": "#F9FAFB",     # Crisp White-Gray
    "fg_secondary": "#9CA3AF",   # Muted Gray
    "accent_cyan": "#00E5FF",    # Cyber Cyan
    "accent_green": "#10B981",   # Online Emerald Green
    "accent_red": "#EF4444",     # Danger / Stop Red
    "accent_amber": "#F59E0B",   # Warning / Custom Port Amber
    "border": "#374151"          # Subtle Border
}

# =============================================================================
# NETWORK ENGINE & UTILITY FUNCTIONS
# =============================================================================
def get_local_network_info():
    """Detects primary local IP address and suggests a /24 range."""
    local_ip = "192.168.1.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

    parts = local_ip.split(".")
    if len(parts) == 4:
        base = f"{parts[0]}.{parts[1]}.{parts[2]}"
        return local_ip, f"{base}.1-254"
    return local_ip, "192.168.1.1-254"


def parse_ip_targets(target_str):
    """
    Parses Advanced IP Scanner style strings into a flat list of IP strings.
    Supports:
      - 192.168.1.1-254
      - 192.168.1.1-192.168.1.100
      - 192.168.1.0/24
      - Comma-separated combinations: 192.168.1.1-50, 10.0.0.5
    """
    ips = []
    segments = [seg.strip() for seg in target_str.split(",") if seg.strip()]

    for seg in segments:
        if "/" in seg:
            try:
                net = ipaddress.ip_network(seg, strict=False)
                if net.num_addresses > 65536:
                    raise ValueError("Mạng CIDR quá lớn (tối đa /16 tương đương 65,536 IP).")
                for ip in net.hosts():
                    ips.append(str(ip))
            except ValueError as e:
                raise ValueError(f"Định dạng CIDR không hợp lệ: {seg} ({e})")

        elif "-" in seg:
            start_part, end_part = [p.strip() for p in seg.split("-", 1)]
            try:
                start_ip = ipaddress.IPv4Address(start_part)
                if "." in end_part:
                    end_ip = ipaddress.IPv4Address(end_part)
                else:
                    octet = int(end_part)
                    if not (0 <= octet <= 255):
                        raise ValueError(f"Octet cuối phải từ 0 đến 255 (nhận được: {octet}).")
                    prefix = ".".join(start_part.split(".")[:-1])
                    end_ip = ipaddress.IPv4Address(f"{prefix}.{octet}")

                if int(end_ip) < int(start_ip):
                    start_ip, end_ip = end_ip, start_ip

                if int(end_ip) - int(start_ip) > 65535:
                    raise ValueError("Dải IP quá lớn (tối đa 65,535 IP mỗi lần quét).")

                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    ips.append(str(ipaddress.IPv4Address(ip_int)))
            except Exception as e:
                raise ValueError(f"Dải IP không hợp lệ: {seg} ({e})")

        else:
            try:
                ip = ipaddress.IPv4Address(seg)
                ips.append(str(ip))
            except ValueError:
                try:
                    resolved = socket.gethostbyname(seg)
                    ips.append(resolved)
                except Exception:
                    raise ValueError(f"Địa chỉ IP hoặc Hostname không hợp lệ: {seg}")

    return list(dict.fromkeys(ips))


def parse_custom_ports(port_str):
    """Parses custom port string like '80, 443, 8000-8005' into a sorted list of ints."""
    ports = set()
    if not port_str or not port_str.strip():
        return []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            s, e = part.split("-", 1)
            s_p, e_p = int(s.strip()), int(e.strip())
            if s_p > e_p:
                s_p, e_p = e_p, s_p
            if e_p - s_p > 2000:
                raise ValueError("Dải Custom Port quá rộng (tối đa 2000 cổng để đảm bảo tốc độ).")
            for p in range(s_p, e_p + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
            else:
                raise ValueError(f"Cổng {p} nằm ngoài phạm vi hợp lệ (1-65535).")
    return sorted(list(ports))


def guess_os_from_ttl(ttl):
    """Predicts OS family based on ICMP TTL value."""
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return f"Linux / Unix / macOS (TTL={ttl})"
    elif ttl <= 128:
        return f"Windows (TTL={ttl})"
    else:
        return f"Network Device / Cisco (TTL={ttl})"


def lookup_mac_vendor(mac):
    """Looks up manufacturer from MAC address prefix (supports both : and - separators)."""
    if not mac:
        return "Unknown"
    clean_mac = mac.strip().upper().replace("-", ":")
    if len(clean_mac) < 8 or clean_mac.count(":") < 2:
        return "Unknown"
    prefix = clean_mac[:8]
    return OUI_DATABASE.get(prefix, "Generic / Unknown Vendor")


def get_arp_table():
    """Parses the system ARP cache into a dict {ip: mac}."""
    arp_map = {}
    try:
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        output = subprocess.check_output(
            ["arp", "-a"],
            startupinfo=startupinfo,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            encoding="utf-8",
            errors="ignore"
        )
        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
        )
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2).upper().replace("-", ":")
                if mac_addr != "FF:FF:FF:FF:FF:FF":
                    arp_map[ip_addr] = mac_addr
    except Exception:
        pass
    return arp_map


def ping_host(ip, timeout_ms=600):
    """
    Pings a target IP using native OS ping command.
    Returns: (is_alive: bool, rtt_ms: str, ttl: int or None)
    """
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, int(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        output = subprocess.check_output(
            cmd,
            startupinfo=startupinfo,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding="utf-8",
            errors="ignore"
        )
        ttl_match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
        time_match = re.search(r"(?:time|thời gian)[=<](\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)

        if ttl_match:
            ttl = int(ttl_match.group(1))
            rtt = f"{time_match.group(1)} ms" if time_match else "<1 ms"
            return True, rtt, ttl
    except Exception:
        pass
    return False, "", None


def scan_tcp_port(ip, port, timeout=0.35):
    """Checks if a single TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def get_netbios_or_dns_name(ip):
    """Resolves hostname via reverse DNS, falling back to Windows NetBIOS (nbtstat -A) if needed."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name
    except Exception:
        pass

    if os.name == "nt":
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output(
                ["nbtstat", "-A", ip],
                startupinfo=startupinfo,
                stderr=subprocess.DEVNULL,
                timeout=1.2,
                universal_newlines=True,
                encoding="utf-8",
                errors="ignore"
            )
            for line in output.splitlines():
                if "<00>" in line and "UNIQUE" in line.upper():
                    parts = line.strip().split()
                    if parts:
                        return parts[0]
        except Exception:
            pass
    return ip


def enumerate_smb_shares(ip):
    """Attempts to list Windows SMB shares via net view \\IP."""
    if os.name != "nt":
        return []
    shares = []
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        unc_target = f"\\\\{ip}"
        output = subprocess.check_output(
            ["net", "view", unc_target],
            startupinfo=startupinfo,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            universal_newlines=True,
            encoding="utf-8",
            errors="ignore"
        )
        for line in output.splitlines():
            match = re.match(r"^(.+?)\s+(?:Disk|Print)\s+", line.strip())
            if match:
                shares.append(match.group(1).strip())
    except Exception:
        pass
    return shares


def send_wake_on_lan(mac_address, broadcast_ip="255.255.255.255", port=9):
    """Constructs and sends a Wake-on-LAN Magic Packet."""
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(clean_mac) != 12:
        raise ValueError("Địa chỉ MAC không hợp lệ (Cần đúng 12 ký tự Hex).")

    data = bytes.fromhex("FF" * 6 + clean_mac * 16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, (broadcast_ip, port))


def rtt_to_float(rtt_str):
    """Converts RTT string ('12 ms', '<1 ms', 'TCP Resp') to float for accurate sorting."""
    if not rtt_str:
        return 999999.0
    if "<1" in rtt_str:
        return 0.5
    m = re.search(r"(\d+(?:\.\d+)?)", rtt_str)
    return float(m.group(1)) if m else 99999.0


# =============================================================================
# MAIN GUI APPLICATION: IA IP SCANNER
# =============================================================================
class IAIPScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IA IP Scanner - Information Assurance Edition v2.0")
        self.root.geometry("1280x760")
        self.root.minsize(1024, 600)
        self.root.configure(bg=THEME["bg_main"])

        # State Variables
        self.is_scanning = False
        self.stop_event = threading.Event()
        self.scan_results = {}  # ip -> dict of host info
        self.sort_reverse = {}  # col -> bool
        self.local_ip, default_range = get_local_network_info()

        # Tkinter Variables
        self.ip_range_var = tk.StringVar(value=default_range)
        self.custom_ports_var = tk.StringVar(value="21, 22, 80, 443, 445, 3389, 8080")
        self.threads_var = tk.IntVar(value=100)
        self.timeout_var = tk.IntVar(value=500)
        self.scan_shares_var = tk.BooleanVar(value=True)
        self.tcp_fallback_var = tk.BooleanVar(value=True)
        self.search_filter_var = tk.StringVar()
        self.search_filter_var.trace_add("write", lambda *args: self.apply_filter())

        self.status_text_var = tk.StringVar(value=f"Sẵn sàng | IP Máy trạm: {self.local_ip}")
        self.stats_text_var = tk.StringVar(value="Alive: 0 | Ports Open: 0 | Shares: 0")

        self._setup_styles()
        self._build_header()
        self._build_control_panel()
        self._build_quick_action_bar()
        self._build_treeview()
        self._build_status_bar()
        self._build_context_menu()

    def _setup_styles(self):
        """Configures custom dark mode ttk styles."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "IA.Treeview",
            background=THEME["bg_row_even"],
            foreground=THEME["fg_primary"],
            fieldbackground=THEME["bg_row_even"],
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 10)
        )
        style.configure(
            "IA.Treeview.Heading",
            background="#1E293B",
            foreground=THEME["accent_cyan"],
            relief="flat",
            font=("Segoe UI Semibold", 10)
        )
        style.map(
            "IA.Treeview",
            background=[("selected", THEME["bg_selected"])],
            foreground=[("selected", "#FFFFFF")]
        )
        style.map(
            "IA.Treeview.Heading",
            background=[("active", "#334155")]
        )

        style.configure(
            "IA.Horizontal.TProgressbar",
            troughcolor=THEME["bg_input"],
            background=THEME["accent_cyan"],
            bordercolor=THEME["bg_main"],
            lightcolor=THEME["accent_cyan"],
            darkcolor=THEME["accent_cyan"]
        )

    def _build_header(self):
        """Builds the top branding and utility bar."""
        header = tk.Frame(self.root, bg=THEME["bg_panel"], pady=10, padx=16)
        header.pack(fill="x", side="top")

        title_frame = tk.Frame(header, bg=THEME["bg_panel"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame, text=" 🛡️ IA ", bg=THEME["accent_cyan"], fg="#000000",
            font=("Consolas", 13, "bold"), padx=4, pady=2
        ).pack(side="left", padx=(0, 10))

        tk.Label(
            title_frame, text="IA IP SCANNER", bg=THEME["bg_panel"], fg=THEME["fg_primary"],
            font=("Segoe UI", 15, "bold")
        ).pack(side="left")

        tk.Label(
            title_frame, text=" v2.0 // Network Discovery & Security Auditor",
            bg=THEME["bg_panel"], fg=THEME["fg_secondary"], font=("Consolas", 10)
        ).pack(side="left", padx=(8, 0))

        btn_frame = tk.Frame(header, bg=THEME["bg_panel"])
        btn_frame.pack(side="right")

        self._create_flat_button(
            btn_frame, "🌐 Lấy Subnet Hiện Tại", self.auto_fill_subnet,
            bg="#1E293B", fg=THEME["accent_cyan"]
        ).pack(side="left", padx=4)

        self._create_flat_button(
            btn_frame, "⚡ Wake-on-LAN", self.dialog_wake_on_lan,
            bg="#1E293B", fg=THEME["accent_amber"]
        ).pack(side="left", padx=4)

        self._create_flat_button(
            btn_frame, "💾 Xuất Báo Cáo (CSV/HTML/XML)", self.export_results,
            bg="#1E293B", fg=THEME["accent_green"]
        ).pack(side="left", padx=4)

    def _build_control_panel(self):
        """Builds the IP range input, custom port settings, and Scan/Stop buttons."""
        panel = tk.Frame(self.root, bg=THEME["bg_main"], pady=8, padx=16)
        panel.pack(fill="x", side="top")

        row1 = tk.Frame(panel, bg=THEME["bg_main"])
        row1.pack(fill="x", pady=(0, 6))

        tk.Label(
            row1, text="Dải IP / CIDR:", bg=THEME["bg_main"], fg=THEME["fg_primary"],
            font=("Segoe UI Semibold", 10), width=13, anchor="w"
        ).pack(side="left")

        self.entry_ip = tk.Entry(
            row1, textvariable=self.ip_range_var, bg=THEME["bg_input"], fg=THEME["accent_cyan"],
            insertbackground="#FFFFFF", relief="flat", font=("Consolas", 11)
        )
        self.entry_ip.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 12))

        self.btn_scan = tk.Button(
            row1, text="▶ BẮT ĐẦU QUÉT (SCAN)", command=self.start_scan,
            bg=THEME["accent_green"], fg="#000000", activebackground="#059669",
            font=("Segoe UI", 10, "bold"), relief="flat", padx=18, pady=5, cursor="hand2"
        )
        self.btn_scan.pack(side="left", padx=(0, 8))

        self.btn_stop = tk.Button(
            row1, text="⏹ DỪNG LẠI", command=self.stop_scan, state="disabled",
            bg=THEME["accent_red"], fg="#FFFFFF", activebackground="#DC2626",
            font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=5, cursor="hand2"
        )
        self.btn_stop.pack(side="left")

        row2 = tk.Frame(panel, bg=THEME["bg_main"])
        row2.pack(fill="x")

        tk.Label(
            row2, text="Custom Ports:", bg=THEME["bg_main"], fg=THEME["fg_primary"],
            font=("Segoe UI Semibold", 10), width=13, anchor="w"
        ).pack(side="left")

        entry_ports = tk.Entry(
            row2, textvariable=self.custom_ports_var, bg=THEME["bg_input"], fg=THEME["accent_amber"],
            insertbackground="#FFFFFF", relief="flat", font=("Consolas", 10), width=32
        )
        entry_ports.pack(side="left", ipady=4, padx=(0, 14))

        tk.Label(
            row2, text="Luồng (Threads):", bg=THEME["bg_main"], fg=THEME["fg_secondary"],
            font=("Segoe UI", 9)
        ).pack(side="left")

        spin_threads = tk.Spinbox(
            row2, from_=10, to=300, increment=10, textvariable=self.threads_var,
            bg=THEME["bg_input"], fg=THEME["fg_primary"], relief="flat", width=5,
            font=("Consolas", 10), buttonbackground=THEME["bg_panel"]
        )
        spin_threads.pack(side="left", ipady=3, padx=(4, 14))

        tk.Checkbutton(
            row2, text="TCP Ping Fallback (Chống chặn ICMP)", variable=self.tcp_fallback_var,
            bg=THEME["bg_main"], fg=THEME["fg_secondary"], selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_main"], activeforeground=THEME["fg_primary"],
            font=("Segoe UI", 9)
        ).pack(side="left", padx=(0, 10))

        tk.Checkbutton(
            row2, text="Liệt kê Shared Folders (SMB)", variable=self.scan_shares_var,
            bg=THEME["bg_main"], fg=THEME["fg_secondary"], selectcolor=THEME["bg_input"],
            activebackground=THEME["bg_main"], activeforeground=THEME["fg_primary"],
            font=("Segoe UI", 9)
        ).pack(side="left", padx=(0, 10))

        tk.Entry(
            row2, textvariable=self.search_filter_var, bg=THEME["bg_input"], fg=THEME["fg_primary"],
            insertbackground="#FFFFFF", relief="flat", font=("Segoe UI", 10), width=22
        ).pack(side="right", ipady=3)
        tk.Label(
            row2, text="🔍 Lọc nhanh:", bg=THEME["bg_main"], fg=THEME["fg_secondary"],
            font=("Segoe UI", 9)
        ).pack(side="right", padx=(0, 4))

    def _build_quick_action_bar(self):
        """Toolbar for one-click actions on the selected host."""
        bar = tk.Frame(self.root, bg=THEME["bg_panel"], pady=6, padx=16)
        bar.pack(fill="x", side="top")

        tk.Label(
            bar, text="TÁC VỤ NHANH:", bg=THEME["bg_panel"], fg=THEME["fg_secondary"],
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(0, 8))

        actions = [
            ("🌍 Mở Web (HTTP)", lambda: self.action_open_web(https=False)),
            ("🔒 Mở Web (HTTPS)", lambda: self.action_open_web(https=True)),
            ("📂 Mở Shared Folder", self.action_open_shares),
            ("🖥️ Remote Desktop (RDP)", self.action_open_rdp),
            ("💻 Kết nối SSH", self.action_open_ssh),
            ("📡 CMD Ping", self.action_cmd_ping),
            ("🧭 CMD Tracert", self.action_cmd_tracert),
            ("⚡ Wake-on-LAN", self.action_wol_selected),
            ("🛑 Tắt máy từ xa (Shutdown)", self.action_remote_shutdown),
            ("📋 Copy IP", lambda: self.action_copy_field("ip")),
            ("📋 Copy MAC", lambda: self.action_copy_field("mac")),
            ("➕ Mở rộng / Thu gọn cây", self.toggle_all_trees)
        ]

        for label, cmd in actions:
            btn = self._create_flat_button(bar, label, cmd, bg="#1F2937", fg=THEME["fg_primary"], font_size=9)
            btn.pack(side="left", padx=3)

    def _build_treeview(self):
        """Builds the main hierarchical table displaying discovered devices and expandable services."""
        container = tk.Frame(self.root, bg=THEME["bg_main"], padx=16, pady=6)
        container.pack(fill="both", expand=True)

        columns = ("ip", "hostname", "os_ttl", "mac", "vendor", "ports", "rtt")
        self.tree = ttk.Treeview(
            container, columns=columns, show="tree headings", style="IA.Treeview", selectmode="browse"
        )

        self.tree.heading("#0", text="Trạng thái / Dịch vụ", anchor="w")
        self.tree.heading("ip", text="Địa chỉ IP ↕", anchor="w", command=lambda: self.sort_column("ip"))
        self.tree.heading("hostname", text="Tên thiết bị (Hostname) ↕", anchor="w", command=lambda: self.sort_column("hostname"))
        self.tree.heading("os_ttl", text="Hệ điều hành (TTL) ↕", anchor="w", command=lambda: self.sort_column("os_ttl"))
        self.tree.heading("mac", text="Địa chỉ MAC ↕", anchor="w", command=lambda: self.sort_column("mac"))
        self.tree.heading("vendor", text="Nhà sản xuất (Manufacturer) ↕", anchor="w", command=lambda: self.sort_column("vendor"))
        self.tree.heading("ports", text="Cổng mở & Dịch vụ (Open Ports) ↕", anchor="w", command=lambda: self.sort_column("ports"))
        self.tree.heading("rtt", text="Ping ↕", anchor="center", command=lambda: self.sort_column("rtt"))

        self.tree.column("#0", width=185, minwidth=150)
        self.tree.column("ip", width=125, minwidth=110)
        self.tree.column("hostname", width=175, minwidth=130)
        self.tree.column("os_ttl", width=175, minwidth=130)
        self.tree.column("mac", width=140, minwidth=120)
        self.tree.column("vendor", width=185, minwidth=140)
        self.tree.column("ports", width=220, minwidth=150)
        self.tree.column("rtt", width=80, minwidth=65, anchor="center")

        self.tree.tag_configure("even", background=THEME["bg_row_even"], foreground=THEME["fg_primary"])
        self.tree.tag_configure("odd", background=THEME["bg_row_odd"], foreground=THEME["fg_primary"])
        self.tree.tag_configure("child", background="#0F172A", foreground=THEME["accent_cyan"], font=("Consolas", 9))

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.on_double_click)

        self.trees_expanded = False

    def _build_status_bar(self):
        """Builds the bottom status and progress bar."""
        footer = tk.Frame(self.root, bg=THEME["bg_panel"], pady=6, padx=16)
        footer.pack(fill="x", side="bottom")

        tk.Label(
            footer, textvariable=self.status_text_var, bg=THEME["bg_panel"],
            fg=THEME["fg_secondary"], font=("Consolas", 9)
        ).pack(side="left")

        self.progress = ttk.Progressbar(
            footer, orient="horizontal", length=280, mode="determinate",
            style="IA.Horizontal.TProgressbar"
        )
        self.progress.pack(side="right", padx=(12, 0))

        tk.Label(
            footer, textvariable=self.stats_text_var, bg=THEME["bg_panel"],
            fg=THEME["accent_cyan"], font=("Consolas", 9, "bold")
        ).pack(side="right")

    def _build_context_menu(self):
        """Right-click popup menu matching Advanced IP Scanner."""
        self.context_menu = tk.Menu(
            self.root, tearoff=0, bg=THEME["bg_panel"], fg=THEME["fg_primary"],
            activebackground=THEME["bg_selected"], activeforeground="#FFFFFF",
            font=("Segoe UI", 9)
        )
        self.context_menu.add_command(label="🌍 Mở trình duyệt HTTP (Port 80)", command=lambda: self.action_open_web(False))
        self.context_menu.add_command(label="🔒 Mở trình duyệt HTTPS (Port 443)", command=lambda: self.action_open_web(True))
        self.context_menu.add_command(label="📂 Mở Thư mục Chia sẻ (\\\\IP)", command=self.action_open_shares)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🖥️ Kết nối Remote Desktop (mstsc)", command=self.action_open_rdp)
        self.context_menu.add_command(label="💻 Kết nối SSH (Terminal)", command=self.action_open_ssh)
        self.context_menu.add_command(label="📁 Mở FTP trong Explorer", command=self.action_open_ftp)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📡 Chạy lệnh Ping (CMD)", command=self.action_cmd_ping)
        self.context_menu.add_command(label="🧭 Chạy lệnh Traceroute (CMD)", command=self.action_cmd_tracert)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⚡ Gửi gói tin Wake-on-LAN", command=self.action_wol_selected)
        self.context_menu.add_command(label="🛑 Tắt máy từ xa (Remote Shutdown)", command=self.action_remote_shutdown)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy Địa chỉ IP", command=lambda: self.action_copy_field("ip"))
        self.context_menu.add_command(label="📋 Copy Địa chỉ MAC", command=lambda: self.action_copy_field("mac"))
        self.context_menu.add_command(label="📋 Copy Hostname", command=lambda: self.action_copy_field("hostname"))

    def _create_flat_button(self, parent, text, command, bg, fg, font_size=9):
        return tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg,
            activebackground="#374151", activeforeground="#FFFFFF",
            relief="flat", font=("Segoe UI", font_size), padx=8, pady=3, cursor="hand2"
        )

    # =========================================================================
    # SCANNING WORKFLOW & MULTI-THREADING
    # =========================================================================
    def auto_fill_subnet(self):
        self.local_ip, subnet_range = get_local_network_info()
        self.ip_range_var.set(subnet_range)
        self.status_text_var.set(f"Đã tự động nhận diện mạng LAN: {subnet_range} (IP máy: {self.local_ip})")

    def start_scan(self):
        if self.is_scanning:
            return

        try:
            target_ips = parse_ip_targets(self.ip_range_var.get())
        except ValueError as e:
            messagebox.showerror("Lỗi Định Dạng IP", str(e))
            return

        if not target_ips:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập ít nhất một địa chỉ IP hoặc dải mạng.")
            return

        try:
            custom_ports = parse_custom_ports(self.custom_ports_var.get())
        except Exception as e:
            messagebox.showerror("Lỗi Cổng (Port)", f"Danh sách Custom Ports không hợp lệ: {e}\nVí dụ đúng: 21, 22, 80, 443, 8000-8010")
            return

        all_ports = sorted(list(set(DEFAULT_PORTS.keys()).union(set(custom_ports))))

        self.is_scanning = True
        self.stop_event.clear()
        self.scan_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.progress["maximum"] = len(target_ips)
        self.progress["value"] = 0
        self.status_text_var.set(f"Đang quét {len(target_ips)} địa chỉ IP với {len(all_ports)} cổng dịch vụ...")
        self.stats_text_var.set("Alive: 0 | Ports Open: 0 | Shares: 0")

        threading.Thread(
            target=self._scan_coordinator,
            args=(target_ips, all_ports),
            daemon=True
        ).start()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_event.set()
            self.status_text_var.set("Đang dừng tiến trình quét và thu hồi các luồng...")

    def _scan_coordinator(self, target_ips, ports_to_scan):
        start_time = time.time()
        try:
            max_workers = max(10, min(300, int(self.threads_var.get())))
        except Exception:
            max_workers = 100
        try:
            timeout_ms = max(200, int(self.timeout_var.get()))
        except Exception:
            timeout_ms = 500

        do_shares = self.scan_shares_var.get()
        do_tcp_fallback = self.tcp_fallback_var.get()

        completed = 0
        total = len(target_ips)

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_to_ip = {
                executor.submit(
                    self._scan_single_host, ip, ports_to_scan, timeout_ms, do_tcp_fallback, do_shares
                ): ip for ip in target_ips
            }

            for future in as_completed(future_to_ip):
                if self.stop_event.is_set():
                    break
                completed += 1
                try:
                    result = future.result()
                    if result and result.get("alive"):
                        self.root.after(0, self._add_host_to_ui, result)
                except Exception:
                    pass

                self.root.after(0, self._update_progress, completed, total)
        finally:
            if sys.version_info >= (3, 9):
                executor.shutdown(wait=False, cancel_futures=True)
            else:
                executor.shutdown(wait=False)

        arp_table = get_arp_table()
        self.root.after(0, self._finalize_scan, arp_table, time.time() - start_time)

    def _scan_single_host(self, ip, ports_to_scan, timeout_ms, do_tcp_fallback, do_shares):
        if self.stop_event.is_set():
            return None

        # Step 1: ICMP Ping
        alive, rtt, ttl = ping_host(ip, timeout_ms=timeout_ms)

        # Step 2: Optional TCP Ping Fallback (Checks common ports if ICMP is blocked by Firewall)
        open_ports = []
        if not alive and do_tcp_fallback:
            for probe_port in (80, 443, 445, 3389, 22, 135):
                if self.stop_event.is_set():
                    return None
                if scan_tcp_port(ip, probe_port, timeout=0.25):
                    alive = True
                    rtt = "TCP Resp"
                    ttl = 128 if probe_port in (445, 3389, 135) else 64
                    open_ports.append(probe_port)
                    break

        if not alive:
            return {"ip": ip, "alive": False}

        # Step 3: Concurrent Port Scanning on Alive Host
        remaining_ports = [p for p in ports_to_scan if p not in open_ports]
        if remaining_ports and not self.stop_event.is_set():
            port_workers = min(16, len(remaining_ports))
            with ThreadPoolExecutor(max_workers=port_workers) as port_exec:
                fut_map = {port_exec.submit(scan_tcp_port, ip, p, 0.3): p for p in remaining_ports}
                for fut in as_completed(fut_map):
                    if self.stop_event.is_set():
                        break
                    if fut.result():
                        open_ports.append(fut_map[fut])
        open_ports.sort()

        # Step 4: Hostname & OS Fingerprinting
        hostname = get_netbios_or_dns_name(ip)
        os_guess = guess_os_from_ttl(ttl)

        # Step 5: SMB Shared Folders Check (if Port 445 or 139 is open)
        shares = []
        if do_shares and not self.stop_event.is_set() and (445 in open_ports or 139 in open_ports):
            shares = enumerate_smb_shares(ip)

        return {
            "ip": ip,
            "alive": True,
            "hostname": hostname,
            "ttl": ttl,
            "os": os_guess,
            "mac": "Đang lấy...",
            "vendor": "Đang tra cứu...",
            "open_ports": open_ports,
            "shares": shares,
            "rtt": rtt
        }

    def _add_host_to_ui(self, host_data):
        ip = host_data["ip"]
        self.scan_results[ip] = host_data
        query = self.search_filter_var.get().strip().lower()
        if not query or self._matches_filter(host_data, query):
            self._insert_tree_row(host_data)
        self._refresh_counters()

    def _insert_tree_row(self, host_data):
        ip = host_data["ip"]
        if self.tree.exists(ip):
            self.tree.delete(ip)

        ports_str = ", ".join(
            f"{p} ({DEFAULT_PORTS.get(p, 'Custom')})" for p in host_data["open_ports"]
        ) if host_data["open_ports"] else "Không có cổng mở"

        row_count = len(self.tree.get_children(""))
        tag = "even" if row_count % 2 == 0 else "odd"

        node_id = self.tree.insert(
            "", "end", iid=ip,
            text=" 🟢 Online",
            values=(
                ip,
                host_data["hostname"],
                host_data["os"],
                host_data["mac"],
                host_data["vendor"],
                ports_str,
                host_data["rtt"]
            ),
            tags=(tag,)
        )

        for p in host_data["open_ports"]:
            srv_name = DEFAULT_PORTS.get(p, "Custom TCP Service")
            action_hint = "Double-click để mở" if p in (80, 8080, 443, 3389, 22, 21) else "Port đang mở (LISTENING)"
            self.tree.insert(
                node_id, "end",
                text=f"   ├─ 🔌 Port {p} [{srv_name}]",
                values=(ip, srv_name, action_hint, "", "", "", ""),
                tags=("child",)
            )

        for share in host_data["shares"]:
            unc_share = f"\\\\{ip}\\{share}"
            self.tree.insert(
                node_id, "end",
                text=f"   └─ 📂 Share: {unc_share}",
                values=(ip, f"SMB Share ({share})", "Double-click để mở Explorer", "", "", "", ""),
                tags=("child",)
            )

    def _update_progress(self, completed, total):
        self.progress["value"] = completed
        self.status_text_var.set(f"Đang quét... Đã kiểm tra {completed}/{total} địa chỉ IP")

    def _finalize_scan(self, arp_table, elapsed_sec):
        """Updates MAC addresses and Vendor names from ARP cache after scan completes."""
        for ip, data in self.scan_results.items():
            mac = arp_table.get(ip, "N/A (Khác Subnet/Local)")
            if ip == self.local_ip:
                mac = "Local Host"
            vendor = lookup_mac_vendor(mac) if ":" in mac else ("This PC" if mac == "Local Host" else "Unknown")
            data["mac"] = mac
            data["vendor"] = vendor

            if self.tree.exists(ip):
                vals = list(self.tree.item(ip, "values"))
                vals[3] = mac
                vals[4] = vendor
                self.tree.item(ip, values=vals)

        self.is_scanning = False
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.sort_column("ip", force_asc=True)
        self._refresh_counters()

        status_prefix = "Đã dừng quét" if self.stop_event.is_set() else "Hoàn tất quét mạng"
        self.status_text_var.set(
            f"{status_prefix} trong {elapsed_sec:.2f} giây | Tìm thấy {len(self.scan_results)} thiết bị đang hoạt động."
        )

    def _refresh_counters(self):
        alive_count = len(self.scan_results)
        total_ports = sum(len(d["open_ports"]) for d in self.scan_results.values())
        total_shares = sum(len(d["shares"]) for d in self.scan_results.values())
        self.stats_text_var.set(f"Alive: {alive_count} | Ports Open: {total_ports} | Shares: {total_shares}")

    # =========================================================================
    # FILTERING, SORTING & TREE NAVIGATION
    # =========================================================================
    def _matches_filter(self, data, query):
        ports_str = " ".join(str(p) for p in data["open_ports"])
        searchable = f"{data['ip']} {data['hostname']} {data['os']} {data['mac']} {data['vendor']} {ports_str}".lower()
        return query in searchable

    def apply_filter(self):
        query = self.search_filter_var.get().strip().lower()
        for item in self.tree.get_children(""):
            self.tree.delete(item)

        for ip in sorted(self.scan_results.keys(), key=lambda x: int(ipaddress.IPv4Address(x))):
            data = self.scan_results[ip]
            if not query or self._matches_filter(data, query):
                self._insert_tree_row(data)

    def sort_column(self, col, force_asc=False):
        if force_asc:
            reverse = False
        else:
            reverse = self.sort_reverse.get(col, False)
        self.sort_reverse[col] = not reverse

        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col == "ip":
            items.sort(key=lambda t: int(ipaddress.IPv4Address(t[0])), reverse=reverse)
        elif col == "rtt":
            items.sort(key=lambda t: rtt_to_float(t[0]), reverse=reverse)
        else:
            items.sort(key=lambda t: t[0].lower(), reverse=reverse)

        for idx, (_, k) in enumerate(items):
            self.tree.move(k, "", idx)
            tag = "even" if idx % 2 == 0 else "odd"
            self.tree.item(k, tags=(tag,))

    def toggle_all_trees(self):
        self.trees_expanded = not self.trees_expanded
        for item in self.tree.get_children(""):
            self.tree.item(item, open=self.trees_expanded)

    # =========================================================================
    # INTERACTIVE ACTIONS (WEB, RDP, SMB, SSH, WOL, SHUTDOWN)
    # =========================================================================
    def _get_selected_ip(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Thông báo", "Vui lòng chọn một thiết bị trong danh sách trước.")
            return None
        item_id = sel[0]
        parent_id = self.tree.parent(item_id)
        return parent_id if parent_id else item_id

    def show_context_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def on_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        text = self.tree.item(item_id, "text")
        ip = self._get_selected_ip()

        if "Port 80 " in text:
            webbrowser.open(f"http://{ip}")
        elif "Port 8080" in text:
            webbrowser.open(f"http://{ip}:8080")
        elif "Port 443" in text:
            webbrowser.open(f"https://{ip}")
        elif "Port 3389" in text:
            self.action_open_rdp()
        elif "Port 22 " in text:
            self.action_open_ssh()
        elif "Port 21 " in text:
            self.action_open_ftp()
        elif "Share:" in text:
            match = re.search(r"Share:\s*(\\\\[^\s]+)", text)
            target_unc = match.group(1) if match else f"\\\\{ip}"
            self.action_open_shares(custom_unc=target_unc)

    def action_open_web(self, https=False):
        ip = self._get_selected_ip()
        if ip:
            proto = "https" if https else "http"
            webbrowser.open(f"{proto}://{ip}")

    def action_open_ftp(self):
        ip = self._get_selected_ip()
        if ip:
            webbrowser.open(f"ftp://{ip}")

    def action_open_shares(self, custom_unc=None):
        ip = self._get_selected_ip()
        if not ip:
            return
        unc_path = custom_unc if custom_unc else f"\\\\{ip}"
        if os.name == "nt":
            subprocess.Popen(["explorer", unc_path])
        else:
            messagebox.showinfo("SMB Share", f"Đường dẫn UNC: {unc_path}")

    def action_open_rdp(self):
        ip = self._get_selected_ip()
        if not ip:
            return
        if os.name == "nt":
            subprocess.Popen(["mstsc", f"/v:{ip}"])
        else:
            messagebox.showinfo("RDP", f"Mở trình khách RDP tới: {ip}:3389")

    def action_open_ssh(self):
        ip = self._get_selected_ip()
        if not ip:
            return
        user = simpledialog.askstring("Kết nối SSH", f"Nhập tên người dùng (Username) cho {ip}:", initialvalue="root")
        if user:
            clean_user = re.sub(r"[^a-zA-Z0-9_.-]", "", user)
            if os.name == "nt":
                subprocess.Popen(f'start cmd /k "ssh {clean_user}@{ip}"', shell=True)
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", f"ssh {clean_user}@{ip}"])

    def action_cmd_ping(self):
        ip = self._get_selected_ip()
        if ip and os.name == "nt":
            subprocess.Popen(f'start cmd /k "ping -t {ip}"', shell=True)

    def action_cmd_tracert(self):
        ip = self._get_selected_ip()
        if ip and os.name == "nt":
            subprocess.Popen(f'start cmd /k "tracert {ip}"', shell=True)

    def action_copy_field(self, field):
        ip = self._get_selected_ip()
        if not ip or ip not in self.scan_results:
            return
        val = self.scan_results[ip].get(field, ip)
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self.status_text_var.set(f"Đã sao chép vào Clipboard: {val}")

    def action_wol_selected(self):
        ip = self._get_selected_ip()
        if not ip or ip not in self.scan_results:
            return
        mac = self.scan_results[ip].get("mac", "")
        self.dialog_wake_on_lan(default_mac=mac)

    def dialog_wake_on_lan(self, default_mac=""):
        mac = simpledialog.askstring(
            "Wake-on-LAN (Magic Packet)",
            "Nhập địa chỉ MAC của máy cần bật (VD: 00:11:22:33:44:55):",
            initialvalue=default_mac if ":" in default_mac else ""
        )
        if mac:
            try:
                send_wake_on_lan(mac)
                messagebox.showinfo("Thành công", f"Đã gửi gói tin Magic Packet (Wake-on-LAN) tới MAC: {mac}")
            except Exception as e:
                messagebox.showerror("Lỗi Wake-on-LAN", str(e))

    def action_remote_shutdown(self):
        ip = self._get_selected_ip()
        if not ip:
            return
        confirm = messagebox.askyesno(
            "Xác nhận Tắt máy từ xa",
            f"Bạn có chắc chắn muốn gửi lệnh Shutdown tới máy \\\\{ip} không?\n(Yêu cầu quyền Administrator trên máy đích)"
        )
        if confirm and os.name == "nt":
            subprocess.Popen(
                f'start cmd /k "shutdown /s /m \\\\{ip} /t 30 /c \\"Shutdown initiated by IA IP Scanner\\""',
                shell=True
            )

    # =========================================================================
    # EXPORT REPORTS (CSV, HTML, XML)
    # =========================================================================
    def _get_sorted_results(self):
        return sorted(
            self.scan_results.items(),
            key=lambda item: int(ipaddress.IPv4Address(item[0]))
        )

    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("Chưa có dữ liệu", "Chưa có kết quả quét nào để xuất báo cáo.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Xuất Báo Cáo IA IP Scanner",
            defaultextension=".html",
            initialfile=f"IA_Scan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[
                ("HTML Security Report (*.html)", "*.html"),
                ("CSV Spreadsheet (*.csv)", "*.csv"),
                ("XML Data (*.xml)", "*.xml")
            ]
        )
        if not file_path:
            return

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext == ".csv":
                self._export_csv(file_path)
            elif ext == ".xml":
                self._export_xml(file_path)
            else:
                self._export_html(file_path)
            messagebox.showinfo("Xuất Báo Cáo Thành Công", f"Đã lưu báo cáo tại:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Lỗi Xuất File", str(e))

    def _export_csv(self, path):
        with open(path, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "OS (TTL)", "MAC Address", "Vendor", "Open Ports", "SMB Shares", "RTT"])
            for ip, d in self._get_sorted_results():
                writer.writerow([
                    ip, d["hostname"], d["os"], d["mac"], d["vendor"],
                    "; ".join(map(str, d["open_ports"])),
                    "; ".join(d["shares"]),
                    d["rtt"]
                ])

    def _export_xml(self, path):
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<IAIPScannerReport>']
        for ip, d in self._get_sorted_results():
            ports_str = ",".join(map(str, d["open_ports"]))
            shares_str = ",".join(html.escape(s, quote=True) for s in d["shares"])
            lines.append(
                f'  <Host ip="{html.escape(ip, quote=True)}" '
                f'hostname="{html.escape(d["hostname"], quote=True)}" '
                f'os="{html.escape(d["os"], quote=True)}" '
                f'mac="{html.escape(d["mac"], quote=True)}" '
                f'vendor="{html.escape(d["vendor"], quote=True)}" '
                f'ports="{ports_str}" '
                f'shares="{shares_str}" '
                f'rtt="{html.escape(d["rtt"], quote=True)}" />'
            )
        lines.append('</IAIPScannerReport>')
        with open(path, mode="w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _export_html(self, path):
        rows_html = ""
        for ip, d in self._get_sorted_results():
            ports_badges = " ".join(
                f'<span class="badge">{p} ({html.escape(DEFAULT_PORTS.get(p, "Custom"))})</span>'
                for p in d["open_ports"]
            ) or "None"
            shares_str = ", ".join(html.escape(s) for s in d["shares"]) or "-"
            rows_html += f"""
            <tr>
                <td class="ip">{html.escape(ip)}</td>
                <td>{html.escape(d['hostname'])}</td>
                <td>{html.escape(d['os'])}</td>
                <td class="mac">{html.escape(d['mac'])}</td>
                <td>{html.escape(d['vendor'])}</td>
                <td>{ports_badges}</td>
                <td>{shares_str}</td>
                <td>{html.escape(d['rtt'])}</td>
            </tr>"""

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>IA IP Scanner v2.0 - Security Audit Report</title>
<style>
  body {{ background: #0B0F19; color: #F9FAFB; font-family: 'Segoe UI', sans-serif; padding: 24px; }}
  h1 {{ color: #00E5FF; margin-bottom: 4px; }}
  p.meta {{ color: #9CA3AF; margin-top: 0; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; }}
  th {{ background: #1E293B; color: #00E5FF; text-align: left; padding: 12px; font-size: 13px; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1F2937; font-size: 13px; }}
  tr:hover {{ background: #162032; }}
  .ip {{ color: #10B981; font-weight: bold; font-family: Consolas, monospace; }}
  .mac {{ font-family: Consolas, monospace; color: #F59E0B; }}
  .badge {{ background: #0284C7; color: #FFF; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 4px; display: inline-block; }}
</style>
</head>
<body>
  <h1>🛡️ IA IP SCANNER v2.0 - NETWORK AUDIT REPORT</h1>
  <p class="meta">Thời gian xuất: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Tổng số thiết bị phát hiện: {len(self.scan_results)}</p>
  <table>
    <thead>
      <tr>
        <th>IP Address</th><th>Hostname</th><th>OS / TTL</th><th>MAC Address</th>
        <th>Vendor</th><th>Open Ports</th><th>Shared Folders</th><th>Ping RTT</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
</body>
</html>"""
        with open(path, mode="w", encoding="utf-8") as f:
            f.write(html_content)


if __name__ == "__main__":
    root = tk.Tk()
    app = IAIPScannerApp(root)
    root.mainloop()
