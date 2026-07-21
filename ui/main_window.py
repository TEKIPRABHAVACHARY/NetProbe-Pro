"""
NETPROBE PRO  –  main_window.py
Full-featured Nmap-style port scanner UI.

New in this version
───────────────────
• Rich table: #  PORT  NAME  STATE  SERVICE  PROTOCOL  RISK
• Colour-coded RISK badges  (Critical / High / Medium / Low / Info)
• Filter bar  – live search by port / service / state
• Show-Only-Open toggle
• Export  → CSV  and  TXT (nmap-style)
• Copy selected row to clipboard
• Scan-summary side panel (open / closed / filtered / elapsed time)
• Scan-speed slider (threads)
• Port-range custom input
• Right-click context menu on rows
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import tkinter as tk
import threading
import time
import csv
import io
import sys
import os
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.scanner import NetProbeScanner
from core.utils import get_local_ip

# ══════════════════════════════════════════════════════════
#  PALETTE
# ══════════════════════════════════════════════════════════
C_BG        = "#0d1117"
C_PANEL     = "#161b22"
C_PANEL2    = "#1c2128"
C_BORDER    = "#30363d"
C_ACCENT    = "#0f3460"
C_ACCENT2   = "#1a4a7a"
C_OPEN      = "#00ff88"
C_CLOSED    = "#ff4d4d"
C_PORT      = "#58a6ff"
C_SERVICE   = "#c9d1d9"
C_SUBTEXT   = "#8b949e"
C_HEADER    = "#00d4ff"
C_EVEN      = "#161b22"
C_ODD       = "#1c2128"
C_GREEN_BTN = "#10ac84"
C_RED_BTN   = "#e74c3c"
C_ORG_BTN   = "#f39c12"
C_BLUE_BTN  = "#2563eb"
C_PURPLE    = "#7c3aed"
FONT_MONO   = "Courier New"
FONT_UI     = "Segoe UI"

# Risk colours
RISK_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
    "INFO":     "#636e72",
}

# ── Known-port database ──────────────────────────────────
# (port → (name, risk_level, description))
PORT_DB = {
    20:   ("FTP-DATA",  "HIGH",     "FTP data transfer"),
    21:   ("FTP",       "HIGH",     "File Transfer Protocol"),
    22:   ("SSH",       "LOW",      "Secure Shell"),
    23:   ("TELNET",    "CRITICAL", "Unencrypted remote login"),
    25:   ("SMTP",      "MEDIUM",   "Mail transfer"),
    53:   ("DNS",       "MEDIUM",   "Domain Name System"),
    67:   ("DHCP",      "MEDIUM",   "Dynamic Host Config"),
    68:   ("DHCP",      "MEDIUM",   "Dynamic Host Config client"),
    69:   ("TFTP",      "HIGH",     "Trivial File Transfer"),
    80:   ("HTTP",      "MEDIUM",   "Unencrypted web server"),
    110:  ("POP3",      "HIGH",     "Post Office Protocol v3"),
    111:  ("RPCBIND",   "HIGH",     "RPC port mapper"),
    119:  ("NNTP",      "MEDIUM",   "Network News Transfer"),
    123:  ("NTP",       "LOW",      "Network Time Protocol"),
    135:  ("MSRPC",     "HIGH",     "Microsoft RPC"),
    137:  ("NETBIOS",   "HIGH",     "NetBIOS Name Service"),
    138:  ("NETBIOS",   "HIGH",     "NetBIOS Datagram"),
    139:  ("NETBIOS",   "HIGH",     "NetBIOS Session"),
    143:  ("IMAP",      "MEDIUM",   "Internet Message Access"),
    161:  ("SNMP",      "HIGH",     "Network Management"),
    194:  ("IRC",       "MEDIUM",   "Internet Relay Chat"),
    389:  ("LDAP",      "MEDIUM",   "Directory Access Protocol"),
    443:  ("HTTPS",     "LOW",      "Encrypted web server"),
    445:  ("SMB",       "CRITICAL", "Windows file sharing"),
    465:  ("SMTPS",     "LOW",      "Encrypted SMTP"),
    500:  ("ISAKMP",    "MEDIUM",   "VPN key exchange"),
    514:  ("SYSLOG",    "MEDIUM",   "System logging"),
    515:  ("LPD",       "MEDIUM",   "Line Printer Daemon"),
    587:  ("SUBMISSION","LOW",      "Mail submission"),
    631:  ("IPP",       "MEDIUM",   "Internet Printing Protocol"),
    636:  ("LDAPS",     "LOW",      "Encrypted LDAP"),
    993:  ("IMAPS",     "LOW",      "Encrypted IMAP"),
    995:  ("POP3S",     "LOW",      "Encrypted POP3"),
    1080: ("SOCKS",     "HIGH",     "SOCKS proxy"),
    1194: ("OPENVPN",   "LOW",      "OpenVPN"),
    1433: ("MSSQL",     "HIGH",     "Microsoft SQL Server"),
    1521: ("ORACLE",    "HIGH",     "Oracle Database"),
    1723: ("PPTP",      "MEDIUM",   "Point-to-Point Tunneling"),
    2049: ("NFS",       "HIGH",     "Network File System"),
    2181: ("ZOOKEEPER", "HIGH",     "Apache ZooKeeper"),
    2375: ("DOCKER",    "CRITICAL", "Docker daemon (unencrypted)"),
    2376: ("DOCKER-TLS","MEDIUM",   "Docker daemon (TLS)"),
    3000: ("DEV-HTTP",  "MEDIUM",   "Common dev server port"),
    3306: ("MYSQL",     "HIGH",     "MySQL Database"),
    3389: ("RDP",       "HIGH",     "Remote Desktop Protocol"),
    4444: ("METASPLOIT","CRITICAL", "Common backdoor port"),
    5000: ("DEV-HTTP",  "MEDIUM",   "Flask / dev server"),
    5432: ("POSTGRES",  "HIGH",     "PostgreSQL Database"),
    5900: ("VNC",       "HIGH",     "Virtual Network Computing"),
    5985: ("WINRM",     "HIGH",     "Windows Remote Management"),
    6379: ("REDIS",     "HIGH",     "Redis (often unauthenticated)"),
    6443: ("K8S-API",   "HIGH",     "Kubernetes API server"),
    8080: ("HTTP-ALT",  "MEDIUM",   "Alternate HTTP / proxy"),
    8443: ("HTTPS-ALT", "LOW",      "Alternate HTTPS"),
    8888: ("JUPYTER",   "HIGH",     "Jupyter Notebook"),
    9000: ("PHP-FPM",   "MEDIUM",   "PHP FastCGI / SonarQube"),
    9090: ("PROMETHEUS","MEDIUM",   "Prometheus metrics"),
    9200: ("ELASTIC",   "HIGH",     "Elasticsearch HTTP"),
    9300: ("ELASTIC",   "HIGH",     "Elasticsearch transport"),
    27017:("MONGODB",   "HIGH",     "MongoDB (often unauthenticated)"),
}

def port_info(port: int, service: str):
    """Return (name, risk, description) for a port number."""
    if port in PORT_DB:
        return PORT_DB[port]
    svc = (service or "").upper().strip("-").strip()
    if svc:
        return svc, "INFO", f"Port {port}"
    return f"PORT-{port}", "INFO", f"Unknown service on port {port}"


# ══════════════════════════════════════════════════════════
#  RICH NMAP TABLE
# ══════════════════════════════════════════════════════════
class NmapTable(ctk.CTkFrame):
    ROW_H = 38
    PX    = 10

    # (header_label, pixel_width, anchor, stretch)
    COLUMNS = [
        ("#",         46,  "center", False),
        ("PORT",     100,  "center", False),
        ("NAME",     130,  "center", False),
        ("STATE",    115,  "center", False),
        ("SERVICE",  190,  "w",      False),
        ("PROTOCOL",  95,  "center", False),
        ("RISK",     110,  "center", False),
        ("DESCRIPTION", 0, "w",     True),   # stretches
    ]

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C_BG, corner_radius=0, **kwargs)
        self._all_rows  = []   # list of (row_frame, meta_dict)
        self._row_count = 0
        self._filter_text  = ""
        self._only_open    = False
        self._selected_row = None
        self._build()

    # ── build ──────────────────────────────────────────────
    def _build(self):
        # sticky header
        hdr = tk.Frame(self, bg=C_ACCENT2, height=42)
        hdr.pack(fill='x', side='top')
        hdr.pack_propagate(False)

        for label, width, anchor, stretch in self.COLUMNS:
            kw = dict(bg=C_ACCENT2, fg=C_HEADER,
                      font=(FONT_MONO, 13, "bold"),
                      text=label, anchor=anchor)
            if width:
                kw["width"] = width
            lbl = tk.Label(hdr, **kw)
            if stretch:
                lbl.pack(side='left', padx=self.PX, pady=8,
                         fill='x', expand=True)
            else:
                lbl.pack(side='left', padx=self.PX, pady=8)

        # scrollable canvas body
        body = tk.Frame(self, bg=C_BG)
        body.pack(fill='both', expand=True)

        self._canvas = tk.Canvas(body, bg=C_BG,
                                 highlightthickness=0, bd=0)
        self._vbar = ctk.CTkScrollbar(
            body, orientation="vertical",
            command=self._canvas.yview,
            button_color="#2a2a4a",
            button_hover_color="#3a3a6a")
        self._vbar.pack(side='right', fill='y')
        self._canvas.pack(side='left', fill='both', expand=True)
        self._canvas.configure(yscrollcommand=self._vbar.set)

        self._inner = tk.Frame(self._canvas, bg=C_BG)
        self._win   = self._canvas.create_window(
            (0, 0), window=self._inner, anchor='nw')

        self._canvas.bind('<Configure>', lambda e: self._canvas.itemconfig(
            self._win, width=e.width))
        self._inner.bind('<Configure>',  lambda e: self._canvas.configure(
            scrollregion=self._canvas.bbox('all')))
        self._canvas.bind_all('<MouseWheel>', self._wheel)
        self._canvas.bind_all('<Button-4>',   self._wheel)
        self._canvas.bind_all('<Button-5>',   self._wheel)

    def _wheel(self, e):
        if e.num == 4:   self._canvas.yview_scroll(-1, 'units')
        elif e.num == 5: self._canvas.yview_scroll( 1, 'units')
        else:            self._canvas.yview_scroll(int(-e.delta/120), 'units')

    # ── add row ────────────────────────────────────────────
    def add_port(self, seq, port_str, state, service,
                 name, risk, description, protocol="tcp"):
        bg = C_EVEN if self._row_count % 2 == 0 else C_ODD

        row = tk.Frame(self._inner, bg=bg, height=self.ROW_H)
        row.pack(fill='x')
        row.pack_propagate(False)

        state_color = C_OPEN   if state.upper() == "OPEN" else C_CLOSED
        state_icon  = "●"      if state.upper() == "OPEN" else "○"
        risk_color  = RISK_COLORS.get(risk.upper(), RISK_COLORS["INFO"])

        cells = [
            (str(seq),                   C_SUBTEXT,   46,  "center"),
            (port_str,                   C_PORT,     100,  "center"),
            (name,                       "#e8c46e",  130,  "center"),
            (f"{state_icon} {state}",    state_color, 115,  "center"),
            (service or "—",             C_SERVICE,  190,  "w"),
            (protocol.upper(),           "#a78bfa",   95,  "center"),
            (risk,                       risk_color, 110,  "center"),
            (description,                C_SUBTEXT,    0,  "w"),
        ]

        for i, (text, color, width, anchor) in enumerate(cells):
            stretch = (width == 0)
            kw = dict(bg=bg, fg=color,
                      font=(FONT_MONO, 12),
                      text=text, anchor=anchor)
            if width:
                kw["width"] = width
            lbl = tk.Label(row, **kw)
            if stretch:
                lbl.pack(side='left', padx=self.PX, pady=4,
                         fill='x', expand=True)
            else:
                lbl.pack(side='left', padx=(self.PX, 0), pady=4)

        meta = dict(seq=seq, port_str=port_str, state=state,
                    service=service, name=name, risk=risk,
                    description=description, protocol=protocol)
        self._all_rows.append((row, meta))
        self._row_count += 1

        # bind click + right-click
        def on_click(e, r=row, m=meta):
            self._select(r, m)
        def on_right(e, r=row, m=meta):
            self._select(r, m)
            self._show_context(e, m)

        for w in row.winfo_children():
            w.bind('<Button-1>', on_click)
            w.bind('<Button-3>', on_right)
        row.bind('<Button-1>', on_click)
        row.bind('<Button-3>', on_right)

        # apply current filter
        self._apply_visibility(row, meta)

        self._canvas.update_idletasks()
        self._canvas.yview_moveto(1.0)

    def _select(self, row_frame, meta):
        if self._selected_row:
            try:
                self._selected_row.configure(bg=C_EVEN
                    if int(self._selected_row.winfo_name()[-1]) % 2 == 0
                    else C_ODD)
            except Exception:
                pass
        self._selected_row = row_frame
        row_frame.configure(bg="#1e3a5f")
        for ch in row_frame.winfo_children():
            try:
                ch.configure(bg="#1e3a5f")
            except Exception:
                pass

    def _show_context(self, event, meta):
        menu = tk.Menu(self._canvas, tearoff=0,
                       bg=C_PANEL2, fg=C_SERVICE,
                       activebackground=C_ACCENT2,
                       activeforeground="white",
                       font=(FONT_UI, 12))
        menu.add_command(
            label="📋  Copy Row",
            command=lambda: self._copy_row(meta))
        menu.add_command(
            label="🔍  Copy Port",
            command=lambda: self._copy_text(meta['port_str']))
        menu.add_separator()
        menu.add_command(
            label="🌐  Lookup on IANA",
            command=lambda: self._open_url(
                f"https://www.iana.org/assignments/service-names-port-numbers/"
                f"service-names-port-numbers.xhtml?search={meta['port_str'].split('/')[0]}"))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_row(self, meta):
        line = (f"{meta['port_str']:<12} {meta['state']:<8} "
                f"{meta['name']:<14} {meta['service']:<20} "
                f"{meta['protocol']:<6} {meta['risk']:<10} "
                f"{meta['description']}")
        self._copy_text(line)

    def _copy_text(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _open_url(self, url):
        import webbrowser
        webbrowser.open(url)

    # ── filtering ──────────────────────────────────────────
    def _apply_visibility(self, row, meta):
        show = True
        if self._only_open and meta['state'].upper() != 'OPEN':
            show = False
        if self._filter_text:
            q = self._filter_text.lower()
            haystack = (f"{meta['port_str']} {meta['name']} "
                        f"{meta['state']} {meta['service']} "
                        f"{meta['risk']} {meta['description']}").lower()
            if q not in haystack:
                show = False
        if show:
            row.pack(fill='x')
        else:
            row.pack_forget()

    def apply_filter(self, text: str, only_open: bool):
        self._filter_text = text.strip()
        self._only_open   = only_open
        for row, meta in self._all_rows:
            self._apply_visibility(row, meta)
        self._canvas.update_idletasks()
        self._canvas.configure(scrollregion=self._canvas.bbox('all'))

    # ── clear ──────────────────────────────────────────────
    def clear(self):
        for w in self._inner.winfo_children():
            w.destroy()
        self._all_rows  = []
        self._row_count = 0
        self._selected_row = None

    # ── export helpers ─────────────────────────────────────
    def get_all_rows(self):
        return [m for _, m in self._all_rows]


# ══════════════════════════════════════════════════════════
#  PROGRESS STRIP
# ══════════════════════════════════════════════════════════
class LiveProgress(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C_PANEL,
                         corner_radius=0, **kwargs)
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill='x', padx=20, pady=(8, 4))

        self.stats = ctk.CTkLabel(
            top, text="Ready to scan",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_SUBTEXT)
        self.stats.pack(side='left')

        self.elapsed = ctk.CTkLabel(
            top, text="",
            font=ctk.CTkFont(family=FONT_MONO, size=13),
            text_color=C_SUBTEXT)
        self.elapsed.pack(side='right', padx=(0, 16))

        self.pct = ctk.CTkLabel(
            top, text="0%",
            font=ctk.CTkFont(family=FONT_MONO, size=13, weight="bold"),
            text_color=C_OPEN)
        self.pct.pack(side='right')

        self.bar = ctk.CTkProgressBar(
            self, height=8, progress_color=C_OPEN, corner_radius=4)
        self.bar.pack(fill='x', padx=20, pady=(0, 8))
        self.bar.set(0)


# ══════════════════════════════════════════════════════════
#  SUMMARY PANEL
# ══════════════════════════════════════════════════════════
class SummaryPanel(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=C_PANEL2,
                         corner_radius=8, **kwargs)
        ctk.CTkLabel(self, text="SCAN SUMMARY",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=C_HEADER).pack(pady=(12, 6), padx=16)

        self._items = {}
        rows = [
            ("target",   "Target",    "—"),
            ("mode",     "Mode",      "—"),
            ("total",    "Total",     "0"),
            ("open",     "Open",      "0",  C_OPEN),
            ("closed",   "Closed",    "0",  C_CLOSED),
            ("filtered", "Filtered",  "0"),
            ("elapsed",  "Elapsed",   "0s"),
            ("speed",    "Rate",      "0 p/s"),
            ("risk_c",   "Critical",  "0",  RISK_COLORS["CRITICAL"]),
            ("risk_h",   "High",      "0",  RISK_COLORS["HIGH"]),
            ("risk_m",   "Medium",    "0",  RISK_COLORS["MEDIUM"]),
        ]

        sep = tk.Frame(self, bg=C_BORDER, height=1)
        sep.pack(fill='x', padx=10, pady=4)

        for key, label, default, *color in rows:
            fc = color[0] if color else C_SERVICE
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill='x', padx=12, pady=2)
            ctk.CTkLabel(row, text=label + ":",
                         font=ctk.CTkFont(size=12),
                         text_color=C_SUBTEXT,
                         anchor='w', width=70).pack(side='left')
            val = ctk.CTkLabel(row, text=default,
                               font=ctk.CTkFont(family=FONT_MONO,
                                                size=12, weight="bold"),
                               text_color=fc, anchor='w')
            val.pack(side='left')
            self._items[key] = val

    def update(self, **kw):
        for k, v in kw.items():
            if k in self._items:
                self._items[k].configure(text=str(v))


# ══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════
class NetProbeWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NETPROBE PRO")
        self.configure(fg_color=C_BG)

        try:
            self.state('zoomed')
        except Exception:
            try:
                self.attributes('-zoomed', True)
            except Exception:
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                self.geometry(f"{sw}x{sh}+0+0")
        self.resizable(True, True)

        # state
        self.scanner       = NetProbeScanner()
        self.is_scanning   = False
        self.open_count    = 0
        self.closed_count  = 0
        self.total_ports   = 0
        self.scan_results  = []
        self._rows_added   = 0
        self._risk_counts  = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        self._start_time   = None
        self._elapsed_job  = None

        self._build_ui()

    # ══════════════════════════════════════════════════════
    #  ROOT LAYOUT  (grid)
    # ══════════════════════════════════════════════════════
    def _build_ui(self):
        # rows: 0=header 1=controls 2=filter 3=progress 4=body 5=statusbar
        for r, w in enumerate([0, 0, 0, 0, 1, 0]):
            self.grid_rowconfigure(r, weight=w)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_controls()
        self._build_filter_bar()
        self._build_progress()
        self._build_body()       # table + summary side-panel
        self._build_statusbar()

    # ── HEADER ─────────────────────────────────────────────
    def _build_header(self):
        f = ctk.CTkFrame(self, fg_color=C_PANEL, corner_radius=0)
        f.grid(row=0, column=0, sticky='ew')

        inner = ctk.CTkFrame(f, fg_color="transparent")
        inner.pack(side='left', pady=10, padx=20)

        try:
            lp = os.path.join(os.path.dirname(__file__), "../assets/logo.png")
            if os.path.exists(lp):
                img = ctk.CTkImage(Image.open(lp), size=(36, 36))
                ctk.CTkLabel(inner, image=img, text="").pack(
                    side='left', padx=(0, 10))
            else:
                raise FileNotFoundError
        except Exception:
            ctk.CTkLabel(inner, text="🛡️",
                         font=ctk.CTkFont(size=28)).pack(
                side='left', padx=(0, 10))

        ctk.CTkLabel(inner, text="NETPROBE PRO",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(side='left')
        ctk.CTkLabel(inner, text="  |  Advanced Network Scanner",
                     font=ctk.CTkFont(size=13), text_color=C_SUBTEXT
                     ).pack(side='left', pady=(3, 0))

        right = ctk.CTkFrame(f, fg_color="transparent")
        right.pack(side='right', padx=20)

        self.theme_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(right, text="Dark Mode",
                      variable=self.theme_var,
                      command=self._toggle_theme,
                      font=ctk.CTkFont(size=13)
                      ).pack(side='right', pady=10)

    # ── CONTROLS ───────────────────────────────────────────
    def _build_controls(self):
        f = ctk.CTkFrame(self, fg_color=C_PANEL, corner_radius=0)
        f.grid(row=1, column=0, sticky='ew', pady=(2, 0))
        f.grid_columnconfigure(1, weight=3)
        f.grid_columnconfigure(3, weight=1)

        # Target
        ctk.CTkLabel(f, text="Target",
                     font=ctk.CTkFont(size=14, weight="bold")
                     ).grid(row=0, column=0, padx=(16,6), pady=12, sticky='w')
        self.target = ctk.CTkEntry(
            f, height=40, font=ctk.CTkFont(size=14),
            placeholder_text="127.0.0.1  or  scanme.nmap.org",
            fg_color=C_BG, border_color=C_BORDER)
        self.target.grid(row=0, column=1, padx=6, pady=12, sticky='ew')
        self.target.insert(0, "127.0.0.1")

        # Mode
        ctk.CTkLabel(f, text="Mode",
                     font=ctk.CTkFont(size=14, weight="bold")
                     ).grid(row=0, column=2, padx=(12,6), pady=12, sticky='w')
        self.scan_mode = ctk.CTkOptionMenu(
            f, values=["Quick (1-1024)", "Top 100",
                       "Intense (1-10K)", "ALL PORTS (65,535)",
                       "Custom Range"],
            height=40, font=ctk.CTkFont(size=13),
            fg_color=C_BG, button_color=C_ACCENT,
            command=self._on_mode_change)
        self.scan_mode.grid(row=0, column=3, padx=6, pady=12, sticky='ew')
        self.scan_mode.set("Quick (1-1024)")

        # Custom range entry (hidden by default)
        self.custom_range = ctk.CTkEntry(
            f, height=40, font=ctk.CTkFont(size=13),
            placeholder_text="e.g. 8000-9000",
            fg_color=C_BG, border_color=C_BORDER, width=140)
        # will be grid'd when needed

        # Threads slider
        ctk.CTkLabel(f, text="Threads",
                     font=ctk.CTkFont(size=13), text_color=C_SUBTEXT
                     ).grid(row=0, column=4, padx=(10,4), pady=12, sticky='w')
        self.threads_var = ctk.IntVar(value=100)
        self.threads_slider = ctk.CTkSlider(
            f, from_=10, to=500, variable=self.threads_var,
            width=120, button_color=C_OPEN, progress_color=C_ACCENT)
        self.threads_slider.grid(row=0, column=5, padx=4, pady=12)
        self.threads_lbl = ctk.CTkLabel(
            f, textvariable=self.threads_var,
            font=ctk.CTkFont(family=FONT_MONO, size=13),
            text_color=C_OPEN, width=38)
        self.threads_lbl.grid(row=0, column=6, padx=(0, 8), pady=12)

        # Buttons
        self.start_btn = ctk.CTkButton(
            f, text="▶  SCAN", command=self.start_scan,
            height=40, width=115,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=C_GREEN_BTN, hover_color="#0e9270")
        self.start_btn.grid(row=0, column=7, padx=5, pady=12)

        self.stop_btn = ctk.CTkButton(
            f, text="■  STOP", command=self.stop_scan,
            height=40, width=100, state="disabled",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=C_RED_BTN, hover_color="#c0392b")
        self.stop_btn.grid(row=0, column=8, padx=5, pady=12)

        self.clear_btn = ctk.CTkButton(
            f, text="✕  CLEAR", command=self.clear_all,
            height=40, width=100,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=C_ORG_BTN, hover_color="#d68910")
        self.clear_btn.grid(row=0, column=9, padx=5, pady=12)

        # Export buttons
        self.export_csv_btn = ctk.CTkButton(
            f, text="⬇ CSV", command=self.export_csv,
            height=40, width=85,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C_BLUE_BTN, hover_color="#1d4ed8")
        self.export_csv_btn.grid(row=0, column=10, padx=5, pady=12)

        self.export_txt_btn = ctk.CTkButton(
            f, text="⬇ TXT", command=self.export_txt,
            height=40, width=85,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C_PURPLE, hover_color="#6d28d9")
        self.export_txt_btn.grid(row=0, column=11, padx=(5, 16), pady=12)

        # Status line
        self.status_lbl = ctk.CTkLabel(
            f, text=f"  Local IP: {get_local_ip()}   |   Ready",
            font=ctk.CTkFont(size=12), text_color=C_SUBTEXT, anchor='w')
        self.status_lbl.grid(row=1, column=0, columnspan=12,
                             padx=16, pady=(0, 6), sticky='ew')

    def _on_mode_change(self, val):
        if val == "Custom Range":
            self.custom_range.grid(row=0, column=12, padx=6, pady=12)
        else:
            self.custom_range.grid_remove()

    # ── FILTER BAR ─────────────────────────────────────────
    def _build_filter_bar(self):
        f = ctk.CTkFrame(self, fg_color=C_PANEL2, corner_radius=0)
        f.grid(row=2, column=0, sticky='ew', pady=(2, 0))

        ctk.CTkLabel(f, text="🔍  Filter:",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=C_SUBTEXT).pack(side='left', padx=(16, 6), pady=8)

        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add('write', self._on_filter_change)
        self.filter_entry = ctk.CTkEntry(
            f, textvariable=self.filter_var,
            height=34, width=280,
            font=ctk.CTkFont(size=13),
            placeholder_text="port / name / service / risk …",
            fg_color=C_BG, border_color=C_BORDER)
        self.filter_entry.pack(side='left', padx=6, pady=8)

        # quick filter buttons
        for label, q in [("OPEN only","open"), ("CRITICAL","critical"),
                          ("HIGH","high"), ("MEDIUM","medium")]:
            ctk.CTkButton(
                f, text=label, height=30, width=90,
                font=ctk.CTkFont(size=12),
                fg_color=C_ACCENT, hover_color=C_ACCENT2,
                command=lambda q=q: self._quick_filter(q)
            ).pack(side='left', padx=4, pady=8)

        ctk.CTkButton(
            f, text="Clear Filter", height=30, width=90,
            font=ctk.CTkFont(size=12),
            fg_color=C_PANEL, hover_color=C_BORDER,
            command=self._clear_filter
        ).pack(side='left', padx=4, pady=8)

        self.only_open_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            f, text="Show open only",
            variable=self.only_open_var,
            command=self._on_filter_change,
            font=ctk.CTkFont(size=13),
            text_color=C_SUBTEXT,
            checkbox_width=18, checkbox_height=18,
            checkmark_color=C_OPEN, border_color=C_BORDER
        ).pack(side='left', padx=16, pady=8)

        self.filtered_lbl = ctk.CTkLabel(
            f, text="Showing all results",
            font=ctk.CTkFont(size=12), text_color=C_SUBTEXT)
        self.filtered_lbl.pack(side='right', padx=16, pady=8)

    def _on_filter_change(self, *_):
        self._apply_filter()

    def _quick_filter(self, q):
        self.filter_var.set(q)

    def _clear_filter(self):
        self.filter_var.set("")
        self.only_open_var.set(False)
        self._apply_filter()

    def _apply_filter(self):
        q    = self.filter_var.get()
        only = self.only_open_var.get()
        self.nmap_table.apply_filter(q, only)
        visible = sum(
            1 for _, m in self.nmap_table._all_rows
            if self._row_visible(m, q, only))
        total = len(self.nmap_table._all_rows)
        self.filtered_lbl.configure(
            text=f"Showing {visible} / {total} results")
        self.summary.update(filtered=total - visible)

    def _row_visible(self, meta, q, only):
        if only and meta['state'].upper() != 'OPEN':
            return False
        if q:
            hay = (f"{meta['port_str']} {meta['name']} {meta['state']} "
                   f"{meta['service']} {meta['risk']} {meta['description']}").lower()
            if q.lower() not in hay:
                return False
        return True

    # ── PROGRESS ───────────────────────────────────────────
    def _build_progress(self):
        self.live_progress = LiveProgress(self)
        self.live_progress.grid(row=3, column=0, sticky='ew', pady=(2, 0))

    # ── BODY  (table + summary) ────────────────────────────
    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=C_BG, corner_radius=0)
        body.grid(row=4, column=0, sticky='nsew', pady=(2, 0))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=0)

        # table area
        table_outer = ctk.CTkFrame(body, fg_color=C_PANEL, corner_radius=0)
        table_outer.grid(row=0, column=0, sticky='nsew')
        table_outer.grid_rowconfigure(1, weight=1)
        table_outer.grid_columnconfigure(0, weight=1)

        # table title bar
        tbar = tk.Frame(table_outer, bg=C_ACCENT, height=34)
        tbar.grid(row=0, column=0, sticky='ew')
        tbar.grid_propagate(False)
        tk.Label(tbar, text="  SCAN RESULTS  —  PORT  NAME  STATE  SERVICE  PROTOCOL  RISK  DESCRIPTION",
                 bg=C_ACCENT, fg=C_HEADER,
                 font=(FONT_MONO, 12, "bold"), anchor='w'
                 ).pack(side='left', padx=8, fill='y')
        self.result_count_lbl = tk.Label(
            tbar, text="0 ports",
            bg=C_ACCENT, fg=C_SUBTEXT,
            font=(FONT_MONO, 11))
        self.result_count_lbl.pack(side='right', padx=12)

        self.nmap_table = NmapTable(table_outer)
        self.nmap_table.grid(row=1, column=0, sticky='nsew')

        # summary panel (right side)
        self.summary = SummaryPanel(body, width=200)
        self.summary.grid(row=0, column=1, sticky='ns',
                          padx=(4, 0), pady=0)
        self.summary.grid_propagate(False)
        self.summary.configure(width=210)

    # ── STATUS BAR ─────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=C_PANEL,
                           corner_radius=0, height=40)
        bar.grid(row=5, column=0, sticky='ew', pady=(2, 0))
        bar.grid_propagate(False)

        self.open_lbl = ctk.CTkLabel(
            bar, text="● OPEN: 0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_OPEN)
        self.open_lbl.pack(side='left', padx=20, pady=6)

        self.closed_lbl = ctk.CTkLabel(
            bar, text="○ CLOSED: 0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_CLOSED)
        self.closed_lbl.pack(side='left', padx=8, pady=6)

        # risk pills
        self._risk_lbls = {}
        for risk, color in RISK_COLORS.items():
            if risk == "INFO":
                continue
            lbl = ctk.CTkLabel(
                bar, text=f"{risk}: 0",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=color)
            lbl.pack(side='left', padx=10, pady=6)
            self._risk_lbls[risk] = lbl

        self.scan_status_lbl = ctk.CTkLabel(
            bar, text="Idle",
            font=ctk.CTkFont(size=13),
            text_color=C_SUBTEXT)
        self.scan_status_lbl.pack(side='right', padx=20, pady=6)

    # ── THEME ──────────────────────────────────────────────
    def _toggle_theme(self):
        ctk.set_appearance_mode(
            "dark" if self.theme_var.get() else "light")

    # ── FORMAT ─────────────────────────────────────────────
    @staticmethod
    def _fmt(port, status, service):
        name, risk, desc = port_info(port, service)
        return (
            f"{port}/tcp",
            "OPEN"   if status == "OPEN" else "CLOSED",
            service  if service not in ("-", "", None) else "—",
            name, risk, desc,
        )

    # ── ELAPSED TIMER ─────────────────────────────────────
    def _tick(self):
        if self._start_time is None:
            return
        elapsed = time.time() - self._start_time
        m, s = divmod(int(elapsed), 60)
        ts = f"{m}m {s}s" if m else f"{s}s"
        self.live_progress.elapsed.configure(text=f"⏱ {ts}")
        self.summary.update(elapsed=ts)

        if self.is_scanning:
            total = self._rows_added
            rate  = total / elapsed if elapsed > 0 else 0
            self.summary.update(speed=f"{rate:.0f} p/s")
            self._elapsed_job = self.after(1000, self._tick)

    # ── THREAD-SAFE UPDATE ─────────────────────────────────
    def update_ui_threadsafe(self, result, progress, current, total):
        self.after(0, lambda r=result, p=progress, c=current, t=total:
                   self._update_ui(r, p, c, t))

    def _update_ui(self, result, progress, current, total):
        pct = int(progress * 100)

        self.live_progress.bar.set(progress)
        self.live_progress.pct.configure(text=f"{pct}%")
        self.live_progress.stats.configure(
            text=(f"Port {result['port']}/tcp   "
                  f"{current:,} / {self.total_ports:,}   "
                  f"{result['status']}"))

        port_str, state, service, name, risk, desc = self._fmt(
            result['port'], result['status'], result['service'])

        self.nmap_table.add_port(
            self._rows_added + 1,
            port_str, state, service, name, risk, desc)
        self._rows_added += 1

        if result['status'] == 'OPEN':
            self.open_count += 1
            r = risk.upper()
            self._risk_counts[r] = self._risk_counts.get(r, 0) + 1
            for rk, lbl in self._risk_lbls.items():
                lbl.configure(text=f"{rk}: {self._risk_counts.get(rk,0)}")
            self.summary.update(
                risk_c=self._risk_counts.get("CRITICAL",0),
                risk_h=self._risk_counts.get("HIGH",0),
                risk_m=self._risk_counts.get("MEDIUM",0),
            )
        else:
            self.closed_count += 1
        self.scan_results.append(result)

        self.open_lbl.configure(text=f"● OPEN: {self.open_count}")
        self.closed_lbl.configure(text=f"○ CLOSED: {self.closed_count}")
        self.result_count_lbl.configure(
            text=f"{self._rows_added:,} ports")
        self.status_lbl.configure(
            text=(f"  Scanning  {self.target.get()}"
                  f"   |   Open: {self.open_count}"
                  f"   |   {current:,}/{self.total_ports:,}  ({pct}%)"))
        self.scan_status_lbl.configure(
            text=f"{current:,} / {self.total_ports:,}  ({pct}%)")
        self.summary.update(
            open=self.open_count,
            closed=self.closed_count,
            total=self._rows_added)

        # re-apply filter so new rows obey current filter
        self._apply_filter()

    # ── SCAN CONTROLS ──────────────────────────────────────
    def start_scan(self):
        if self.is_scanning:
            return
        target = self.target.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter a target IP or hostname!")
            return

        self.is_scanning  = True
        self.open_count   = 0
        self.closed_count = 0
        self.scan_results = []
        self._rows_added  = 0
        self._risk_counts = {k: 0 for k in self._risk_counts}
        self._start_time  = time.time()

        self.start_btn.configure(state="disabled", text="⏳  SCANNING…")
        self.stop_btn.configure(state="normal")
        self.clear_all(keep_target=True)

        mode = self.scan_mode.get()
        if mode == "Custom Range":
            ports = self.scanner.parse_custom_range(
                self.custom_range.get())
        else:
            ports = self.scanner.get_port_list(mode)
        self.total_ports = len(ports)

        self.summary.update(
            target=target, mode=mode,
            total=self.total_ports)
        self.status_lbl.configure(
            text=(f"  Nmap-style scan  →  {target}"
                  f"   |   {self.total_ports:,} ports queued"))

        self._tick()

        threading.Thread(
            target=lambda: self.scanner.scan_with_callback(
                target, ports, self.update_ui_threadsafe),
            daemon=True,
        ).start()

    def stop_scan(self):
        try:
            self.scanner.stop()
        except AttributeError:
            pass
        self.is_scanning = False
        self._start_time = None
        self.start_btn.configure(state="normal", text="▶  SCAN")
        self.stop_btn.configure(state="disabled")
        self.scan_status_lbl.configure(text="Stopped")
        self.status_lbl.configure(
            text=f"  Scan stopped   |   Open: {self.open_count}")

    def clear_all(self, keep_target=False):
        self.nmap_table.clear()
        self.scanner       = NetProbeScanner()
        self.open_count    = 0
        self.closed_count  = 0
        self.scan_results  = []
        self._rows_added   = 0
        self._risk_counts  = {k: 0 for k in self._risk_counts}
        self._start_time   = None

        self.live_progress.bar.set(0)
        self.live_progress.stats.configure(text="Ready to scan")
        self.live_progress.pct.configure(text="0%")
        self.live_progress.elapsed.configure(text="")
        self.open_lbl.configure(text="● OPEN: 0")
        self.closed_lbl.configure(text="○ CLOSED: 0")
        for rk, lbl in self._risk_lbls.items():
            lbl.configure(text=f"{rk}: 0")
        self.result_count_lbl.configure(text="0 ports")
        self.status_lbl.configure(
            text=f"  Local IP: {get_local_ip()}   |   Ready")
        self.scan_status_lbl.configure(text="Idle")
        self.filtered_lbl.configure(text="Showing all results")
        self.summary.update(open=0, closed=0, total=0, filtered=0,
                            elapsed="0s", speed="0 p/s",
                            risk_c=0, risk_h=0, risk_m=0)

        if not keep_target:
            self.start_btn.configure(state="normal", text="▶  SCAN")
            self.stop_btn.configure(state="disabled")

    # ── EXPORT ─────────────────────────────────────────────
    def export_csv(self):
        rows = self.nmap_table.get_all_rows()
        if not rows:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"netprobe_{self.target.get().replace('.','_')}.csv")
        if not path:
            return
        with open(path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=[
                'seq','port_str','name','state','service',
                'protocol','risk','description'])
            w.writeheader()
            w.writerows(rows)
        messagebox.showinfo("Export", f"Saved {len(rows)} rows to:\n{path}")

    def export_txt(self):
        rows = self.nmap_table.get_all_rows()
        if not rows:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"netprobe_{self.target.get().replace('.','_')}.txt")
        if not path:
            return
        with open(path, 'w') as f:
            f.write(f"NETPROBE PRO  –  Scan report for {self.target.get()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"{'PORT':<14} {'NAME':<14} {'STATE':<8} "
                    f"{'SERVICE':<20} {'PROTO':<6} {'RISK':<10} DESCRIPTION\n")
            f.write("-" * 80 + "\n")
            for m in rows:
                f.write(
                    f"{m['port_str']:<14} {m['name']:<14} {m['state']:<8} "
                    f"{m['service']:<20} {m['protocol']:<6} {m['risk']:<10} "
                    f"{m['description']}\n")
            f.write(f"\nOpen: {self.open_count}  |  "
                    f"Closed: {self.closed_count}  |  "
                    f"Total scanned: {self._rows_added}\n")
        messagebox.showinfo("Export", f"Saved {len(rows)} rows to:\n{path}")


# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    app = NetProbeWindow()
    app.mainloop()