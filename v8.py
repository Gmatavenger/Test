# =============================================================================
# Splunk Dashboard Automator (Consolidated & Enhanced)
#
# This application provides a graphical user interface (GUI) to automate
# interactions with Splunk dashboards.
#
# Key Features:
# - Advanced Time Range Selector (Presets, Relative, Date/Time, Epoch).
# - Intelligent detection and handling for Splunk Studio vs. Classic dashboards.
# - Dashboard management with Groups (Add, Edit, Delete).
# - Screenshot capture and detailed analysis modes.
# - Simple, single-task scheduling system.
# - Secure, encrypted storage for Splunk credentials.
# - Modern, themeable UI with Light & Dark modes.
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, filedialog
import asyncio
from datetime import datetime, time as dt_time
import pytz
import os
import sys
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from threading import Thread
import logging
from logging.handlers import RotatingFileHandler
import shutil
import io
import uuid
import csv
from typing import Dict, List, Any, Optional, Tuple

# --- Import third-party libraries ---
try:
    from tkcalendar import DateEntry
except ImportError:
    messagebox.showerror("Missing Library", "The 'tkcalendar' library is required. Please run: pip install tkcalendar")
    sys.exit(1)

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    messagebox.showerror("Missing Library", "The 'playwright' library is required. Please run: pip install playwright")
    sys.exit(1)

from PIL import Image, ImageDraw, ImageFont
from cryptography.fernet import Fernet

# =============================================================================
# SECTION 1: CONFIGURATION AND SETUP
# =============================================================================

class Config:
    """Holds all important constant values for the application."""
    LOG_DIR = "logs"
    TMP_DIR = "tmp"
    SCREENSHOT_ARCHIVE_DIR = "screenshots"
    DASHBOARD_FILE = "dashboards.json"
    SCHEDULE_FILE = "schedule.json"
    SETTINGS_FILE = "settings.json"
    SECRETS_KEY_FILE = ".secrets.key"
    SECRETS_FILE = ".secrets"
    DAYS_TO_KEEP_ARCHIVES = 3
    EST = pytz.timezone("America/New_York")

class Theme:
    """Defines color schemes for Light and Dark themes."""
    LIGHT = { 'bg': '#FDFDFD', 'fg': '#000000', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF', 'button_bg': '#F0F0F0', 'button_fg': '#000000', 'frame_bg': '#F1F1F1', 'accent': '#0078D4', 'tree_bg': '#FFFFFF', 'tree_fg': '#000000' }
    DARK = { 'bg': '#1E1E1E', 'fg': '#FFFFFF', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF', 'button_bg': '#2D2D30', 'button_fg': '#FFFFFF', 'frame_bg': '#252526', 'accent': '#0078D4', 'tree_bg': '#2A2D2E', 'tree_fg': '#CCCCCC' }

# --- Setup Logging ---
os.makedirs(Config.LOG_DIR, exist_ok=True)
log_file = os.path.join(Config.LOG_DIR, f"app_{datetime.now().strftime('%Y%m%d')}.log")
logger = logging.getLogger("SplunkAutomator")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler(sys.stdout))

# =============================================================================
# SECTION 2: CORE UTILITIES (FILES, ENCRYPTION, ETC.)
# =============================================================================

def ensure_dirs():
    """Create necessary application directories if they don't exist."""
    for directory in [Config.LOG_DIR, Config.TMP_DIR, Config.SCREENSHOT_ARCHIVE_DIR]:
        os.makedirs(directory, exist_ok=True)

def archive_and_clean_tmp():
    """Moves older screenshot folders to an archive and cleans the temp directory."""
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    if not os.path.exists(Config.TMP_DIR): return
    for item in os.listdir(Config.TMP_DIR):
        item_path = os.path.join(Config.TMP_DIR, item)
        if os.path.isdir(item_path) and item != today_str:
            archive_path = os.path.join(Config.SCREENSHOT_ARCHIVE_DIR, item)
            shutil.rmtree(archive_path, ignore_errors=True)
            shutil.move(item_path, archive_path)
            logger.info(f"Archived {item_path} to {archive_path}")
        elif os.path.isfile(item_path):
            os.remove(item_path)
            logger.info(f"Removed stray file from tmp: {item_path}")

def purge_old_archives():
    """Deletes archived screenshot folders older than the configured number of days."""
    now = datetime.now()
    if not os.path.exists(Config.SCREENSHOT_ARCHIVE_DIR): return
    logger.info(f"Purging archives older than {Config.DAYS_TO_KEEP_ARCHIVES} days.")
    for folder in os.listdir(Config.SCREENSHOT_ARCHIVE_DIR):
        try:
            folder_date = datetime.strptime(folder, "%Y-%m-%d")
            if (now - folder_date).days > Config.DAYS_TO_KEEP_ARCHIVES:
                shutil.rmtree(os.path.join(Config.SCREENSHOT_ARCHIVE_DIR, folder))
                logger.info(f"Purged old archive folder: {folder}")
        except (ValueError, OSError) as e:
            logger.warning(f"Could not process or delete archive folder {folder}: {e}")

def save_screenshot_with_watermark(screenshot_bytes: bytes, filename: str) -> str:
    """Saves the screenshot with a professional, semi-transparent watermark."""
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    day_tmp_dir = os.path.join(Config.TMP_DIR, today_str)
    os.makedirs(day_tmp_dir, exist_ok=True)
    file_path = os.path.join(day_tmp_dir, filename)

    image = Image.open(io.BytesIO(screenshot_bytes))
    draw = ImageDraw.Draw(image, "RGBA")
    timestamp = datetime.now(Config.EST).strftime("%Y-%m-%d %H:%M:%S %Z")
    text = f"Captured: {timestamp}"
    
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except IOError:
        font = ImageFont.load_default()

    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = text_bbox[2] - text_bbox[0], text_bbox[3] - text_bbox[1]
    
    padding, bg_padding = 15, 8
    x = image.width - text_width - padding
    y = padding
    
    draw.rectangle((x - bg_padding, y - bg_padding, x + text_width + bg_padding, y + text_height + bg_padding), fill=(0, 0, 0, 128))
    draw.text((x, y), text, fill="white", font=font)

    image.convert("RGB").save(file_path)
    logger.info(f"Saved watermarked screenshot to {file_path}")
    return file_path

def set_secure_permissions(file_path: str):
    """Sets file permissions to read/write for the current user only (non-Windows)."""
    if os.name != 'nt':
        try:
            os.chmod(file_path, 0o600)
        except OSError as e:
            logger.warning(f"Could not set secure permissions for {file_path}: {e}")

def get_encryption_key() -> bytes:
    """Retrieves the encryption key, generating it if it doesn't exist."""
    if os.path.exists(Config.SECRETS_KEY_FILE):
        with open(Config.SECRETS_KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(Config.SECRETS_KEY_FILE, "wb") as f:
            f.write(key)
        set_secure_permissions(Config.SECRETS_KEY_FILE)
        return key

def save_credentials(username: str, password: str) -> bool:
    """Encrypts and saves credentials to a secure file."""
    try:
        fernet = Fernet(get_encryption_key())
        credentials = {"username": username, "password": password}
        encrypted_data = fernet.encrypt(json.dumps(credentials).encode())
        with open(Config.SECRETS_FILE, "wb") as f:
            f.write(encrypted_data)
        set_secure_permissions(Config.SECRETS_FILE)
        logger.info("Credentials saved securely.")
        return True
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        return False

def load_credentials() -> Tuple[Optional[str], Optional[str]]:
    """Loads and decrypts credentials from the secure file."""
    if not os.path.exists(Config.SECRETS_FILE): return None, None
    try:
        fernet = Fernet(get_encryption_key())
        with open(Config.SECRETS_FILE, "rb") as f:
            decrypted_data = fernet.decrypt(f.read())
        credentials = json.loads(decrypted_data.decode())
        return credentials.get("username"), credentials.get("password")
    except Exception as e:
        logger.error(f"Error loading credentials (file might be corrupt or key changed): {e}")
        return None, None

# =============================================================================
# SECTION 3: GUI DIALOGS (Pop-up windows)
# =============================================================================

class TimeRangeDialog(Toplevel):
    """A comprehensive dialog for selecting Splunk-compatible time ranges."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Select Time Range (EST)")
        self.geometry("700x500")
        self.result: Dict[str, Any] = {}
        self.transient(parent)
        self.grab_set()

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        left_frame = ttk.Frame(main_frame, width=150)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        options = ["Presets", "Relative", "Date Range", "Date & Time Range", "Advanced"]
        self.option_var = tk.StringVar(value=options[0])
        self.frames = {opt: ttk.Frame(self.content_frame) for opt in options}
        for option in options:
            ttk.Radiobutton(left_frame, text=option, variable=self.option_var, value=option, command=self.show_selected_frame).pack(anchor="w", pady=5)
        
        self._build_frames()
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="Apply", command=self.on_apply, style="Accent.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)
        self.show_selected_frame()

    def show_selected_frame(self):
        for frame in self.frames.values(): frame.pack_forget()
        self.frames[self.option_var.get()].pack(fill=tk.BOTH, expand=True)

    def _build_frames(self):
        # Presets
        self.preset_map = { "Last 15 minutes": "-15m@m", "Last 60 minutes": "-60m@m", "Last 4 hours": "-4h@h", "Last 24 hours": "-24h@h", "Last 7 days": "-7d@d", "Today": "@d", "Yesterday": "-1d@d", "Week to date": "@w" }
        preset_frame = self.frames["Presets"]
        for name, val in self.preset_map.items():
            ttk.Button(preset_frame, text=name, command=lambda v=val: self.select_preset(v)).pack(pady=2, padx=10, fill=tk.X)
        
        # Relative
        rel_frame = self.frames["Relative"]
        self.rel_amount = ttk.Entry(rel_frame, width=5); self.rel_amount.pack(side=tk.LEFT, padx=2)
        self.rel_amount.insert(0, "4")
        units = ["minutes", "hours", "days", "weeks", "months"]
        self.rel_unit = ttk.Combobox(rel_frame, values=units, state="readonly", width=8); self.rel_unit.pack(side=tk.LEFT, padx=2)
        self.rel_unit.set("hours")
        
        # Date Range
        dr_frame = self.frames["Date Range"]
        ttk.Label(dr_frame, text="Between").pack(side=tk.LEFT)
        self.start_date = DateEntry(dr_frame); self.start_date.pack(side=tk.LEFT, padx=5)
        ttk.Label(dr_frame, text="and").pack(side=tk.LEFT)
        self.end_date = DateEntry(dr_frame); self.end_date.pack(side=tk.LEFT, padx=5)

        # Date & Time Range
        dtr_frame = self.frames["Date & Time Range"]
        self.dt_start_date = DateEntry(dtr_frame); self.dt_start_date.pack(pady=2)
        self.dt_start_time = ttk.Entry(dtr_frame, width=12); self.dt_start_time.insert(0, "00:00:00"); self.dt_start_time.pack(pady=2)
        self.dt_end_date = DateEntry(dtr_frame); self.dt_end_date.pack(pady=2)
        self.dt_end_time = ttk.Entry(dtr_frame, width=12); self.dt_end_time.insert(0, "23:59:59"); self.dt_end_time.pack(pady=2)

        # Advanced
        adv_frame = self.frames["Advanced"]
        ttk.Label(adv_frame, text="Earliest (epoch):").pack()
        self.earliest_epoch = ttk.Entry(adv_frame); self.earliest_epoch.pack()
        ttk.Label(adv_frame, text="Latest (epoch):").pack()
        self.latest_epoch = ttk.Entry(adv_frame); self.latest_epoch.pack()

    def select_preset(self, value):
        self.result = {"start": value, "end": "now"}
        self.destroy()

    def on_apply(self):
        try:
            option = self.option_var.get()
            if option == "Relative":
                amount = int(self.rel_amount.get())
                unit_map = {"minutes": "m", "hours": "h", "days": "d", "weeks": "w", "months": "mon"}
                unit = unit_map[self.rel_unit.get()]
                self.result = {"start": f"-{amount}{unit}", "end": "now"}
            elif option == "Date Range":
                start = datetime.combine(self.start_date.get_date(), dt_time.min)
                end = datetime.combine(self.end_date.get_date(), dt_time.max)
                self.result = {"start": start, "end": end}
            elif option == "Date & Time Range":
                start = datetime.combine(self.dt_start_date.get_date(), datetime.strptime(self.dt_start_time.get(), "%H:%M:%S").time())
                end = datetime.combine(self.dt_end_date.get_date(), datetime.strptime(self.dt_end_time.get(), "%H:%M:%S").time())
                self.result = {"start": start, "end": end}
            elif option == "Advanced":
                start = datetime.fromtimestamp(int(self.earliest_epoch.get()))
                end = datetime.fromtimestamp(int(self.latest_epoch.get()))
                self.result = {"start": start, "end": end}
            
            if isinstance(self.result.get("start"), datetime) and self.result['start'] >= self.result['end']:
                raise ValueError("Start time must be before end time.")
            
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", f"Invalid time range: {e}", parent=self)

class DashboardDialogBase(Toplevel):
    """Base dialog for adding or editing a dashboard."""
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.configure(bg=self.app.current_theme['bg'])
        self.transient(parent)
        self.grab_set()
        self._create_ui()

    def _create_ui(self):
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Dashboard Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.name_var, width=50).grid(row=0, column=1, sticky="ew")

        ttk.Label(main_frame, text="Dashboard URL:").grid(row=1, column=0, sticky="w", pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.url_var, width=50).grid(row=1, column=1, sticky="ew")

        ttk.Label(main_frame, text="Group Name:").grid(row=2, column=0, sticky="w", pady=5)
        self.group_var = tk.StringVar()
        existing_groups = sorted(list(self.app.get_all_dashboard_groups()))
        self.group_combo = ttk.Combobox(main_frame, textvariable=self.group_var, values=existing_groups, width=47)
        self.group_combo.grid(row=2, column=1, pady=5)
        if existing_groups: self.group_combo.set(existing_groups[0])

        self.button_frame = ttk.Frame(main_frame)
        self.button_frame.grid(row=3, column=0, columnspan=2, pady=20, sticky="e")

class DashboardAddDialog(DashboardDialogBase):
    def __init__(self, parent, app_instance):
        super().__init__(parent, app_instance)
        self.title("Add New Dashboard")
        ttk.Button(self.button_frame, text="Add Dashboard", command=self.on_add, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(self.button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def on_add(self):
        name, url, group = self.name_var.get().strip(), self.url_var.get().strip(), self.group_var.get().strip() or "Default"
        if not name or not url: messagebox.showerror("Input Error", "Name and URL are required.", parent=self); return
        if not url.lower().startswith("http"): messagebox.showerror("Input Error", "URL must start with http.", parent=self); return
        if any(d["name"].strip().lower() == name.lower() for d in self.app.session["dashboards"]):
            messagebox.showerror("Input Error", "A dashboard with this name already exists.", parent=self); return

        new_dashboard = {"id": str(uuid.uuid4()), "name": name, "url": url, "group": group, "selected": True}
        self.app.session['dashboards'].append(new_dashboard)
        self.app.save_and_refresh_ui()
        self.destroy()

class DashboardEditDialog(DashboardDialogBase):
    def __init__(self, parent, app_instance, dashboard_to_edit: Dict):
        self.dashboard_to_edit = dashboard_to_edit
        super().__init__(parent, app_instance)
        self.title("Edit Dashboard")
        self.name_var.set(dashboard_to_edit.get("name", ""))
        self.url_var.set(dashboard_to_edit.get("url", ""))
        self.group_var.set(dashboard_to_edit.get("group", "Default"))
        ttk.Button(self.button_frame, text="Save Changes", command=self.on_save, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(self.button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def on_save(self):
        new_name, new_url, new_group = self.name_var.get().strip(), self.url_var.get().strip(), self.group_var.get().strip() or "Default"
        if not new_name or not new_url: messagebox.showerror("Input Error", "Name and URL are required.", parent=self); return
        
        original_id = self.dashboard_to_edit.get('id')
        if any(d["name"].strip().lower() == new_name.lower() and d.get('id') != original_id for d in self.app.session["dashboards"]):
            messagebox.showerror("Input Error", "Another dashboard with this name already exists.", parent=self); return

        for db in self.app.session['dashboards']:
            if db.get('id') == original_id:
                db['name'], db['url'], db['group'] = new_name, new_url, new_group
                break
        
        self.app.save_and_refresh_ui()
        self.destroy()

# =============================================================================
# SECTION 4: MAIN APPLICATION CLASS
# =============================================================================

class SplunkAutomatorApp:
    MAX_CONCURRENT_DASHBOARDS = 3

    def __init__(self, master: tk.Tk):
        self.master = master
        settings = self.load_settings()
        master.title("Splunk Dashboard Automator")
        master.geometry(settings.get("geometry", "1200x900"))

        self.is_dark_theme = settings.get("dark_theme", False)
        self.current_theme = Theme.DARK if self.is_dark_theme else Theme.LIGHT
        
        self.status_message = tk.StringVar(value="Ready.")
        self.username, self.password = load_credentials()
        self.session = {"username": self.username, "password": self.password, "dashboards": []}
        self.schedule_timer_id = None

        self._setup_ui()
        self._apply_theme()
        
        self.load_dashboards()
        self.save_and_refresh_ui()
        
        self.start_schedule_if_exists()

        if not self.session["username"] or not self.session["password"]:
            master.after(100, self.manage_credentials)

        archive_and_clean_tmp()
        purge_old_archives()
        logger.info("SplunkAutomatorApp initialized.")

    def _setup_ui(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Manage Credentials", command=self.manage_credentials)
        settings_menu.add_command(label="Export Results", command=self.export_results)
        
        schedule_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Schedule", menu=schedule_menu)
        schedule_menu.add_command(label="Configure Schedule", command=self.configure_schedule)
        schedule_menu.add_command(label="Cancel Schedule", command=self.cancel_schedule)

        main_pane = ttk.PanedWindow(self.master, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        top_frame = ttk.Frame(main_pane, padding=5)
        bottom_frame = ttk.Frame(main_pane, padding=5)
        main_pane.add(top_frame, weight=1)
        main_pane.add(bottom_frame, weight=0)

        # --- Top Frame UI ---
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_rowconfigure(2, weight=1)
        
        header_frame = ttk.Frame(top_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(header_frame, text="Splunk Dashboard Automator", font=("Arial", 16, "bold")).pack(side=tk.LEFT)
        self.theme_btn = ttk.Button(header_frame, text="🌙", command=self.toggle_theme, width=3)
        self.theme_btn.pack(side=tk.RIGHT)

        controls_frame = ttk.Frame(top_frame)
        controls_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        btn_config = [("➕ Add", self.add_dashboard), ("✏️ Edit", self.edit_dashboard), ("🗑️ Delete", self.delete_dashboard),
                      ("☑️ Select All", self.select_all_dashboards), ("☐ Deselect All", self.deselect_all_dashboards)]
        for text, cmd in btn_config: ttk.Button(controls_frame, text=text, command=cmd, width=12).pack(side=tk.LEFT, padx=(0, 5))
        
        filter_frame = ttk.Frame(controls_frame)
        filter_frame.pack(side=tk.RIGHT)
        ttk.Label(filter_frame, text="Filter by Group:").pack(side=tk.LEFT)
        self.group_filter_var = tk.StringVar(value=self.load_settings().get("last_group", "All"))
        self.group_filter = ttk.Combobox(filter_frame, textvariable=self.group_filter_var, state="readonly", width=15)
        self.group_filter.pack(side=tk.LEFT, padx=5)
        self.group_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())

        tree_frame = ttk.Frame(top_frame)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.grid_rowconfigure(0, weight=1); tree_frame.grid_columnconfigure(0, weight=1)

        columns = ("Select", "Name", "URL", "Group", "Status")
        self.treeview = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=v_scroll.set)
        v_scroll.grid(row=0, column=1, sticky="ns"); self.treeview.grid(row=0, column=0, sticky="nsew")
        self.treeview.bind("<Button-1>", self.on_treeview_click)
        
        col_configs = [("Select", 60, "center"), ("Name", 250, "w"), ("URL", 400, "w"), ("Group", 150, "w"), ("Status", 250, "w")]
        for col, width, anchor in col_configs: self.treeview.heading(col, text=col); self.treeview.column(col, width=width, anchor=anchor, minwidth=width)

        # --- Bottom Frame UI ---
        action_frame = ttk.LabelFrame(bottom_frame, text="Actions", padding=10)
        action_frame.pack(fill=tk.BOTH, expand=True)
        action_frame.grid_columnconfigure(0, weight=1); action_frame.grid_columnconfigure(1, weight=1)
        ttk.Button(action_frame, text="📸 Capture Screenshots", command=self.start_capture_thread).grid(row=0, column=0, pady=5, padx=5, sticky="ew")
        ttk.Button(action_frame, text="📊 Analyze Dashboards", command=self.start_analysis_thread).grid(row=0, column=1, pady=5, padx=5, sticky="ew")
        self.progress_bar = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=1, column=0, columnspan=2, pady=(10,0), sticky="ew")

        # --- Status Bar ---
        status_bar = ttk.Frame(self.master, relief=tk.SUNKEN, borderwidth=1)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status_message, anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.connection_status = ttk.Label(status_bar, text="●", foreground="red" if not self.username else "green")
        self.connection_status.pack(side=tk.RIGHT, padx=5)

    def _apply_theme(self):
        style = ttk.Style(); theme = self.current_theme
        style.theme_use('clam')
        style.configure('.', background=theme['bg'], foreground=theme['fg'], fieldbackground=theme['button_bg'])
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TRadiobutton', background=theme['bg'], foreground=theme['fg'])
        style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'], padding=5, borderwidth=1, relief=tk.RAISED)
        style.map('TButton', background=[('active', theme['select_bg'])])
        style.configure('Accent.TButton', background=theme['accent'], foreground=theme['select_fg'])
        style.configure('Treeview', background=theme['tree_bg'], foreground=theme['tree_fg'], fieldbackground=theme['tree_bg'])
        style.map('Treeview', background=[('selected', theme['select_bg'])], foreground=[('selected', theme['select_fg'])])
        style.configure('Treeview.Heading', background=theme['frame_bg'], foreground=theme['fg'], font=('Arial', 10, 'bold'))
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        style.configure('TPanedWindow', background=theme['bg'])
        self.master.configure(bg=theme['bg'])

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.current_theme = Theme.DARK if self.is_dark_theme else Theme.LIGHT
        self.theme_btn.configure(text="☀️" if self.is_dark_theme else "🌙")
        self._apply_theme()
        self.save_settings()

    # --- Dashboard and Group Management ---
    def get_all_dashboard_groups(self) -> set:
        return {"Default"} | {db.get("group", "Default") for db in self.session['dashboards']}
        
    def add_dashboard(self): DashboardAddDialog(self.master, self)
    def edit_dashboard(self):
        selected_dbs = [db for db in self.session['dashboards'] if db.get('selected', False)]
        if len(selected_dbs) != 1: messagebox.showwarning("Selection Error", "Please select exactly one dashboard to edit."); return
        DashboardEditDialog(self.master, self, selected_dbs[0])

    def delete_dashboard(self):
        to_delete = [db for db in self.session['dashboards'] if db.get('selected', False)]
        if not to_delete: messagebox.showwarning("No Selection", "Please select dashboards to delete."); return
        if messagebox.askyesno("Confirm Delete", f"Delete {len(to_delete)} dashboard(s)? This cannot be undone."):
            delete_ids = {db['id'] for db in to_delete}
            self.session['dashboards'] = [db for db in self.session['dashboards'] if db.get('id') not in delete_ids]
            self.save_and_refresh_ui()

    def select_all_dashboards(self): self._toggle_all_selection(True)
    def deselect_all_dashboards(self): self._toggle_all_selection(False)
    def _toggle_all_selection(self, select_state: bool):
        current_filter = self.group_filter_var.get()
        for db in self.session['dashboards']:
            if current_filter == "All" or db.get("group", "Default") == current_filter: db['selected'] = select_state
        self.refresh_dashboard_list()

    def on_treeview_click(self, event):
        item_id = self.treeview.identify_row(event.y)
        if not item_id or self.treeview.identify_column(event.x) != "#1": return
        for db in self.session['dashboards']:
            if db.get('id') == item_id: db["selected"] = not db.get("selected", False); self.refresh_dashboard_list(); break

    def refresh_dashboard_list(self):
        for item in self.treeview.get_children(): self.treeview.delete(item)
        selected_filter = self.group_filter_var.get()
        
        for db in sorted(self.session['dashboards'], key=lambda x: x['name'].lower()):
            if 'id' not in db: db['id'] = str(uuid.uuid4()) # Backwards compatibility
            if selected_filter == "All" or db.get("group", "Default") == selected_filter:
                values = ("☑" if db.get("selected") else "☐", db['name'], db['url'], db.get('group', 'Default'), db.get('status', 'Ready'))
                self.treeview.insert("", "end", iid=db['id'], values=values)
        
        self.update_status_summary()

    def update_group_filter(self):
        all_groups = {"All"} | self.get_all_dashboard_groups()
        self.group_filter['values'] = sorted(list(all_groups))
        if self.group_filter_var.get() not in self.group_filter['values']: self.group_filter_var.set("All")

    def save_and_refresh_ui(self):
        self.save_dashboards()
        self.update_group_filter()
        self.refresh_dashboard_list()

    # --- Core Processing Logic ---
    def _prepare_and_start_job(self, capture_only: bool):
        """Common logic to prepare and start a processing job."""
        archive_and_clean_tmp()
        selected_dbs = [db for db in self.session['dashboards'] if db.get('selected', False)]
        if not selected_dbs: messagebox.showwarning("No Selection", "Please select one or more dashboards."); return
        if not self.session['username'] or not self.session['password']: messagebox.showerror("Credentials Required", "Please set Splunk credentials."); return

        dialog = TimeRangeDialog(self.master)
        self.master.wait_window(dialog)
        if not dialog.result: logger.warning("Job cancelled: No time range selected."); return
        time_range = dialog.result

        retries = 1 if capture_only else simpledialog.askinteger("Retry Count", "Retry how many times on failure?", initialvalue=2, minvalue=0, maxvalue=5)
        if retries is None: return

        self.progress_bar['maximum'] = len(selected_dbs)
        self.progress_bar['value'] = 0
        for db in selected_dbs: self.update_dashboard_status(db['name'], "Queued")
        
        job_name = "Capture" if capture_only else "Analysis"
        self.update_status(f"Starting {job_name} for {len(selected_dbs)} dashboards...")

        def run_async_job():
            asyncio.run(self._process_dashboards_async(selected_dbs, time_range, retries, capture_only))
        
        Thread(target=run_async_job, name=f"{job_name}Thread", daemon=True).start()
    
    def start_capture_thread(self): self._prepare_and_start_job(capture_only=True)
    def start_analysis_thread(self): self._prepare_and_start_job(capture_only=False)

    async def _process_dashboards_async(self, dashboards: List[Dict], time_range: Dict, retries: int, capture_only: bool):
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_DASHBOARDS)
        async with async_playwright() as playwright:
            tasks = [self._process_single_dashboard_wrapper(playwright, db, time_range, retries, capture_only, semaphore, i) for i, db in enumerate(dashboards)]
            await asyncio.gather(*tasks)
        
        self.master.after(0, lambda: self._on_operation_complete("Capture" if capture_only else "Analysis"))

    async def _process_single_dashboard_wrapper(self, playwright, dashboard, time_range, retries, capture_only, semaphore, index):
        async with semaphore:
            for attempt in range(retries + 1):
                try:
                    await self.process_single_dashboard(playwright, dashboard, time_range, capture_only)
                    break # Success
                except Exception as e:
                    logger.warning(f"Attempt {attempt + 1}/{retries+1} failed for {dashboard['name']}: {e}")
                    self.update_dashboard_status(dashboard['name'], f"Retry {attempt + 1} failed")
                    if attempt == retries: self.update_dashboard_status(dashboard['name'], "❌ Failed")
            
            self.master.after(0, lambda: self.progress_bar.step())

    async def process_single_dashboard(self, playwright, db_data: Dict, time_range: Dict, capture_only: bool):
        name, url = db_data['name'], db_data['url']
        logger.info(f"Processing '{name}'. Capture only: {capture_only}")
        self.update_dashboard_status(name, "Launching...")
        
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1920, 'height': 1080})
            page = await context.new_page()

            is_studio = "dashboard/studio" in url.lower() # Simple but effective check
            full_url = self.format_time_for_url(url, time_range['start'], time_range['end'], is_studio)
            
            self.update_dashboard_status(name, "Loading page...")
            await page.goto(full_url, timeout=90000, wait_until='domcontentloaded')

            if await page.locator('input[name="username"]').is_visible(timeout=5000):
                self.update_dashboard_status(name, "Authenticating...")
                await page.fill('input[name="username"]', self.session['username'])
                await page.fill('input[name="password"]', self.session['password'])
                await page.click('button[type="submit"], input[type="submit"]')
                await page.wait_for_url(lambda u: "account/login" not in u, timeout=15000)

            if not capture_only:
                await self._wait_for_dashboard_load(page, name, is_studio)

            self.update_dashboard_status(name, "Capturing...")
            screenshot_bytes = await page.screenshot(full_page=True)
            filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now().strftime('%H%M%S')}.png"
            
            save_screenshot_with_watermark(screenshot_bytes, filename)
            self.update_dashboard_status(name, f"✅ Success")
        finally:
            await browser.close()

    async def _wait_for_dashboard_load(self, page, name: str, is_studio: bool):
        """Waits for dashboard panels to finish loading."""
        self.update_dashboard_status(name, "Waiting for panels...")
        try:
            if is_studio:
                await page.wait_for_function("() => !document.querySelector('.spl-spinner, .dashboard-loading, .inline-loading-indicator')", timeout=180000)
            else: # Classic
                await page.wait_for_function("() => document.querySelectorAll('.dashboard-panel .search-controls .search-progress').length === 0", timeout=180000)
            
            await asyncio.sleep(3) # Final stabilization wait
            logger.info(f"Dashboard '{name}' panels loaded.")
        except PlaywrightTimeoutError:
            logger.warning(f"Timeout waiting for panels to load on '{name}'. Proceeding anyway.")
            self.update_dashboard_status(name, "⚠️ Panel load timeout")

    def format_time_for_url(self, base_url: str, start, end, is_studio: bool) -> str:
        """Appends the correct time range parameters to the Splunk dashboard URL."""
        params = {}
        prefix = "form.global_time" if is_studio else "form.time"
        
        if isinstance(start, datetime): params[f'{prefix}.earliest'] = int(start.timestamp())
        else: params[f'{prefix}.earliest'] = start
        
        if isinstance(end, datetime): params[f'{prefix}.latest'] = int(end.timestamp())
        else: params[f'{prefix}.latest'] = end
        
        # This logic ensures existing query params are preserved.
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        query_params.update(params)
        
        return urlunparse(parsed_url._replace(query=urlencode(query_params, doseq=True)))

    def _on_operation_complete(self, operation_name: str):
        self.update_status(f"{operation_name} completed.")
        messagebox.showinfo("Complete", f"{operation_name} has finished.")
        self.progress_bar['value'] = 0
        purge_old_archives()

    # --- Scheduling System ---
    def configure_schedule(self):
        interval_str = simpledialog.askstring("Schedule Analysis", "Enter interval in minutes (min 1):")
        if not interval_str or not interval_str.isdigit() or int(interval_str) < 1:
            messagebox.showerror("Invalid Input", "Interval must be a number greater than 0."); return
        
        schedule_config = {"interval_minutes": int(interval_str)}
        with open(Config.SCHEDULE_FILE, 'w') as f: json.dump(schedule_config, f, indent=4)
        set_secure_permissions(Config.SCHEDULE_FILE)
        
        messagebox.showinfo("Schedule Saved", f"Analysis for all selected dashboards will run every {interval_str} minutes.")
        self.start_schedule_if_exists() # Start or restart the schedule timer

    def start_schedule_if_exists(self):
        if self.schedule_timer_id: self.master.after_cancel(self.schedule_timer_id)
        
        if os.path.exists(Config.SCHEDULE_FILE):
            try:
                with open(Config.SCHEDULE_FILE, 'r') as f: config = json.load(f)
                interval_ms = config['interval_minutes'] * 60 * 1000
                self.update_status(f"Next scheduled run in {config['interval_minutes']} minutes.")
                self.schedule_timer_id = self.master.after(interval_ms, self.run_scheduled_analysis)
            except (json.JSONDecodeError, KeyError, OSError) as e:
                logger.error(f"Could not start schedule from file: {e}")

    def run_scheduled_analysis(self):
        logger.info("Executing scheduled analysis run...")
        self.update_status("Starting scheduled analysis...")
        self._toggle_all_selection(True) # Select all for the run
        self.start_analysis_thread()
        self.start_schedule_if_exists() # Reschedule for the next interval

    def cancel_schedule(self):
        if self.schedule_timer_id: self.master.after_cancel(self.schedule_timer_id); self.schedule_timer_id = None
        if os.path.exists(Config.SCHEDULE_FILE): os.remove(Config.SCHEDULE_FILE)
        self.update_status("Schedule cancelled.")
        messagebox.showinfo("Schedule Cancelled", "The analysis schedule has been stopped and removed.")
            
    # --- Helper Functions & State Management ---
    def manage_credentials(self):
        dialog = Toplevel(self.master)
        dialog.title("Manage Credentials"); dialog.transient(self.master); dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Splunk Username:").grid(row=0, column=0, sticky="w", pady=5)
        user_var = tk.StringVar(value=self.username)
        ttk.Entry(frame, textvariable=user_var, width=40).grid(row=0, column=1, sticky="ew")

        ttk.Label(frame, text="Splunk Password:").grid(row=1, column=0, sticky="w", pady=5)
        pass_var = tk.StringVar(value=self.password)
        pass_entry = ttk.Entry(frame, textvariable=pass_var, show="*", width=40)
        pass_entry.grid(row=1, column=1, sticky="ew")
        
        def on_save():
            if save_credentials(user_var.get(), pass_var.get()):
                self.username, self.password = user_var.get(), pass_var.get()
                self.session.update({'username': self.username, 'password': self.password})
                self.connection_status.config(foreground="green")
                messagebox.showinfo("Success", "Credentials saved securely.", parent=dialog)
                dialog.destroy()
            else: messagebox.showerror("Error", "Failed to save credentials.", parent=dialog)

        ttk.Button(frame, text="Save", command=on_save, style="Accent.TButton").grid(row=2, column=1, sticky="e", pady=10)

    def export_results(self):
        """Exports the current dashboard list and statuses to a CSV file."""
        if not self.session['dashboards']: messagebox.showinfo("Nothing to export", "No dashboards loaded."); return
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not filepath: return
        
        try:
            with open(filepath, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "URL", "Group", "Status"])
                for db in self.session['dashboards']:
                    writer.writerow([db['name'], db['url'], db.get('group', "Default"), db.get('status', "")])
            self.update_status(f"Results exported to {os.path.basename(filepath)}")
        except IOError as e:
            messagebox.showerror("Export Error", f"Could not write to file: {e}")

    def update_dashboard_status(self, dashboard_name: str, status: str):
        """Updates a dashboard's status in the UI safely from any thread."""
        def update_ui():
            for db in self.session['dashboards']:
                if db['name'] == dashboard_name: db['status'] = status; break
            for item_id in self.treeview.get_children():
                if self.treeview.item(item_id)['values'][1] == dashboard_name:
                    values = list(self.treeview.item(item_id)['values']); values[4] = status
                    self.treeview.item(item_id, values=tuple(values)); break
        self.master.after(0, update_ui)
    
    def update_status_summary(self):
        total = len(self.session['dashboards'])
        selected = sum(1 for d in self.session['dashboards'] if d.get('selected', False))
        self.update_status(f"{total} dashboards loaded ({selected} selected).")

    def update_status(self, message: str):
        self.status_message.set(message); logger.info(f"Status: {message}")
        
    def load_dashboards(self):
        if not os.path.exists(Config.DASHBOARD_FILE): self.session['dashboards'] = []; return
        try:
            with open(Config.DASHBOARD_FILE, 'r', encoding='utf-8') as f: dashboards = json.load(f)
            for db in dashboards:
                if 'group' not in db: db['group'] = 'Default' # Backwards compatibility
                if 'id' not in db: db['id'] = str(uuid.uuid4())
            self.session['dashboards'] = dashboards
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Error loading dashboards: {e}"); self.session['dashboards'] = []
    
    def save_dashboards(self):
        try:
            with open(Config.DASHBOARD_FILE, 'w', encoding='utf-8') as f:
                to_save = [{k: v for k, v in db.items() if k != 'status'} for db in self.session['dashboards']]
                json.dump(to_save, f, indent=4)
            set_secure_permissions(Config.DASHBOARD_FILE)
        except OSError as e:
            logger.error(f"Error saving dashboards: {e}")

    def load_settings(self) -> Dict[str, Any]:
        if not os.path.exists(Config.SETTINGS_FILE): return {}
        try:
            with open(Config.SETTINGS_FILE, "r", encoding='utf-8') as f: return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load settings: {e}"); return {}

    def save_settings(self):
        settings = { "geometry": self.master.geometry(), "dark_theme": self.is_dark_theme, "last_group": self.group_filter_var.get() }
        try:
            with open(Config.SETTINGS_FILE, "w", encoding='utf-8') as f: json.dump(settings, f, indent=4)
        except OSError as e:
            logger.error(f"Error saving settings: {e}")

    def on_closing(self):
        self.save_settings()
        self.master.destroy()

# =============================================================================
# SECTION 5: APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
