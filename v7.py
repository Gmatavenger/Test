# =============================================================================
# Splunk Dashboard Automator
#
# This application provides a graphical user interface (GUI) to automate
# interactions with Splunk dashboards. Its key features include:
# - Managing a list of dashboards, organized into user-defined lists.
# - Capturing screenshots or performing detailed analysis of dashboards.
# - A powerful scheduling system to run jobs automatically.
# - Secure, encrypted storage for your Splunk credentials.
# - A modern, themeable user interface (Light & Dark modes).
# =============================================================================

# --- Import necessary libraries ---
# tkinter: For creating the graphical user interface (GUI).
# asyncio: For running multiple operations at the same time without freezing the app.
# datetime, pytz: For handling dates and timezones correctly.
# os, sys, shutil: For interacting with the operating system (e.g., creating folders, managing files).
# re, json: For text processing and storing data in a structured way.
# urllib: For handling web URLs.
# threading: To run long tasks in the background without freezing the UI.
# logging: To record application events and errors for troubleshooting.
# Pillow (PIL): For adding watermarks to images.
# cryptography: For encrypting and decrypting credentials securely.
# tkcalendar: For a user-friendly date selection widget.
# playwright: For controlling a web browser to interact with Splunk.

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel
import asyncio
from datetime import datetime, timedelta, time as dt_time
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
from typing import Dict, List, Any, Optional, Tuple

# --- Import third-party libraries and check for their existence ---
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

# Import image processing and encryption libraries
from PIL import Image, ImageDraw, ImageFont
from cryptography.fernet import Fernet


# =============================================================================
# SECTION 1: CONFIGURATION AND SETUP
# =============================================================================

class Config:
    """
    This class holds all the important constant values (configurations) for the application.
    Using a class like this makes it easy to find and change settings in one place.
    """
    LOG_DIR = "logs"
    TMP_DIR = "tmp"
    SCREENSHOT_ARCHIVE_DIR = "screenshots"
    DASHBOARD_FILE = "dashboards.json"
    SCHEDULE_FILE = "schedules.json"
    SETTINGS_FILE = "settings.json"
    SECRETS_KEY_FILE = ".secrets.key"
    SECRETS_FILE = ".secrets"
    DAYS_TO_KEEP_ARCHIVES = 3  # How many days of old screenshots to keep
    EST = pytz.timezone("America/New_York") # Timezone for watermarks

class Theme:
    """
    This class defines the color schemes for the Light and Dark themes.
    Each theme has colors for background, text, buttons, etc.
    """
    LIGHT = {
        'bg': '#FDFDFD', 'fg': '#000000', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF',
        'button_bg': '#F0F0F0', 'button_fg': '#000000', 'frame_bg': '#F1F1F1', 'accent': '#0078D4',
        'tree_bg': '#FFFFFF', 'tree_fg': '#000000'
    }
    DARK = {
        'bg': '#1E1E1E', 'fg': '#FFFFFF', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF',
        'button_bg': '#2D2D30', 'button_fg': '#FFFFFF', 'frame_bg': '#252526', 'accent': '#0078D4',
        'tree_bg': '#2A2D2E', 'tree_fg': '#CCCCCC'
    }

# --- Set up Logging ---
# Logging records important events and errors to a file, which helps in debugging.
os.makedirs(Config.LOG_DIR, exist_ok=True)
log_file = os.path.join(Config.LOG_DIR, f"app_{datetime.now().strftime('%Y%m%d')}.log")
logger = logging.getLogger("SplunkAutomator")
logger.setLevel(logging.INFO) # Set the lowest level of events to record (INFO and above)
# This handler makes sure the log file doesn't grow infinitely large.
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
# This defines the format of each log message (timestamp, level, message).
formatter = logging.Formatter('%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
# This also prints log messages to the console for real-time feedback.
logger.addHandler(logging.StreamHandler(sys.stdout))


# =============================================================================
# SECTION 2: CORE UTILITIES (FILES, ENCRYPTION, ETC.)
# =============================================================================

def ensure_dirs():
    """Create necessary application directories if they don't already exist."""
    for directory in [Config.TMP_DIR, Config.SCREENSHOT_ARCHIVE_DIR]:
        os.makedirs(directory, exist_ok=True)

def archive_and_clean_tmp():
    """
    Organizes screenshot files. It moves older screenshot folders into an
    'archive' directory to keep the main temporary folder clean.
    """
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    for folder in os.listdir(Config.TMP_DIR):
        folder_path = os.path.join(Config.TMP_DIR, folder)
        if os.path.isdir(folder_path) and folder != today_str:
            archive_path = os.path.join(Config.SCREENSHOT_ARCHIVE_DIR, folder)
            if os.path.exists(archive_path):
                shutil.rmtree(archive_path) # Remove old archive if it exists
            shutil.move(folder_path, archive_path)
            logger.info(f"Archived {folder_path} to {archive_path}")

def purge_old_archives():
    """Deletes archived screenshot folders that are older than the configured number of days."""
    now = datetime.now()
    if not os.path.exists(Config.SCREENSHOT_ARCHIVE_DIR):
        return
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
    """
    Saves the screenshot and adds a professional-looking watermark with the current time.
    The watermark has a semi-transparent background to ensure it's always visible.
    """
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    day_tmp_dir = os.path.join(Config.TMP_DIR, today_str)
    os.makedirs(day_tmp_dir, exist_ok=True)
    file_path = os.path.join(day_tmp_dir, filename)

    image = Image.open(io.BytesIO(screenshot_bytes))
    draw = ImageDraw.Draw(image, "RGBA") # Use RGBA to allow for transparency
    timestamp = datetime.now(Config.EST).strftime("%Y-%m-%d %H:%M:%S %Z")
    text = f"Captured: {timestamp}"
    
    # Try to use a common font, but fall back to a default if not found.
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except IOError:
        font = ImageFont.load_default()

    # Calculate text size to perfectly position the watermark
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = text_bbox[2] - text_bbox[0], text_bbox[3] - text_bbox[1]
    
    # Position watermark in the top-right corner with padding.
    padding = 15
    x = image.width - text_width - padding
    y = padding
    
    # Draw a semi-transparent rectangle behind the text for visibility.
    bg_padding = 8
    draw.rectangle(
        (x - bg_padding, y - bg_padding, x + text_width + bg_padding, y + text_height + bg_padding),
        fill=(0, 0, 0, 128) # Black with 50% opacity
    )
    # Draw the white text on top of the rectangle.
    draw.text((x, y), text, fill="white", font=font)

    image.convert("RGB").save(file_path) # Convert back to RGB to save as PNG
    logger.info(f"Saved watermarked screenshot to {file_path}")
    return file_path

def set_secure_permissions(file_path: str):
    """
    Sets file permissions so only the current user can read/write it.
    This is an extra security step for the credential and key files (on Linux/Mac).
    """
    if os.name != 'nt': # This check skips the function on Windows
        try:
            os.chmod(file_path, 0o600)
        except OSError as e:
            logger.warning(f"Could not set secure permissions for {file_path}: {e}")

def get_encryption_key() -> bytes:
    """
    This function gets the secret key used for encryption.
    If the key file doesn't exist, it creates a new one. This ensures
    that credentials can always be decrypted on the same computer.
    """
    if os.path.exists(Config.SECRETS_KEY_FILE):
        with open(Config.SECRETS_KEY_FILE, "rb") as f:
            return f.read()
    else:
        # Generate a new, strong encryption key.
        key = Fernet.generate_key()
        with open(Config.SECRETS_KEY_FILE, "wb") as f:
            f.write(key)
        set_secure_permissions(Config.SECRETS_KEY_FILE)
        return key

def save_credentials(username: str, password: str) -> bool:
    """
    Encrypts the username and password and saves them to a file.
    The data is not human-readable, protecting your credentials.
    """
    try:
        key = get_encryption_key()
        fernet = Fernet(key)
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
    """
    Loads and decrypts the stored credentials from the secrets file.
    """
    if not os.path.exists(Config.SECRETS_FILE):
        return None, None
    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        with open(Config.SECRETS_FILE, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        credentials = json.loads(decrypted_data.decode())
        return credentials.get("username"), credentials.get("password")
    except Exception as e:
        # This can happen if the key is lost or the file is corrupted.
        logger.error(f"Error loading credentials: {e}")
        return None, None


# =============================================================================
# SECTION 3: GUI DIALOGS (Pop-up windows)
# =============================================================================

class DashboardAddDialog(Toplevel):
    """A dialog window for adding a new dashboard to the application."""
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.title("Add New Dashboard")
        self.app = app_instance # A reference to the main app to access its data
        self.configure(bg=self.app.current_theme['bg'])

        self.transient(parent) # This dialog stays on top of the main window.
        self.grab_set() # This dialog blocks interaction with the main window.
        
        self._create_ui()

    def _create_ui(self):
        """Creates all the widgets (buttons, text boxes) for the dialog."""
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Input fields for dashboard details ---
        ttk.Label(main_frame, text="Dashboard Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.name_var, width=50).grid(row=0, column=1, sticky="ew")

        ttk.Label(main_frame, text="Dashboard URL:").grid(row=1, column=0, sticky="w", pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.url_var, width=50).grid(row=1, column=1, sticky="ew")

        # --- Checkboxes for selecting which lists this dashboard belongs to ---
        ttk.Label(main_frame, text="Add to Lists:").grid(row=2, column=0, sticky="nw", pady=(15, 5))
        self.lists_frame = ttk.Frame(main_frame)
        self.lists_frame.grid(row=2, column=1, sticky="ew")
        
        self.list_vars = {} # This dictionary will hold the state (checked/unchecked) of each checkbox.
        self.update_list_checkboxes()

        # --- Section to add a new list category on the fly ---
        new_list_frame = ttk.Frame(main_frame)
        new_list_frame.grid(row=3, column=1, sticky="ew", pady=(10, 0))
        self.new_list_var = tk.StringVar()
        ttk.Entry(new_list_frame, textvariable=self.new_list_var).pack(side=tk.LEFT, expand=True, fill=tk.X)
        ttk.Button(new_list_frame, text="Add New List", command=self.add_new_list).pack(side=tk.LEFT, padx=(5,0))

        # --- 'Add' and 'Cancel' buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20, sticky="e")
        ttk.Button(button_frame, text="Add Dashboard", command=self.on_add, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def update_list_checkboxes(self):
        """Populates the list selection area with checkboxes for each existing list."""
        for widget in self.lists_frame.winfo_children():
            widget.destroy()

        # Get all unique list names from the existing dashboards.
        existing_lists = set(['Default'])
        for dashboard in self.app.session['dashboards']:
            existing_lists.update(dashboard.get('lists', []))

        # Create a checkbox for each list.
        for i, list_name in enumerate(sorted(existing_lists)):
            var = tk.BooleanVar(value=(list_name == 'Default'))
            self.list_vars[list_name] = var
            cb = ttk.Checkbutton(self.lists_frame, text=list_name, variable=var)
            cb.grid(row=i // 3, column=i % 3, sticky="w", padx=5, pady=2) # Arrange in 3 columns

    def add_new_list(self):
        """Handles the logic for the 'Add New List' button."""
        new_list_name = self.new_list_var.get().strip()
        if not new_list_name:
            messagebox.showwarning("Invalid Name", "Please enter a list name.", parent=self)
            return
        if new_list_name in self.list_vars:
            messagebox.showinfo("Exists", "This list already exists.", parent=self)
            return
        
        # Add the new list and refresh the checkboxes.
        self.list_vars[new_list_name] = tk.BooleanVar(value=True)
        self.new_list_var.set("")
        self.update_list_checkboxes()
        # Ensure the newly added list's checkbox is automatically checked.
        if new_list_name in self.list_vars:
            self.list_vars[new_list_name].set(True)

    def on_add(self):
        """Validates input and adds the new dashboard to the main application."""
        name = self.name_var.get().strip()
        url = self.url_var.get().strip()
        selected_lists = [lname for lname, lvar in self.list_vars.items() if lvar.get()]

        # --- Input Validation ---
        if not name or not url:
            messagebox.showerror("Input Error", "Dashboard Name and URL are required.", parent=self)
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            messagebox.showerror("Input Error", "URL must start with http:// or https://.", parent=self)
            return
        if any(d["name"].strip().lower() == name.lower() for d in self.app.session["dashboards"]):
            messagebox.showerror("Input Error", "A dashboard with this name already exists.", parent=self)
            return
        if not selected_lists:
            messagebox.showerror("Input Error", "At least one list must be selected.", parent=self)
            return

        # Add the dashboard and refresh the main window's list.
        new_dashboard = {"name": name, "url": url, "lists": selected_lists, "selected": True}
        self.app.session['dashboards'].append(new_dashboard)
        self.app.save_dashboards()
        self.app.refresh_dashboard_list()
        self.app.update_list_filter()
        self.destroy() # Close the dialog.

class ScheduleConfigDialog(Toplevel):
    """A dialog for creating or editing a single analysis schedule."""
    def __init__(self, parent, app, schedule_id=None):
        super().__init__(parent)
        self.app = app
        self.schedule_id = schedule_id or str(uuid.uuid4())
        
        # Load existing schedule data if we are editing.
        existing_schedule = self.app.schedules.get(self.schedule_id) if self.schedule_id else None
        
        self.title("Edit Schedule" if existing_schedule else "Create New Schedule")
        self.transient(parent)
        self.grab_set()
        
        # UI Elements
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Schedule Name
        ttk.Label(main_frame, text="Schedule Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.name_var = tk.StringVar(value=existing_schedule.get("name", "New Schedule") if existing_schedule else "")
        ttk.Entry(main_frame, textvariable=self.name_var).grid(row=0, column=1, columnspan=2, sticky="ew")

        # Interval
        ttk.Label(main_frame, text="Run Every:").grid(row=1, column=0, sticky="w", pady=5)
        self.interval_var = tk.IntVar(value=existing_schedule.get("interval_minutes", 60) if existing_schedule else 60)
        ttk.Entry(main_frame, textvariable=self.interval_var, width=8).grid(row=1, column=1, sticky="w")
        ttk.Label(main_frame, text="minutes").grid(row=1, column=2, sticky="w", padx=5)

        # Target Lists
        ttk.Label(main_frame, text="Target Lists:").grid(row=2, column=0, sticky="nw", pady=5)
        self.lists_frame = ttk.Frame(main_frame)
        self.lists_frame.grid(row=2, column=1, columnspan=2, sticky="ew")
        self.populate_list_checkboxes(existing_schedule.get("lists", []) if existing_schedule else [])

        # Time Range
        ttk.Label(main_frame, text="Time Range:").grid(row=3, column=0, sticky="nw", pady=5)
        self.time_range_var = tk.StringVar(value=existing_schedule.get("time_range", "-4h@h") if existing_schedule else "-4h@h")
        ttk.Entry(main_frame, textvariable=self.time_range_var).grid(row=3, column=1, columnspan=2, sticky="ew")

        # Save/Cancel Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=20, sticky="e")
        ttk.Button(btn_frame, text="Save", command=self.on_save, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def populate_list_checkboxes(self, selected_lists):
        """Creates checkboxes for all available dashboard lists."""
        all_lists = set(["All"])
        for dashboard in self.app.session['dashboards']:
            all_lists.update(dashboard.get('lists', []))
        
        self.list_vars = {}
        for i, list_name in enumerate(sorted(all_lists)):
            var = tk.BooleanVar(value=(list_name in selected_lists))
            self.list_vars[list_name] = var
            cb = ttk.Checkbutton(self.lists_frame, text=list_name, variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky="w")

    def on_save(self):
        """Validates and saves the schedule configuration."""
        selected_lists = [name for name, var in self.list_vars.items() if var.get()]
        if not selected_lists:
            messagebox.showerror("Input Error", "At least one target list must be selected.", parent=self)
            return

        schedule_data = {
            "id": self.schedule_id,
            "name": self.name_var.get(),
            "interval_minutes": self.interval_var.get(),
            "lists": selected_lists,
            "time_range": self.time_range_var.get()
        }
        self.app.schedules[self.schedule_id] = schedule_data
        self.app.save_schedules()
        self.app.start_all_schedules() # Restart all schedules with the new config
        self.destroy()

class ScheduleManagerDialog(Toplevel):
    """A dialog to view, create, edit, and delete all analysis schedules."""
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.title("Schedule Manager")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()

        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Toolbar for actions ---
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=5)
        ttk.Button(toolbar, text="➕ Add", command=self.add_schedule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="✏️ Edit", command=self.edit_schedule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🗑️ Delete", command=self.delete_schedule).pack(side=tk.LEFT, padx=2)

        # --- Treeview to display the list of schedules ---
        columns = ("Name", "Interval", "Targets")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.heading("Name", text="Name")
        self.tree.heading("Interval", text="Interval (Minutes)")
        self.tree.heading("Targets", text="Target Lists")
        self.tree.column("Interval", width=120, anchor="center")
        
        self.refresh_schedules()

    def refresh_schedules(self):
        """Clears and repopulates the list of schedules."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for schedule_id, data in self.app.schedules.items():
            self.tree.insert("", "end", iid=schedule_id, values=(
                data['name'], data['interval_minutes'], ", ".join(data['lists'])
            ))

    def add_schedule(self):
        """Opens the config dialog to create a new schedule."""
        ScheduleConfigDialog(self, self.app)
        self.refresh_schedules()

    def edit_schedule(self):
        """Opens the config dialog to edit the selected schedule."""
        selected_id = self.tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a schedule to edit.")
            return
        ScheduleConfigDialog(self, self.app, schedule_id=selected_id)
        self.refresh_schedules()

    def delete_schedule(self):
        """Deletes the selected schedule."""
        selected_id = self.tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a schedule to delete.")
            return
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this schedule?"):
            del self.app.schedules[selected_id]
            self.app.save_schedules()
            self.app.start_all_schedules() # Restart schedules to remove the deleted one.
            self.refresh_schedules()


# =============================================================================
# SECTION 4: MAIN APPLICATION CLASS
# =============================================================================

class SplunkAutomatorApp:
    """The main application class that ties everything together."""
    MAX_CONCURRENT_DASHBOARDS = 3 # Run up to 3 dashboards at once to avoid overload.

    def __init__(self, master: tk.Tk):
        self.master = master
        settings = self.load_settings()
        master.title("Splunk Dashboard Automator")
        master.geometry(settings.get("geometry", "1200x900")) # Load last window size

        # --- Initialize application state ---
        self.is_dark_theme = settings.get("dark_theme", False)
        self.current_theme = Theme.DARK if self.is_dark_theme else Theme.LIGHT
        
        self.active_timers = {} # Holds the running schedule timers.
        self.schedules = self.load_schedules() # Load all saved schedules.
        
        self.status_message = tk.StringVar(value="Ready.")
        self.username, self.password = load_credentials()
        self.session = {"username": self.username, "password": self.password, "dashboards": []}

        # --- Build the UI and load data ---
        self._setup_ui()
        self._apply_theme()
        
        self.load_dashboards()
        self.update_list_filter()
        self.refresh_dashboard_list()
        
        self.start_all_schedules()

        # If no credentials are found on startup, prompt the user to enter them.
        if not self.session["username"] or not self.session["password"]:
            master.after(100, lambda: self.manage_credentials(first_time=True))

        # Perform startup cleanup.
        archive_and_clean_tmp()
        purge_old_archives()
        logger.info("SplunkAutomatorApp initialized successfully.")

    def _setup_ui(self):
        """Creates the entire main window layout and all its widgets."""
        # --- Menu Bar ---
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        schedule_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=schedule_menu)
        schedule_menu.add_command(label="Schedule Manager", command=self.open_schedule_manager)

        # --- Main Layout Frames ---
        self.master.configure(bg=self.current_theme['bg'])
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        main_pane = ttk.PanedWindow(self.master, orient=tk.VERTICAL)
        main_pane.grid(row=0, column=0, sticky="nsew")

        top_frame = ttk.Frame(main_pane, padding=15)
        bottom_frame = ttk.Frame(main_pane, padding=15)
        main_pane.add(top_frame, weight=1)
        main_pane.add(bottom_frame)

        # --- TOP FRAME: Header and Dashboard List ---
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_rowconfigure(2, weight=1)
        
        header_frame = ttk.Frame(top_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        ttk.Label(header_frame, text="Splunk Dashboard Automator", font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        self.theme_btn = ttk.Button(header_frame, text="🌙" if not self.is_dark_theme else "☀️", command=self.toggle_theme, width=3)
        self.theme_btn.pack(side=tk.RIGHT)

        controls_frame = ttk.Frame(top_frame)
        controls_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        # Add icons for a cleaner look.
        ttk.Button(controls_frame, text="➕ Add", command=self.add_dashboard, width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(controls_frame, text="🗑️ Delete", command=self.delete_dashboard, width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(controls_frame, text="☑️ Select All", command=self.select_all_dashboards).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(controls_frame, text="☐ Deselect All", command=self.deselect_all_dashboards).pack(side=tk.LEFT, padx=(0, 5))
        
        filter_frame = ttk.Frame(controls_frame)
        filter_frame.pack(side=tk.RIGHT)
        ttk.Label(filter_frame, text="Filter by List:").pack(side=tk.LEFT)
        self.list_filter_var = tk.StringVar(value=self.load_settings().get("last_list", "All"))
        self.list_filter = ttk.Combobox(filter_frame, textvariable=self.list_filter_var, state="readonly", width=15)
        self.list_filter.pack(side=tk.LEFT, padx=5)
        self.list_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())

        list_container = ttk.Frame(top_frame)
        list_container.grid(row=2, column=0, sticky="nsew")
        list_container.grid_rowconfigure(0, weight=1)
        list_container.grid_columnconfigure(0, weight=1)

        columns = ("Select", "Name", "URL", "Lists", "Status")
        self.treeview = ttk.Treeview(list_container, columns=columns, show="headings", selectmode="extended")
        v_scroll = ttk.Scrollbar(list_container, orient="vertical", command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=v_scroll.set)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.treeview.bind("<Button-1>", self.on_treeview_click)
        
        col_configs = [("Select", 60, "center"), ("Name", 250, "w"), ("URL", 400, "w"), ("Lists", 200, "w"), ("Status", 250, "w")]
        for col, width, anchor in col_configs:
            self.treeview.heading(col, text=col)
            self.treeview.column(col, width=width, anchor=anchor, minwidth=width)

        # --- BOTTOM FRAME: Time Range and Actions ---
        bottom_frame.grid_columnconfigure(1, weight=1)
        time_frame = ttk.LabelFrame(bottom_frame, text="Time Range Selection", padding=10)
        time_frame.grid(row=0, column=0, sticky="ns", padx=(0, 10))

        action_frame = ttk.LabelFrame(bottom_frame, text="Actions", padding=10)
        action_frame.grid(row=0, column=1, sticky="nsew")
        action_frame.grid_columnconfigure(0, weight=1)

        # --- Integrated Time Range Controls ---
        self.time_choice = tk.StringVar(value="preset")
        ttk.Radiobutton(time_frame, text="Presets", variable=self.time_choice, value="preset", command=self._update_time_controls).pack(anchor="w")
        ttk.Radiobutton(time_frame, text="Relative", variable=self.time_choice, value="relative", command=self._update_time_controls).pack(anchor="w")
        self.time_controls_frame = ttk.Frame(time_frame, padding=(15, 5, 0, 0))
        self.time_controls_frame.pack(anchor="w")
        self._update_time_controls() # Create the initial controls

        # --- Action Buttons and Progress Bar ---
        ttk.Button(action_frame, text="📸 Capture Screenshots", command=lambda: self._start_processing_job(capture_only=True)).grid(row=0, column=0, pady=5, sticky="ew")
        ttk.Button(action_frame, text="📊 Analyze Dashboards", command=lambda: self._start_processing_job(capture_only=False)).grid(row=1, column=0, pady=5, sticky="ew")
        self.progress_bar = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=2, column=0, pady=(10,0), sticky="ew")

        # --- Status Bar ---
        status_bar = ttk.Frame(self.master, padding=(10, 5))
        status_bar.grid(row=1, column=0, sticky="ew")
        ttk.Label(status_bar, textvariable=self.status_message, anchor="w").pack(side=tk.LEFT)
        self.connection_status = ttk.Label(status_bar, text="●", foreground="red" if not self.username else "green")
        ttk.Button(status_bar, text="🔑", command=self.manage_credentials, width=3).pack(side=tk.RIGHT)
        self.connection_status.pack(side=tk.RIGHT, padx=5)
    
    def _update_time_controls(self):
        """Dynamically shows the correct time controls based on user selection."""
        for widget in self.time_controls_frame.winfo_children():
            widget.destroy()

        choice = self.time_choice.get()
        if choice == "preset":
            self.time_preset_map = {"Last 15m": "-15m", "Last 60m": "-60m", "Last 4h": "-4h", "Last 24h": "-24h", "Last 7d": "-7d"}
            self.time_preset_var = tk.StringVar(value="Last 4h")
            ttk.Combobox(self.time_controls_frame, textvariable=self.time_preset_var, values=list(self.time_preset_map.keys()), state="readonly").pack()
        elif choice == "relative":
            ttk.Label(self.time_controls_frame, text="Amount:").pack(side=tk.LEFT)
            self.time_rel_amount = ttk.Entry(self.time_controls_frame, width=5)
            self.time_rel_amount.insert(0, "4")
            self.time_rel_amount.pack(side=tk.LEFT)

            ttk.Label(self.time_controls_frame, text="Unit:").pack(side=tk.LEFT, padx=(5,0))
            self.time_rel_unit = ttk.Combobox(self.time_controls_frame, values=["minutes", "hours", "days"], state="readonly", width=8)
            self.time_rel_unit.set("hours")
            self.time_rel_unit.pack(side=tk.LEFT)
    
    def _get_time_range_from_ui(self) -> Optional[Dict]:
        """Reads the time range from the main UI controls and returns it."""
        try:
            choice = self.time_choice.get()
            if choice == "preset":
                return {'start': self.time_preset_map[self.time_preset_var.get()], 'end': 'now'}
            elif choice == "relative":
                amount = int(self.time_rel_amount.get())
                unit = self.time_rel_unit.get()[0] # m, h, or d
                return {'start': f'-{amount}{unit}', 'end': 'now'}
        except (ValueError, TypeError) as e:
            messagebox.showerror("Input Error", f"Invalid time range input: {e}")
            return None
        return None

    def _apply_theme(self):
        """Applies the selected color theme to all UI elements."""
        style = ttk.Style()
        theme = self.current_theme
        style.theme_use('clam')
        
        # Configure styles for all widget types.
        style.configure('.', background=theme['bg'], foreground=theme['fg'], fieldbackground=theme['button_bg'])
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TRadiobutton', background=theme['bg'], foreground=theme['fg'])
        style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'], padding=5)
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
        """Switches between the light and dark themes."""
        self.is_dark_theme = not self.is_dark_theme
        self.current_theme = Theme.DARK if self.is_dark_theme else Theme.LIGHT
        self.theme_btn.configure(text="🌙" if not self.is_dark_theme else "☀️")
        self._apply_theme()
        self.save_settings()

    # --- Dashboard and List Management ---
    
    def add_dashboard(self):
        """Opens the 'Add Dashboard' dialog."""
        DashboardAddDialog(self.master, self)

    def delete_dashboard(self):
        """Deletes all selected dashboards from the list."""
        selection = self.treeview.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select dashboards to delete.")
            return

        if messagebox.askyesno("Confirm Delete", f"Delete {len(selection)} dashboard(s)? This cannot be undone."):
            # Get the unique names of dashboards to delete from the treeview.
            names_to_delete = {self.treeview.item(item_id)['values'][1] for item_id in selection}
            # Recreate the dashboard list, excluding the ones marked for deletion.
            self.session['dashboards'] = [db for db in self.session['dashboards'] if db['name'] not in names_to_delete]
            self.save_dashboards()
            self.refresh_dashboard_list()
            self.update_list_filter()

    def select_all_dashboards(self):
        """Selects all dashboards currently visible in the list."""
        current_filter = self.list_filter_var.get()
        for db in self.session['dashboards']:
            if current_filter == "All" or current_filter in db.get('lists', []):
                db['selected'] = True
        self.refresh_dashboard_list()

    def deselect_all_dashboards(self):
        """Deselects all dashboards currently visible in the list."""
        current_filter = self.list_filter_var.get()
        for db in self.session['dashboards']:
            if current_filter == "All" or current_filter in db.get('lists', []):
                db['selected'] = False
        self.refresh_dashboard_list()

    def on_treeview_click(self, event):
        """Handles clicks on the checkbox column in the dashboard list."""
        item_id = self.treeview.identify_row(event.y)
        column = self.treeview.identify_column(event.x)
        # Only proceed if the click was on the first column (the checkbox).
        if not item_id or column != "#1":
            return
        
        # Find the dashboard by its unique name and toggle its 'selected' state.
        clicked_name = self.treeview.item(item_id)['values'][1]
        for db in self.session['dashboards']:
            if db['name'] == clicked_name:
                db["selected"] = not db.get("selected", False)
                self.refresh_dashboard_list()
                break

    def refresh_dashboard_list(self):
        """Clears and repopulates the dashboard list based on the current filter."""
        for item in self.treeview.get_children():
            self.treeview.delete(item)

        selected_filter = self.list_filter_var.get()
        for dashboard in self.session['dashboards']:
            dashboard_lists = dashboard.get('lists', ['Default'])
            if selected_filter == "All" or selected_filter in dashboard_lists:
                selected_char = "☑" if dashboard.get("selected", False) else "☐"
                status = dashboard.get('status', 'Ready')
                self.treeview.insert("", "end", values=(selected_char, dashboard['name'], dashboard['url'], ", ".join(dashboard_lists), status))
        
        self.update_status_summary()

    def update_list_filter(self):
        """Updates the 'Filter by List' dropdown with all available list names."""
        all_lists = set(['All', 'Default'])
        for dashboard in self.session['dashboards']:
            all_lists.update(dashboard.get('lists', []))
        
        sorted_lists = sorted(list(all_lists))
        self.list_filter['values'] = sorted_lists
        if self.list_filter_var.get() not in sorted_lists:
            self.list_filter_var.set("All")

    # --- Core Processing and Scheduling Logic ---

    def _start_processing_job(self, capture_only: bool, schedule_data: Optional[Dict] = None):
        """
        The main function to start a dashboard processing job. It can be triggered
        manually by a button or automatically by a schedule.
        """
        # Determine which dashboards to process.
        if schedule_data:
            # For a scheduled job, select dashboards based on the schedule's target lists.
            target_lists = set(schedule_data.get('lists', []))
            selected_dbs = []
            for db in self.session['dashboards']:
                if "All" in target_lists or not target_lists.isdisjoint(db.get('lists', [])):
                    selected_dbs.append(db)
        else:
            # For a manual job, process the user-selected dashboards.
            selected_dbs = [db for db in self.session['dashboards'] if db.get('selected', False)]

        if not selected_dbs:
            messagebox.showwarning("No Selection", "Please select at least one dashboard to process.")
            return
        if not self.session['username'] or not self.session['password']:
            messagebox.showerror("Credentials Required", "Please set your Splunk credentials via the 🔑 button.")
            return

        # Get the time range and retry count.
        time_range = schedule_data['time_range'] if schedule_data else self._get_time_range_from_ui()
        if time_range is None: return # User cancelled or entered invalid time.
        retry_count = 2 # Default for schedules, can be customized later.
        if not schedule_data:
             retry_count = simpledialog.askinteger("Retry Count", "Retry how many times on failure?", initialvalue=2, minvalue=0, maxvalue=5)
             if retry_count is None: return
        
        # Update the UI to show the job is starting.
        self.progress_bar['maximum'] = len(selected_dbs)
        self.progress_bar['value'] = 0
        for db in selected_dbs:
            self.update_dashboard_status(db['name'], "Queued")
        
        job_type = "screenshot capture" if capture_only else "analysis"
        self.update_status(f"Starting {job_type} for {len(selected_dbs)} dashboards...")

        # Run the actual browser automation in a separate thread to avoid freezing the UI.
        def run_async_job():
            asyncio.run(self._process_dashboards_async(selected_dbs, time_range, retry_count, add_watermark=capture_only, wait_full_load=not capture_only, operation_name=job_type))
        
        Thread(target=run_async_job, name=f"{job_type}-thread", daemon=True).start()

    async def _process_dashboards_async(self, dashboards: List[Dict], time_range: Dict, retries: int, add_watermark: bool, wait_full_load: bool, operation_name: str):
        """The core asynchronous function that processes all dashboards in parallel."""
        # Use a 'semaphore' to limit how many browsers open at once.
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_DASHBOARDS)
        # Launch Playwright to control the browser.
        async with async_playwright() as playwright:
            # Create a processing task for each dashboard.
            tasks = [self._process_single_dashboard_wrapper(playwright, db, time_range, retries, add_watermark, wait_full_load, semaphore, i) for i, db in enumerate(dashboards)]
            await asyncio.gather(*tasks) # Run all tasks concurrently.
        
        # Once all tasks are done, update the UI.
        self.master.after(0, lambda: self._on_operation_complete(operation_name))

    async def _process_single_dashboard_wrapper(self, playwright, dashboard, time_range, retries, add_watermark, wait_full_load, semaphore, index):
        """A wrapper that handles retries for a single dashboard."""
        async with semaphore: # This will wait if too many dashboards are already running.
            for attempt in range(retries + 1):
                try:
                    await self.process_single_dashboard(playwright, dashboard, time_range, add_watermark, wait_full_load)
                    break # If successful, break the retry loop.
                except Exception as e:
                    logger.warning(f"Attempt {attempt + 1} failed for {dashboard['name']}: {e}")
                    self.update_dashboard_status(dashboard['name'], f"Retry {attempt + 1} failed")
                    if attempt == retries:
                        self.update_dashboard_status(dashboard['name'], "❌ Failed")
            # Update the main progress bar.
            self.master.after(0, lambda: self.progress_bar.step())

    async def process_single_dashboard(self, playwright, dashboard_data: Dict, time_range: Dict, add_watermark: bool, wait_full_load: bool):
        """The function that performs the browser automation for one dashboard."""
        name, url = dashboard_data['name'], dashboard_data['url']
        logger.info(f"Processing '{name}'. Full load: {wait_full_load}, Watermark: {add_watermark}")
        self.update_dashboard_status(name, "Launching browser...")
        
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1920, 'height': 1080})
        page = await context.new_page()
        
        try:
            full_url = self.format_time_for_url(url, time_range)
            await page.goto(full_url, timeout=90000, wait_until='domcontentloaded')

            # --- Intelligent Authentication Check ---
            # Look for the username field. If it's not visible after a short wait,
            # assume we are already logged in and skip this block.
            if await page.locator('input[name="username"]').is_visible(timeout=5000):
                self.update_dashboard_status(name, "Authenticating...")
                await page.fill('input[name="username"]', self.session['username'])
                await page.fill('input[name="password"]', self.session['password'])
                await page.click('button[type="submit"], input[type="submit"]')
                await page.wait_for_url(lambda url: "account/login" not in url, timeout=15000)

            # For 'Analyze' mode, wait for the dashboard's loading spinners to disappear.
            if wait_full_load:
                self.update_dashboard_status(name, "Waiting for panels to load...")
                # This is a generic wait that works for both Classic and Studio dashboards.
                await page.wait_for_function("() => !document.querySelector('.spl-spinner, .dashboard-loading')", timeout=120000)
                await asyncio.sleep(5) # Extra wait time for data to fully render.

            self.update_dashboard_status(name, "Capturing...")
            screenshot_bytes = await page.screenshot(full_page=True)
            
            filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now().strftime('%H%M%S')}.png"
            
            if add_watermark:
                save_screenshot_with_watermark(screenshot_bytes, filename)
            else:
                # Save without a watermark for analysis.
                image = Image.open(io.BytesIO(screenshot_bytes))
                image.save(os.path.join(Config.TMP_DIR, datetime.now().strftime("%Y-%m-%d"), filename))

            self.update_dashboard_status(name, f"✅ Success")
        finally:
            await browser.close() # Always ensure the browser is closed.

    def format_time_for_url(self, base_url: str, time_range: Dict) -> str:
        """Appends the correct time range parameters to the Splunk dashboard URL."""
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        prefix = "form.time" # Standard prefix for Splunk time pickers.
        query_params[f'{prefix}.earliest'] = time_range['start']
        query_params[f'{prefix}.latest'] = time_range['end']
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query))

    def _on_operation_complete(self, operation_name: str):
        """A callback function to run on the UI thread after a job is finished."""
        self.update_status(f"{operation_name.capitalize()} completed.")
        messagebox.showinfo("Complete", f"{operation_name.capitalize()} has finished.")
        self.progress_bar['value'] = 0

    # --- Scheduling System ---
    
    def open_schedule_manager(self):
        """Opens the dialog to manage all schedules."""
        ScheduleManagerDialog(self.master, self)

    def start_all_schedules(self):
        """Cancels all existing timers and starts new ones based on the schedule file."""
        for timer_id in self.active_timers.values():
            self.master.after_cancel(timer_id)
        self.active_timers.clear()
        
        for schedule_id, data in self.schedules.items():
            interval_ms = data['interval_minutes'] * 60 * 1000
            
            # This is the function that will be called on schedule.
            def scheduled_run(schedule_data=data):
                logger.info(f"Executing scheduled run: {schedule_data['name']}")
                self.update_status(f"Running schedule: {schedule_data['name']}...")
                # The 'schedule_data' contains the time range and dashboard lists to use.
                self._start_processing_job(capture_only=False, schedule_data=schedule_data)
                # Reschedule itself for the next run.
                self.active_timers[schedule_data['id']] = self.master.after(interval_ms, lambda: scheduled_run(schedule_data))
            
            self.active_timers[schedule_id] = self.master.after(interval_ms, scheduled_run)
        
        if self.schedules:
            logger.info(f"Started {len(self.schedules)} schedule(s).")
            
    # --- Helper Functions and State Management ---
    
    def manage_credentials(self, first_time: bool = False):
        # This is identical to the dialog in Section 3, just called from the main app.
        DashboardAddDialog(self.master, self)

    def update_dashboard_status(self, dashboard_name: str, status: str):
        """Updates a dashboard's status in the UI list safely from any thread."""
        def update_ui():
            # Update the status in the main data list.
            for db in self.session['dashboards']:
                if db['name'] == dashboard_name:
                    db['status'] = status
                    break
            # Find the corresponding row in the visible tree and update it.
            for item_id in self.treeview.get_children():
                if self.treeview.item(item_id)['values'][1] == dashboard_name:
                    current_values = list(self.treeview.item(item_id)['values'])
                    current_values[4] = status
                    self.treeview.item(item_id, values=tuple(current_values))
                    break
        # `after(0, ...)` ensures this UI update runs on the main GUI thread.
        self.master.after(0, update_ui)
    
    def update_status_summary(self):
        """Updates the main status bar with a summary of dashboard counts."""
        total = len(self.session['dashboards'])
        selected = sum(1 for d in self.session['dashboards'] if d.get('selected', False))
        self.update_status(f"{total} dashboards loaded ({selected} selected).")

    def update_status(self, message: str):
        """Updates the text in the bottom status bar."""
        self.status_message.set(message)
        logger.info(f"Status: {message}")
        
    def load_schedules(self) -> Dict:
        """Loads all schedules from the JSON file into a dictionary."""
        if not os.path.exists(Config.SCHEDULE_FILE):
            return {}
        try:
            with open(Config.SCHEDULE_FILE, 'r') as f:
                # The file stores a list, we convert it to a dictionary keyed by ID.
                schedules_list = json.load(f)
                return {s['id']: s for s in schedules_list}
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"Error loading schedules: {e}")
            return {}

    def save_schedules(self):
        """Saves all schedules from the dictionary back to the JSON file."""
        try:
            with open(Config.SCHEDULE_FILE, 'w') as f:
                # Convert the dictionary back to a list for storage.
                json.dump(list(self.schedules.values()), f, indent=4)
        except OSError as e:
            logger.error(f"Error saving schedules: {e}")

    def load_dashboards(self):
        """Loads the list of dashboards from its JSON file."""
        if not os.path.exists(Config.DASHBOARD_FILE):
            self.session['dashboards'] = []
            return
        try:
            with open(Config.DASHBOARD_FILE, 'r', encoding='utf-8') as f:
                dashboards = json.load(f)
            # This handles migrating data from an older format if necessary.
            for db in dashboards:
                if 'lists' not in db: db['lists'] = ['Default']
            self.session['dashboards'] = dashboards
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Error loading dashboards: {e}")
            self.session['dashboards'] = []
    
    def save_dashboards(self):
        """Saves the current list of dashboards to its JSON file."""
        try:
            with open(Config.DASHBOARD_FILE, 'w', encoding='utf-8') as f:
                # Don't save temporary runtime status to the file.
                dashboards_to_save = [{k: v for k, v in db.items() if k != 'status'} for db in self.session['dashboards']]
                json.dump(dashboards_to_save, f, indent=4)
        except OSError as e:
            logger.error(f"Error saving dashboards: {e}")

    def load_settings(self) -> Dict[str, Any]:
        """Loads application settings like window size and theme."""
        if not os.path.exists(Config.SETTINGS_FILE): return {}
        try:
            with open(Config.SETTINGS_FILE, "r", encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load settings: {e}")
            return {}

    def save_settings(self):
        """Saves the current window size and theme choice."""
        settings = {
            "geometry": self.master.geometry(),
            "dark_theme": self.is_dark_theme,
            "last_list": self.list_filter_var.get(),
        }
        try:
            with open(Config.SETTINGS_FILE, "w", encoding='utf-8') as f:
                json.dump(settings, f, indent=4)
        except OSError as e:
            logger.error(f"Error saving settings: {e}")

    def on_closing(self):
        """Called when the user closes the application window."""
        self.save_settings()
        self.master.destroy()

# =============================================================================
# SECTION 5: APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # This is the code that runs when the script is executed.
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    # Ensure settings are saved when the window is closed.
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    # Start the Tkinter event loop to show the window and handle events.
    root.mainloop()
