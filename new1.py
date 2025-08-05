# =================================================================================================
# Splunk Dashboard Automator - Definitive Edition
# =================================================================================================
#
# Author: Gemini, Google AI
# Version: 6.2 (Bugfix Corrected)
# Last Updated: 2025-08-05
#
# Description:
# This application provides a comprehensive desktop GUI to automate interactions with Splunk
# dashboards. It is the culmination of multiple feature requests, designed to be user-friendly,
# robust, and powerful.
#
# Core Features:
#   - Modern UI: A visually appealing interface with selectable Light and Dark themes via the menu.
#   - Advanced Dashboard Management: Easily add, edit, and delete dashboards with a refined UI.
#   - Multi-List Organization: Assign dashboards to multiple custom lists for superior grouping.
#   - Integrated Time Frame: A powerful time range selector is now part of the main UI,
#     eliminating the need for pop-ups during standard operation.
#   - Dual-Mode Capture:
#       1. "Capture Screenshots": Quickly takes a screenshot with an enhanced, highly visible watermark.
#       2. "Analyze Dashboards": A deeper process that waits for dashboards to fully load
#          and saves a clean screenshot WITHOUT a watermark.
#   - Intelligent Splunk Logic: Automatically detects Splunk Studio vs. Classic dashboards
#     and adjusts its waiting logic for optimal performance.
#   - Secure Credential Storage: Encrypts and saves your Splunk username and password securely
#     so you only have to enter them once.
#   - Advanced Scheduling: A built-in manager to create, view, edit, delete, and toggle
#     multiple, persistent schedules to run analysis jobs automatically.
#
# =================================================================================================


# --- Section 1: Importing Necessary Libraries ---
# These are the building blocks of our application. We import libraries for the user interface,
# automation, file handling, and security.

# For creating the graphical user interface (GUI)
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, Listbox

# For running browser automation and other tasks without freezing the app
import asyncio
from threading import Thread

# For handling dates, times, and timezones
from datetime import datetime, timedelta, time as dt_time
import pytz

# For interacting with the computer's operating system (e.g., managing files and folders)
import os
import sys
import shutil

# For data handling and text processing
import json
import re
import io
import uuid # For generating unique IDs
from typing import Dict, List, Any, Optional, Tuple

# For advanced GUI elements like a pop-up calendar
try:
    from tkcalendar import DateEntry
except ImportError:
    messagebox.showerror("Missing Library", "The 'tkcalendar' library is required.\nPlease run: pip install tkcalendar")
    sys.exit(1)

# For controlling a web browser to interact with Splunk
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    messagebox.showerror("Missing Library", "The 'playwright' library is required.\nPlease run: pip install playwright")
    sys.exit(1)

# For adding watermarks to images
from PIL import Image, ImageDraw, ImageFont

# For strong encryption to keep your credentials safe
from cryptography.fernet import Fernet

# For handling and constructing web URLs correctly
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

# For logging events and errors
import logging
from logging.handlers import RotatingFileHandler


# =============================================================================
# SECTION 2: APPLICATION CONFIGURATION
# =============================================================================
# This section centralizes all the settings for the application, making it
# easy to change things like file names, colors, and behavior in one place.

class Config:
    """
    This class holds all the important constant values (configurations) for the application.
    """
    # --- File and Folder Locations ---
    LOG_DIR = "logs"                        # Folder to store log files for troubleshooting.
    TMP_DIR = "tmp"                         # Temporary folder for screenshots during processing.
    SCREENSHOT_ARCHIVE_DIR = "screenshots"  # Folder where daily screenshots are permanently archived.
    DASHBOARD_FILE = "dashboards.json"      # File to save all your dashboard configurations.
    SCHEDULE_FILE = "schedules.json"        # File to save all your automation schedules.
    SETTINGS_FILE = "settings.json"         # File to save your personal UI settings (like theme).
    SECRETS_KEY_FILE = ".secrets.key"       # The key used to encrypt your credentials.
    SECRETS_FILE = ".secrets"               # The encrypted file containing your credentials.

    # --- Application Behavior ---
    DAYS_TO_KEEP_ARCHIVES = 3  # How many days of old screenshots to keep before deleting.
    MAX_CONCURRENT_DASHBOARDS = 3 # How many dashboards to process at the same time.

    # --- Timezone for Watermarks ---
    # We use a standard timezone to ensure all timestamps are consistent.
    EST = pytz.timezone("America/New_York")

class Theme:
    """
    This class defines the color schemes for the Light and Dark themes.
    A good theme makes the application much more pleasant to use.
    """
    # Colors for the Light theme - clean and professional.
    LIGHT = {
        'name': 'Light',
        'bg': '#FDFDFD', 'fg': '#000000', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF',
        'button_bg': '#F0F0F0', 'button_fg': '#000000', 'frame_bg': '#F1F1F1', 'accent': '#0078D4',
        'tree_bg': '#FFFFFF', 'tree_fg': '#000000'
    }
    # Colors for the Dark theme - easy on the eyes, especially at night.
    DARK = {
        'name': 'Dark',
        'bg': '#1E1E1E', 'fg': '#FFFFFF', 'select_bg': '#0078D4', 'select_fg': '#FFFFFF',
        'button_bg': '#2D2D30', 'button_fg': '#FFFFFF', 'frame_bg': '#252526', 'accent': '#0078D4',
        'tree_bg': '#2A2D2E', 'tree_fg': '#CCCCCC'
    }

# --- Set up Logging ---
# Logging records important events and errors to a file. This is extremely helpful
# for figuring out what went wrong if the application ever has a problem.
os.makedirs(Config.LOG_DIR, exist_ok=True)
log_file = os.path.join(Config.LOG_DIR, f"app_{datetime.now().strftime('%Y%m%d')}.log")
logger = logging.getLogger("SplunkAutomator")
logger.setLevel(logging.INFO) # Record informational messages and anything more severe (warnings, errors).
# This handler makes sure the log file doesn't grow infinitely large. It creates backups.
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
# This defines the format of each log message (e.g., "2025-08-04 10:30:00 [INFO] ...").
formatter = logging.Formatter('%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
# This also prints log messages to the console for real-time feedback during development.
logger.addHandler(logging.StreamHandler(sys.stdout))


# =============================================================================
# SECTION 3: CORE UTILITIES (File System, Encryption, etc.)
# =============================================================================
# These are helper functions that perform common tasks needed throughout the application.

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
            shutil.rmtree(archive_path, ignore_errors=True) # Remove old archive if it exists
            shutil.move(folder_path, archive_path)
            logger.info(f"Archived {folder_path} to {archive_path}")

def purge_old_archives():
    """Deletes archived screenshot folders that are older than the configured number of days."""
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

    # Try to use a bolder font for better visibility, with fallbacks.
    try: font = ImageFont.truetype("arialbd.ttf", 30)
    except IOError:
        try: font = ImageFont.truetype("arial.ttf", 30)
        except IOError: font = ImageFont.load_default()

    # Calculate text size to perfectly position the watermark
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = text_bbox[2] - text_bbox[0], text_bbox[3] - text_bbox[1]
    
    # Position watermark in the bottom-right corner with padding.
    padding = 20
    x = image.width - text_width - padding
    y = image.height - text_height - padding
    
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
        try: os.chmod(file_path, 0o600)
        except OSError as e: logger.warning(f"Could not set secure permissions for {file_path}: {e}")

def get_encryption_key() -> bytes:
    """
    This function gets the secret key used for encryption. If the key file doesn't
    exist, it creates a new one. This ensures credentials can always be decrypted
    on the same computer.
    """
    if os.path.exists(Config.SECRETS_KEY_FILE):
        with open(Config.SECRETS_KEY_FILE, "rb") as f: return f.read()
    else:
        key = Fernet.generate_key()
        with open(Config.SECRETS_KEY_FILE, "wb") as f: f.write(key)
        set_secure_permissions(Config.SECRETS_KEY_FILE)
        return key

def save_credentials(username: str, password: str) -> bool:
    """
    Encrypts the username and password and saves them to a file.
    The data is not human-readable, protecting your credentials.
    """
    try:
        fernet = Fernet(get_encryption_key())
        credentials = {"username": username, "password": password}
        encrypted_data = fernet.encrypt(json.dumps(credentials).encode())
        with open(Config.SECRETS_FILE, "wb") as f: f.write(encrypted_data)
        set_secure_permissions(Config.SECRETS_FILE)
        logger.info("Credentials saved securely.")
        return True
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        return False

def load_credentials() -> Tuple[Optional[str], Optional[str]]:
    """Loads and decrypts the stored credentials from the secrets file."""
    if not os.path.exists(Config.SECRETS_FILE): return None, None
    try:
        fernet = Fernet(get_encryption_key())
        with open(Config.SECRETS_FILE, "rb") as f: encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        credentials = json.loads(decrypted_data.decode())
        return credentials.get("username"), credentials.get("password")
    except Exception as e:
        # This can happen if the key is lost or the file is corrupted.
        logger.error(f"Error loading credentials: {e}")
        return None, None


# =============================================================================
# SECTION 4: GUI DIALOGS AND FRAMES
# =============================================================================
# This section contains the code for all pop-up windows (dialogs) and complex
# UI components like the integrated time range selector.

# --- Time Range Selection Frame - Integrated into Main UI (WITH FIXED HEIGHT/SCROLLBAR) ---
class TimeRangeFrame(ttk.LabelFrame):
    """Integrated frame for selecting time range for Splunk queries."""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, text="Time Range Selection (EST)", *args, **kwargs)
        self.est = Config.EST
        self.result = {} # Stores the selected time range
        self._setup_ui()
        self.show_selected_frame() # Show default frame

    def _setup_ui(self):
        # Configure the main frame's columns: left for options, right for content
        self.grid_columnconfigure(1, weight=1) # Let content area expand horizontally

        # --- Left Side: Time Range Options ---
        left_frame = ttk.Frame(self) # Frame for radio buttons
        left_frame.grid(row=0, column=0, sticky="nw", padx=(5, 10), pady=5)

        options = ["Presets", "Relative", "Date Range", "Date & Time Range", "Advanced"]
        self.option_var = tk.StringVar(value=options[0])
        for option in options:
            rb = ttk.Radiobutton(
                left_frame, 
                text=option, 
                variable=self.option_var, 
                value=option, 
                command=self.show_selected_frame
            )
            rb.pack(anchor="w", pady=2, fill=tk.X) # Fill X for better button appearance

        # --- Right Side: Content Area with Scrollbar ---
        # Create a fixed-size container for the scrollable content
        # Using a standard tk.Frame for fixed pixel dimensions
        content_container = tk.Frame(self, width=500, height=180) # Adjust width/height as needed
        content_container.grid(row=0, column=1, sticky="nsew", padx=(0, 5), pady=5)
        content_container.grid_propagate(False) # Prevent the frame from shrinking to fit its contents

        # Create a Canvas and a Scrollbar inside the container
        self.canvas = tk.Canvas(content_container, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(content_container, orient="vertical", command=self.canvas.yview)
        
        # Create the frame that will hold the actual content
        self.scrollable_content_frame = ttk.Frame(self.canvas)

        # Configure scrolling
        self.scrollable_content_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_content_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack canvas and scrollbar within the fixed container
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Handle resizing of the canvas window (important for dynamic content)
        def on_canvas_resize(event):
             canvas_width = event.width
             self.canvas.itemconfig(self.canvas_window, width=canvas_width)

        self.canvas.bind("<Configure>", on_canvas_resize)

        # --- Create Frames for Each Option ---
        self.frames = {option: ttk.Frame(self.scrollable_content_frame) for option in options}
        self.build_presets_frame(self.frames["Presets"])
        self.build_relative_frame(self.frames["Relative"])
        self.build_date_range_frame(self.frames["Date Range"])
        self.build_datetime_range_frame(self.frames["Date & Time Range"])
        self.build_advanced_frame(self.frames["Advanced"])

        # Pack the initially selected frame
        self.show_selected_frame()

    def show_selected_frame(self):
        """Show the frame corresponding to the selected option."""
        for frame in self.frames.values():
            frame.pack_forget()
        # Pack the selected frame into the scrollable content frame
        self.frames[self.option_var.get()].pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def build_presets_frame(self, parent):
        """Builds the UI for the 'Presets' option."""
        self.preset_splunk_ranges = {
            "Last 15 minutes": ("-15m@m", "now"),
            "Last 60 minutes": ("-60m@m", "now"),
            "Last 4 hours": ("-4h@h", "now"),
            "Last 24 hours": ("-24h@h", "now"),
            "Last 7 days": ("-7d@d", "now"),
            "Last 30 days": ("-30d@d", "now"),
            "Today": ("@d", "now"),
            "Yesterday": ("-1d@d", "@d"),
            "Previous week": ("-1w@w", "@w"),
            "Previous month": ("-1mon@mon", "@mon"),
            "Previous year": ("-1y@y", "@y"),
            "Week to date": ("@w", "now"),
            "Month to date": ("@mon", "now"),
            "Year to date": ("@y", "now"),
            "All time": ("0", "now"),
        }
        presets = list(self.preset_splunk_ranges.keys())

        # Use nested frames for better layout control within the scrollable area
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Use a canvas with scrollbar for presets if there are many
        canvas = tk.Canvas(main_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Create buttons for each preset
        for i, preset in enumerate(presets):
            btn = ttk.Button(
                scrollable_frame,
                text=preset,
                width=25, # Fixed width for consistency
                command=lambda p=preset: self.select_preset(self.preset_splunk_ranges[p]) # Pass the actual range
            )
            btn.pack(pady=2, padx=10, fill=tk.X)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def build_relative_frame(self, parent):
        """Builds the UI for the 'Relative' option."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Time range from now back to:").pack(anchor="w")
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.relative_amount = ttk.Entry(options_frame, width=5)
        self.relative_amount.pack(side=tk.LEFT, padx=2)
        self.relative_amount.insert(0, "1")
        
        units = ["minutes", "hours", "days", "weeks", "months", "years"]
        self.relative_unit = ttk.Combobox(options_frame, values=units, state="readonly", width=10)
        self.relative_unit.current(1) # Default to hours
        self.relative_unit.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(options_frame, text="ago until now").pack(side=tk.LEFT, padx=5)

    def build_date_range_frame(self, parent):
        """Builds the UI for the 'Date Range' option."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Date Range").pack(anchor="w")
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(controls_frame, text="Between").pack(side=tk.LEFT)
        self.start_date = DateEntry(controls_frame, date_pattern='y-mm-dd')
        self.start_date.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="and").pack(side=tk.LEFT, padx=5)
        self.end_date = DateEntry(controls_frame, date_pattern='y-mm-dd')
        self.end_date.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="(00:00:00 to 23:59:59)").pack(side=tk.LEFT, padx=5)

    def build_datetime_range_frame(self, parent):
        """Builds the UI for the 'Date & Time Range' option."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Date & Time Range").pack(anchor="w")
        
        # Earliest
        start_frame = ttk.Frame(frame)
        start_frame.pack(fill=tk.X, pady=5)
        ttk.Label(start_frame, text="Earliest:").pack(side=tk.LEFT)
        self.dt_start_date = DateEntry(start_frame, date_pattern='y-mm-dd')
        self.dt_start_date.pack(side=tk.LEFT, padx=5)
        self.dt_start_time = ttk.Entry(start_frame, width=12)
        self.dt_start_time.insert(0, "00:00:00")
        self.dt_start_time.pack(side=tk.LEFT, padx=5)
        
        # Latest
        end_frame = ttk.Frame(frame)
        end_frame.pack(fill=tk.X, pady=5)
        ttk.Label(end_frame, text="Latest:  ").pack(side=tk.LEFT) # Extra space for alignment
        self.dt_end_date = DateEntry(end_frame, date_pattern='y-mm-dd')
        self.dt_end_date.pack(side=tk.LEFT, padx=5)
        self.dt_end_time = ttk.Entry(end_frame, width=12)
        self.dt_end_time.insert(0, "23:59:59")
        self.dt_end_time.pack(side=tk.LEFT, padx=5)

    def build_advanced_frame(self, parent):
        """Builds the UI for the 'Advanced' option."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Advanced Time Range").pack(anchor="w")
        
        epoch_frame = ttk.Frame(frame)
        epoch_frame.pack(fill=tk.X, pady=10)
        # Allow the entry fields to expand
        epoch_frame.columnconfigure(1, weight=1)
        
        ttk.Label(epoch_frame, text="Earliest (epoch):").grid(row=0, column=0, sticky="w", padx=2, pady=2)
        self.earliest_epoch = ttk.Entry(epoch_frame)
        self.earliest_epoch.grid(row=0, column=1, sticky="ew", padx=2, pady=2) # Sticky EW to expand
        
        ttk.Label(epoch_frame, text="Latest (epoch):").grid(row=1, column=0, sticky="w", padx=2, pady=2)
        self.latest_epoch = ttk.Entry(epoch_frame)
        self.latest_epoch.grid(row=1, column=1, sticky="ew", padx=2, pady=2) # Sticky EW to expand

    def select_preset(self, splunk_range_tuple):
        """Handle preset selection by storing the actual time range tuple."""
        if splunk_range_tuple:
            self.result = {"start": splunk_range_tuple[0], "end": splunk_range_tuple[1]}

    def get_time_range(self): # Renamed from get_result for consistency with uploaded files
        """Validate input and return the selected time range."""
        try:
            option = self.option_var.get()
            if option == "Presets":
                if not self.result:
                     raise ValueError("Please select a preset.")
                return self.result
            elif option == "Relative":
                amount_str = self.relative_amount.get()
                if not amount_str.isdigit() or int(amount_str) < 1:
                    raise ValueError("Relative amount must be a positive integer.")
                amount = int(amount_str)
                unit = self.relative_unit.get()
                unit_map = {
                    "minutes": "m",
                    "hours": "h",
                    "days": "d",
                    "weeks": "w",
                    "months": "mon",
                    "years": "y",
                }
                if unit not in unit_map:
                    raise ValueError("Invalid unit selected.")
                splunk_unit = unit_map[unit]
                earliest = f"-{amount}{splunk_unit}"
                return {"start": earliest, "end": "now"}
            elif option == "Date Range":
                start_date = self.start_date.get_date()
                end_date = self.end_date.get_date()
                # Assuming EST timezone as defined in Config
                start = Config.EST.localize(datetime.combine(start_date, dt_time.min))
                end = Config.EST.localize(datetime.combine(end_date, dt_time(23, 59, 59, 999999)))
                if end < start:
                    raise ValueError("End date cannot be before start date.")
                return {"start": start, "end": end}
            elif option == "Date & Time Range":
                start_date = self.dt_start_date.get_date()
                end_date = self.dt_end_date.get_date()
                try:
                    start_time = datetime.strptime(self.dt_start_time.get(), "%H:%M:%S").time()
                    end_time = datetime.strptime(self.dt_end_time.get(), "%H:%M:%S").time()
                except ValueError:
                    raise ValueError("Time must be in HH:MM:SS format.")
                start = Config.EST.localize(datetime.combine(start_date, start_time))
                end = Config.EST.localize(datetime.combine(end_date, end_time))
                if end <= start:
                    raise ValueError("Latest time must be after earliest time.")
                return {"start": start, "end": end}
            elif option == "Advanced":
                try:
                    earliest_str = self.earliest_epoch.get()
                    latest_str = self.latest_epoch.get()
                    if not earliest_str.isdigit() or not latest_str.isdigit():
                        raise ValueError("Epoch values must be valid integer timestamps.")
                    earliest_ts = int(earliest_str)
                    latest_ts = int(latest_str)
                    if latest_ts <= earliest_ts:
                         raise ValueError("Latest epoch must be after earliest epoch.")
                    start = datetime.fromtimestamp(earliest_ts, tz=Config.EST)
                    end = datetime.fromtimestamp(latest_ts, tz=Config.EST)
                    return {"start": start, "end": end}
                except ValueError:
                    raise # Re-raise ValueError with specific message
                except Exception as e:
                     raise ValueError(f"Error processing epoch times: {e}")

        except ValueError as e:
            # Show error in the parent window (assuming self.master is the main app window)
            # You might need to adjust this depending on the exact parent structure
            parent_window = self.master
            if hasattr(self, 'winfo_toplevel'):
                 parent_window = self.winfo_toplevel()
            messagebox.showerror("Input Error", f"Invalid time range: {e}", parent=parent_window)
            return None # Indicate failure
        except Exception as e: # Catch other unexpected errors
             parent_window = self.master
             if hasattr(self, 'winfo_toplevel'):
                 parent_window = self.winfo_toplevel()
             messagebox.showerror("Unexpected Error", f"An error occurred: {e}", parent=parent_window)
             logger.error(f"Unexpected error in TimeRangeFrame.get_time_range: {e}", exc_info=True)
             return None

        return None # Default return if no option matched (shouldn't happen)
# =============================================================================

class DashboardDialogBase(Toplevel):
    """A base class for the Add and Edit dashboard dialogs to avoid repeating code."""
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.configure(bg=self.app.current_theme['bg'])
        self.transient(parent) # Keep this dialog on top of the main window.
        self.grab_set()       # Modal behavior: user must interact with this dialog.
        self._create_ui()

    def _create_ui(self):
        """Creates the common UI elements for both Add and Edit dialogs."""
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Dashboard Name input
        ttk.Label(main_frame, text="Dashboard Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(main_frame, textvariable=self.name_var, width=50)
        self.name_entry.grid(row=0, column=1, sticky="ew")

        # Dashboard URL input
        ttk.Label(main_frame, text="Dashboard URL:").grid(row=1, column=0, sticky="w", pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.url_var, width=50).grid(row=1, column=1, sticky="ew")

        # Assign to Lists
        ttk.Label(main_frame, text="Assign to Lists:").grid(row=2, column=0, sticky="nw", pady=(15, 5))
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=2, column=1, sticky="nsew", rowspan=2)
        list_frame.grid_rowconfigure(0, weight=1); list_frame.grid_columnconfigure(0, weight=1)

        # A Listbox is used to allow selecting multiple lists for a single dashboard.
        self.list_box = Listbox(list_frame, selectmode=tk.MULTIPLE, exportselection=False)
        list_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.list_box.yview)
        self.list_box.configure(yscrollcommand=list_scroll.set)
        self.list_box.grid(row=0, column=0, sticky="nsew")
        list_scroll.grid(row=0, column=1, sticky="ns")

        # A section to add a new list on-the-fly.
        new_list_frame = ttk.Frame(main_frame)
        new_list_frame.grid(row=4, column=1, sticky="ew", pady=(10, 0))
        self.new_list_var = tk.StringVar()
        ttk.Entry(new_list_frame, textvariable=self.new_list_var).pack(side=tk.LEFT, expand=True, fill=tk.X)
        ttk.Button(new_list_frame, text="Add New List", command=self.add_new_list).pack(side=tk.LEFT, padx=(5,0))

        # Buttons for saving or cancelling
        self.button_frame = ttk.Frame(main_frame)
        self.button_frame.grid(row=5, column=0, columnspan=2, pady=20, sticky="e")

    def update_list_box(self, selected_lists: set = None):
        """Populates the listbox with all available lists and pre-selects relevant ones."""
        if selected_lists is None: selected_lists = {'Default'}
        self.list_box.delete(0, tk.END)
        self.all_lists = sorted(list(self.app.get_all_dashboard_lists()))
        for i, list_name in enumerate(self.all_lists):
            self.list_box.insert(tk.END, list_name)
            if list_name in selected_lists:
                self.list_box.selection_set(i)

    def add_new_list(self):
        """Handles the logic for adding a new list category from the dialog."""
        new_list_name = self.new_list_var.get().strip()
        if not new_list_name: messagebox.showwarning("Invalid Name", "Please enter a list name.", parent=self); return
        if new_list_name in self.all_lists: messagebox.showinfo("Exists", "This list already exists.", parent=self); return

        # Add the new list and select it automatically.
        self.all_lists.append(new_list_name)
        self.all_lists.sort()
        new_idx = self.all_lists.index(new_list_name)
        self.list_box.insert(new_idx, new_list_name)
        self.list_box.selection_set(new_idx)
        self.new_list_var.set("") # Clear the input box.

class DashboardAddDialog(DashboardDialogBase):
    """The specific dialog for ADDING a new dashboard."""
    def __init__(self, parent, app_instance):
        super().__init__(parent, app_instance)
        self.title("Add New Dashboard")
        self.update_list_box() # Populate the listbox with available lists.

        # Add the specific buttons for this dialog.
        ttk.Button(self.button_frame, text="Add Dashboard", command=self.on_add, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(self.button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def on_add(self):
        """Validates all inputs and adds the new dashboard to the application's data."""
        name = self.name_var.get().strip()
        url = self.url_var.get().strip()
        selected_lists = [self.list_box.get(i) for i in self.list_box.curselection()]

        if not name or not url: messagebox.showerror("Input Error", "Dashboard Name and URL are required.", parent=self); return
        if not url.lower().startswith("http"): messagebox.showerror("Input Error", "URL must start with http or https.", parent=self); return
        if any(d["name"].strip().lower() == name.lower() for d in self.app.session["dashboards"]):
            messagebox.showerror("Input Error", "A dashboard with this name already exists.", parent=self); return
        if not selected_lists: messagebox.showerror("Input Error", "At least one list must be selected.", parent=self); return

        new_dashboard = {"id": str(uuid.uuid4()), "name": name, "url": url, "lists": selected_lists, "selected": True}
        self.app.session['dashboards'].append(new_dashboard)
        self.app.save_and_refresh_ui()
        self.destroy()

class DashboardEditDialog(DashboardDialogBase):
    """The specific dialog for EDITING an existing dashboard."""
    def __init__(self, parent, app_instance, dashboard_to_edit: Dict):
        self.dashboard_to_edit = dashboard_to_edit
        super().__init__(parent, app_instance)
        self.title("Edit Dashboard")

        # Pre-fill the fields and make name read-only as it's the identifier.
        self.name_var.set(dashboard_to_edit.get("name", ""))
        self.name_entry.config(state='readonly')
        self.url_var.set(dashboard_to_edit.get("url", ""))
        self.update_list_box(set(dashboard_to_edit.get('lists', [])))

        # Add the specific buttons for this dialog.
        ttk.Button(self.button_frame, text="Save Changes", command=self.on_save, style="Accent.TButton").pack(side=tk.RIGHT)
        ttk.Button(self.button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def on_save(self):
        """Validates all inputs and saves the changes to the existing dashboard."""
        new_url = self.url_var.get().strip()
        new_lists = [self.list_box.get(i) for i in self.list_box.curselection()]

        if not new_url: messagebox.showerror("Input Error", "URL is required.", parent=self); return
        if not new_lists: messagebox.showerror("Input Error", "At least one list must be selected.", parent=self); return

        # Find the original dashboard in the main app's data and update it.
        for db in self.app.session['dashboards']:
            if db.get('id') == self.dashboard_to_edit.get('id'):
                db['url'], db['lists'] = new_url, new_lists
                break
        
        self.app.save_and_refresh_ui()
        self.destroy()

class ScheduleManagerDialog(Toplevel):
    """A dialog to view, create, edit, and delete all analysis schedules."""
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.title("Schedule Manager")
        self.geometry("700x400")
        self.transient(parent); self.grab_set()

        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=5)
        ttk.Button(toolbar, text="➕ Add", command=self.add_schedule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="✏️ Edit", command=self.edit_schedule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🗑️ Delete", command=self.delete_schedule).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="⏯️ Toggle Active", command=self.toggle_schedule).pack(side=tk.LEFT, padx=2)

        columns = ("Name", "Interval", "Look Back", "Dashboards", "Active")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        self.tree.pack(fill=tk.BOTH, expand=True)
        for col in columns: self.tree.heading(col, text=col)
        self.tree.column("Interval", width=100, anchor="center")
        self.tree.column("Look Back", width=100, anchor="center")
        self.tree.column("Dashboards", width=100, anchor="center")
        self.tree.column("Active", width=80, anchor="center")
        
        self.refresh_schedules()

    def refresh_schedules(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for i, schedule in enumerate(self.app.schedules):
            self.tree.insert("", "end", iid=str(i), values=(
                schedule['name'], f"{schedule['interval_minutes']} min", f"{schedule['time_hours']} hrs",
                len(schedule['dashboards']), "Yes" if schedule.get('active', True) else "No"
            ))

    def add_schedule(self):
        """Opens another dialog to configure a new schedule."""
        self.app.configure_schedule(parent=self)
        self.refresh_schedules()

    def edit_schedule(self):
        """Opens a dialog to edit the selected schedule."""
        selected_id = self.tree.focus()
        if not selected_id: messagebox.showwarning("No Selection", "Please select a schedule to edit.", parent=self); return
        self.app.configure_schedule(parent=self, schedule_index=int(selected_id))
        self.refresh_schedules()

    def delete_schedule(self):
        """Deletes the selected schedule."""
        selected_id = self.tree.focus()
        if not selected_id: messagebox.showwarning("No Selection", "Please select a schedule to delete.", parent=self); return
        idx = int(selected_id)
        schedule_name = self.app.schedules[idx]['name']
        if messagebox.askyesno("Confirm Delete", f"Delete schedule '{schedule_name}'?"):
            del self.app.schedules[idx]
            self.app.save_schedules()
            self.app.start_all_schedules()
            self.refresh_schedules()

    def toggle_schedule(self):
        """Toggles the active state of the selected schedule."""
        selected_id = self.tree.focus()
        if not selected_id: messagebox.showwarning("No Selection", "Please select a schedule to toggle.", parent=self); return
        idx = int(selected_id)
        self.app.schedules[idx]['active'] = not self.app.schedules[idx].get('active', True)
        self.app.save_schedules()
        self.app.start_all_schedules()
        self.refresh_schedules()


# =============================================================================
# SECTION 5: MAIN APPLICATION CLASS
# =============================================================================

class SplunkAutomatorApp:
    """The main application class that constructs the GUI and handles all logic."""
    def __init__(self, master: tk.Tk):
        self.master = master
        settings = self.load_settings()
        master.title("Splunk Dashboard Automator")
        master.geometry(settings.get("geometry", "1400x900"))

        # --- Initialize application state variables ---
        self.is_dark_theme = settings.get("dark_theme", False)
        self.schedules = self.load_schedules()
        self.status_message = tk.StringVar(value="Ready.")
        self.username, self.password = load_credentials()
        self.session = {"username": self.username, "password": self.password, "dashboards": []}

        # --- Build the UI and load all data ---
        self._setup_ui()
        self._apply_theme("Dark" if self.is_dark_theme else "Light")
        self.load_dashboards()
        self.update_list_filter()
        self.refresh_dashboard_list()
        self.start_all_schedules()

        if not self.session["username"]:
            master.after(100, lambda: self.manage_credentials(first_time=True))

        archive_and_clean_tmp(); purge_old_archives()
        logger.info("SplunkAutomatorApp initialized successfully.")

    def _setup_ui(self):
        """Creates the entire main window layout and all its widgets."""
        # --- Menu Bar ---
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Manage Credentials", command=self.manage_credentials)
        theme_menu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Light", command=lambda: self.change_theme("Light"))
        theme_menu.add_command(label="Dark", command=lambda: self.change_theme("Dark"))
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Schedule Manager", command=self.open_schedule_manager)

        # A PanedWindow allows the user to resize the top and bottom sections.
        main_pane = ttk.PanedWindow(self.master, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        top_frame = ttk.Frame(main_pane)
        bottom_frame = ttk.Frame(main_pane)
        main_pane.add(top_frame, weight=1)
        main_pane.add(bottom_frame, weight=0)

        # --- Top Frame: Header and Dashboard List ---
        top_frame.grid_columnconfigure(0, weight=1); top_frame.grid_rowconfigure(1, weight=1)
        controls_frame = ttk.Frame(top_frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        btn_config = [("➕ Add", self.add_dashboard), ("✏️ Edit", self.edit_dashboard), ("🗑️ Delete", self.delete_dashboard),
                      ("☑️ Select All", self.select_all_dashboards), ("☐ Deselect All", self.deselect_all_dashboards)]
        for text, cmd in btn_config: ttk.Button(controls_frame, text=text, command=cmd).pack(side=tk.LEFT, padx=(0, 5))
        
        filter_frame = ttk.Frame(controls_frame)
        filter_frame.pack(side=tk.RIGHT)
        ttk.Label(filter_frame, text="Filter by List:").pack(side=tk.LEFT)
        self.list_filter_var = tk.StringVar(value=self.load_settings().get("last_list", "All"))
        self.list_filter = ttk.Combobox(filter_frame, textvariable=self.list_filter_var, state="readonly", width=20)
        self.list_filter.pack(side=tk.LEFT, padx=5)
        self.list_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())

        tree_frame = ttk.Frame(top_frame)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_rowconfigure(0, weight=1); tree_frame.grid_columnconfigure(0, weight=1)
        columns = ("Select", "Name", "URL", "Lists", "Status")
        self.treeview = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=v_scroll.set)
        v_scroll.grid(row=0, column=1, sticky="ns"); self.treeview.grid(row=0, column=0, sticky="nsew")
        self.treeview.bind("<Button-1>", self.on_treeview_click)
        col_configs = [("Select", 60, "center"), ("Name", 250, "w"), ("URL", 400, "w"), ("Lists", 200, "w"), ("Status", 250, "w")]
        for col, width, anchor in col_configs: self.treeview.heading(col, text=col); self.treeview.column(col, width=width, anchor=anchor, minwidth=width)

        # --- Bottom Frame: Time Range and Actions ---
        bottom_frame.grid_columnconfigure(1, weight=1)
        self.time_range_frame = TimeRangeFrame(bottom_frame)
        self.time_range_frame.grid(row=0, column=0, sticky="ns", padx=(0, 10), pady=5)

        action_frame = ttk.LabelFrame(bottom_frame, text="Actions", padding=10)
        action_frame.grid(row=0, column=1, sticky="nsew", pady=5)
        action_frame.grid_columnconfigure(0, weight=1)
        ttk.Button(action_frame, text="📸 Capture Screenshots", command=lambda: self._start_processing_job(capture_only=True)).grid(row=0, column=0, pady=5, sticky="ew")
        ttk.Button(action_frame, text="📊 Analyze Dashboards", command=lambda: self._start_processing_job(capture_only=False)).grid(row=1, column=0, pady=5, sticky="ew")
        self.progress_bar = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=2, column=0, pady=(10,0), sticky="ew")

        # --- Status Bar ---
        status_bar = ttk.Frame(self.master, relief=tk.SUNKEN, borderwidth=1)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status_message, anchor="w").pack(side=tk.LEFT, padx=5)
        self.connection_status = ttk.Label(status_bar, text="●", foreground="red" if not self.username else "green")
        ttk.Button(status_bar, text="🔑", command=self.manage_credentials, width=3).pack(side=tk.RIGHT)
        self.connection_status.pack(side=tk.RIGHT, padx=5)

    def _apply_theme(self, theme_name="Light"):
        """Applies the selected color theme to all UI elements for a consistent look."""
        self.is_dark_theme = (theme_name == "Dark")
        self.current_theme = Theme.DARK if self.is_dark_theme else Theme.LIGHT
        theme = self.current_theme
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=theme['bg'], foreground=theme['fg'], fieldbackground=theme['button_bg'], font=("Segoe UI", 10))
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TRadiobutton', background=theme['bg'], foreground=theme['fg'])
        style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'], padding=5, borderwidth=1)
        style.map('TButton', background=[('active', theme['select_bg'])])
        style.configure('Accent.TButton', background=theme['accent'], foreground=theme['select_fg'], font=("Segoe UI", 10, "bold"))
        style.configure('Treeview', background=theme['tree_bg'], foreground=theme['tree_fg'], fieldbackground=theme['tree_bg'])
        style.map('Treeview', background=[('selected', theme['select_bg'])], foreground=[('selected', theme['select_fg'])])
        style.configure('Treeview.Heading', background=theme['frame_bg'], foreground=theme['fg'], font=('Segoe UI', 10, 'bold'))
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'], font=("Segoe UI", 10, "bold"))
        style.configure('TPanedWindow', background=theme['bg'])
        self.master.configure(bg=theme['bg'])

    def change_theme(self, theme_name):
        """Switches between the light and dark themes."""
        self._apply_theme(theme_name)
        self.save_settings()

    # --- Dashboard and List Management Logic ---
    def get_all_dashboard_lists(self) -> set:
        """Returns a set of all unique list names from all dashboards."""
        return {"Default"} | {l for db in self.session['dashboards'] for l in db.get('lists', [])}
        
    def add_dashboard(self): DashboardAddDialog(self.master, self)
    def edit_dashboard(self):
        selected_dbs = [db for db in self.session['dashboards'] if db.get('selected', False)]
        if len(selected_dbs) != 1: messagebox.showwarning("Selection Error", "Please select exactly one dashboard to edit."); return
        DashboardEditDialog(self.master, self, selected_dbs[0])

    def delete_dashboard(self):
        """Deletes all dashboards that have their checkbox ticked."""
        to_delete = [db for db in self.session['dashboards'] if db.get('selected', False)]
        if not to_delete: messagebox.showwarning("No Selection", "Please select dashboards to delete using the checkboxes."); return
        if messagebox.askyesno("Confirm Delete", f"Delete {len(to_delete)} dashboard(s)? This cannot be undone."):
            delete_ids = {db['id'] for db in to_delete}
            self.session['dashboards'] = [db for db in self.session['dashboards'] if db.get('id') not in delete_ids]
            self.save_and_refresh_ui()

    def select_all_dashboards(self): self._toggle_all_selection(True)
    def deselect_all_dashboards(self): self._toggle_all_selection(False)
    def _toggle_all_selection(self, select_state: bool):
        current_filter = self.list_filter_var.get()
        for db in self.session['dashboards']:
            if current_filter == "All" or current_filter in db.get('lists', []): db['selected'] = select_state
        self.refresh_dashboard_list()

    def on_treeview_click(self, event):
        """Handles clicks on the checkbox column to toggle dashboard selection."""
        item_id = self.treeview.identify_row(event.y)
        if not item_id or self.treeview.identify_column(event.x) != "#1": return # Only toggle if checkbox column is clicked
        for db in self.session['dashboards']:
            if db.get('id') == item_id:
                db["selected"] = not db.get("selected", False)
                self.refresh_dashboard_list()
                break

    def refresh_dashboard_list(self):
        """Clears and repopulates the dashboard list based on the current filter."""
        for item in self.treeview.get_children(): self.treeview.delete(item)
        selected_filter = self.list_filter_var.get()
        
        for db in sorted(self.session['dashboards'], key=lambda x: x['name'].lower()):
            if 'id' not in db: db['id'] = str(uuid.uuid4()) # Backwards compatibility for old data
            dashboard_lists = db.get('lists', ['Default'])
            if selected_filter == "All" or selected_filter in dashboard_lists:
                values = ("☑" if db.get("selected", False) else "☐", db['name'], db['url'], ", ".join(dashboard_lists), db.get('status', 'Ready'))
                self.treeview.insert("", "end", iid=db['id'], values=values)
        self.update_status_summary()

    def update_list_filter(self):
        """Updates the 'Filter by List' dropdown with all available list names."""
        all_lists = {"All"} | self.get_all_dashboard_lists()
        self.list_filter['values'] = sorted(list(all_lists))
        if self.list_filter_var.get() not in self.list_filter['values']: self.list_filter_var.set("All")

    def save_and_refresh_ui(self):
        """A helper function to save data and then update all relevant parts of the UI."""
        self.save_dashboards()
        self.update_list_filter()
        self.refresh_dashboard_list()

    # --- Core Processing and Scheduling Logic ---

    def _start_processing_job(self, capture_only: bool, schedule_data: Optional[Dict] = None):
        """The main function to start a dashboard processing job."""
        if schedule_data: # If run from a schedule, select dashboards based on its configuration.
            scheduled_db_names = set(schedule_data.get('dashboards', []))
            selected_dbs = [db for db in self.session['dashboards'] if db['name'] in scheduled_db_names]
            time_range = {'start': f"-{schedule_data['time_hours']}h@h", 'end': 'now'}
        else: # If run manually, process the user-selected dashboards.
            selected_dbs = [db for db in self.session['dashboards'] if db.get('selected', False)]
            time_range = self.time_range_frame.get_time_range()
            if time_range is None: return # User provided invalid time.

        if not selected_dbs: messagebox.showwarning("No Selection", "Please select at least one dashboard."); return
        if not self.session['username']: messagebox.showerror("Credentials Required", "Please set Splunk credentials first via the 🔑 button."); return

        retry_count = schedule_data.get('retries', 2) if schedule_data else 2
        
        # Update the UI to show the job is starting.
        self.progress_bar['maximum'] = len(selected_dbs)
        self.progress_bar['value'] = 0
        for db in selected_dbs: self.update_dashboard_status(db['name'], "Queued")
        
        job_type = "screenshot capture" if capture_only else "analysis"
        self.update_status(f"Starting {job_type} for {len(selected_dbs)} dashboards...")

        # Run the actual browser automation in a separate thread to avoid freezing the UI.
        def run_async_job():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._process_dashboards_async(selected_dbs, time_range, retry_count, capture_only, job_type))
        Thread(target=run_async_job, name=f"{job_type}-thread", daemon=True).start()

    async def _process_dashboards_async(self, dashboards: List[Dict], time_range: Dict, retries: int, capture_only: bool, operation_name: str):
        """The core asynchronous function that processes all dashboards in parallel."""
        semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_DASHBOARDS)
        async with async_playwright() as playwright:
            tasks = [self._process_single_dashboard_wrapper(playwright, db, time_range, retries, capture_only, semaphore) for db in dashboards]
            await asyncio.gather(*tasks)
        self.master.after(0, lambda: self._on_operation_complete(operation_name))

    async def _process_single_dashboard_wrapper(self, playwright, dashboard, time_range, retries, capture_only, semaphore):
        """A wrapper that handles retries for a single dashboard."""
        async with semaphore: # This will wait if too many dashboards are already running.
            for attempt in range(retries + 1):
                try:
                    await self.process_single_dashboard(playwright, dashboard, time_range, capture_only)
                    break # If successful, break the retry loop.
                except Exception as e:
                    logger.warning(f"Attempt {attempt + 1} failed for {dashboard['name']}: {e}")
                    self.update_dashboard_status(dashboard['name'], f"Retry {attempt + 1} failed")
                    if attempt == retries: self.update_dashboard_status(dashboard['name'], "❌ Failed")
            self.master.after(0, self.progress_bar.step)

    async def process_single_dashboard(self, playwright, dashboard_data: Dict, time_range: Dict, capture_only: bool):
        """This is where the magic happens: browser automation for one dashboard."""
        name, url = dashboard_data['name'], dashboard_data['url']
        logger.info(f"Processing '{name}'. Capture only: {capture_only}")
        self.update_dashboard_status(name, "Launching browser...")
        
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1920, 'height': 1080})
            page = await context.new_page()
            
            # --- Intelligent Splunk Studio vs. Classic Logic ---
            is_studio = "dashboard/studio" in url.lower()
            full_url = self.format_time_for_url(url, time_range['start'], time_range['end'], is_studio)
            
            await page.goto(full_url, timeout=90000, wait_until='domcontentloaded')

            # --- Intelligent Authentication Check ---
            if await page.locator('input[name="username"]').is_visible(timeout=5000):
                self.update_dashboard_status(name, "Authenticating...")
                await page.fill('input[name="username"]', self.session['username'])
                await page.fill('input[name="password"]', self.session['password'])
                await page.click('button[type="submit"], input[type="submit"]')
                await page.wait_for_url(lambda u: "account/login" not in u, timeout=15000)

            # For 'Analyze' mode, wait for the dashboard's loading spinners to disappear.
            if not capture_only:
                self.update_dashboard_status(name, "Waiting for panels to load...")
                wait_expression = "() => !document.querySelector('.spl-spinner, .dashboard-loading')"
                await page.wait_for_function(wait_expression, timeout=120000)
                await asyncio.sleep(5) # Extra wait for data to fully render.

            self.update_dashboard_status(name, "Capturing...")
            screenshot_bytes = await page.screenshot(full_page=True)
            filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now().strftime('%H%M%S')}.png"
            
            if capture_only:
                save_screenshot_with_watermark(screenshot_bytes, filename)
            else:
                # For "Analyze", just save the clean screenshot without a watermark.
                today_str = datetime.now().strftime("%Y-%m-%d")
                day_tmp_dir = os.path.join(Config.TMP_DIR, today_str)
                os.makedirs(day_tmp_dir, exist_ok=True)
                with open(os.path.join(day_tmp_dir, filename), "wb") as f:
                    f.write(screenshot_bytes)

            self.update_dashboard_status(name, f"✅ Success")
        finally:
            await browser.close() # Always ensure the browser is closed to free up resources.

    def format_time_for_url(self, base_url: str, start, end, is_studio: bool) -> str:
        """Appends the correct time range parameters to the Splunk dashboard URL."""
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        prefix = "form.global_time" if is_studio else "form.time"

        if isinstance(start, datetime): query_params[f'{prefix}.earliest'] = int(start.timestamp())
        else: query_params[f'{prefix}.earliest'] = start
        
        if isinstance(end, datetime): query_params[f'{prefix}.latest'] = int(end.timestamp())
        else: query_params[f'{prefix}.latest'] = end
        
        return urlunparse(parsed_url._replace(query=urlencode(query_params, doseq=True)))

    def _on_operation_complete(self, operation_name: str):
        """A function that runs on the main UI thread after a job is finished."""
        self.update_status(f"{operation_name.capitalize()} completed.")
        messagebox.showinfo("Complete", f"{operation_name.capitalize()} has finished.")
        self.progress_bar['value'] = 0

    # --- Scheduling System ---
    def open_schedule_manager(self): ScheduleManagerDialog(self.master, self)
    def start_all_schedules(self):
        """Cancels all existing timers and starts new ones based on the schedule file."""
        for attr in list(self.__dict__.keys()):
            if attr.startswith("_after_job_"):
                self.master.after_cancel(getattr(self, attr))
                delattr(self, attr)
        
        for i, schedule in enumerate(self.schedules):
            if schedule.get("active", True):
                self._start_single_schedule(schedule, i)
        if any(s.get("active") for s in self.schedules):
            logger.info(f"Started active schedules.")

    def _start_single_schedule(self, schedule, index):
        """Starts the timer loop for a single schedule."""
        interval_ms = schedule["interval_minutes"] * 60 * 1000
        
        def scheduled_run():
            if index < len(self.schedules) and self.schedules[index].get("active", True):
                logger.info(f"Executing scheduled run: {schedule['name']}")
                self.update_status(f"Running schedule: {schedule['name']}...")
                self._start_processing_job(capture_only=False, schedule_data=self.schedules[index])
                # Reschedule itself for the next run.
                job_name = f"_after_job_{index}"
                setattr(self, job_name, self.master.after(interval_ms, scheduled_run))
        
        job_name = f"_after_job_{index}"
        setattr(self, job_name, self.master.after(interval_ms, scheduled_run))

    def configure_schedule(self, parent, schedule_index=None):
        """Opens a dialog to create or edit a schedule."""
        is_edit = schedule_index is not None
        schedule_data = self.schedules[schedule_index] if is_edit else {}

        dlg = Toplevel(parent); dlg.title("Edit Schedule" if is_edit else "Configure New Schedule")
        dlg.transient(parent); dlg.grab_set(); dlg.geometry("600x400")
        
        main_frame = ttk.Frame(dlg, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(1, weight=1); main_frame.rowconfigure(4, weight=1)

        ttk.Label(main_frame, text="Schedule Name:").grid(row=0, column=0, sticky="w", pady=2)
        name_var = tk.StringVar(value=schedule_data.get('name', f"Schedule {len(self.schedules) + 1}"))
        ttk.Entry(main_frame, textvariable=name_var).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Interval (minutes):").grid(row=1, column=0, sticky="w", pady=2)
        interval_var = tk.StringVar(value=str(schedule_data.get('interval_minutes', 60)))
        ttk.Entry(main_frame, textvariable=interval_var).grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(main_frame, text="Look Back (hours):").grid(row=2, column=0, sticky="w", pady=2)
        hours_var = tk.StringVar(value=str(schedule_data.get('time_hours', 4)))
        ttk.Entry(main_frame, textvariable=hours_var).grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(main_frame, text="Retries:").grid(row=3, column=0, sticky="w", pady=2)
        retries_var = tk.StringVar(value=str(schedule_data.get('retries', 2)))
        ttk.Entry(main_frame, textvariable=retries_var).grid(row=3, column=1, sticky="w", pady=2)

        ttk.Label(main_frame, text="Dashboards:").grid(row=4, column=0, sticky="nw", pady=2)
        lb_frame = ttk.Frame(main_frame); lb_frame.grid(row=4, column=1, sticky="nsew")
        lb_frame.grid_rowconfigure(0, weight=1); lb_frame.grid_columnconfigure(0, weight=1)
        lb = Listbox(lb_frame, selectmode=tk.MULTIPLE, exportselection=False)
        lb.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(lb_frame, orient="vertical", command=lb.yview); scroll.grid(row=0, column=1, sticky="ns")
        lb.config(yscrollcommand=scroll.set)
        
        all_db_names = [db['name'] for db in self.session['dashboards']]
        for name in all_db_names: lb.insert(tk.END, name)
        
        for i, name in enumerate(all_db_names):
            if name in schedule_data.get('dashboards', []): lb.selection_set(i)

        def on_save():
            try:
                new_schedule = {
                    "name": name_var.get().strip(),
                    "interval_minutes": int(interval_var.get()),
                    "time_hours": int(hours_var.get()),
                    "retries": int(retries_var.get()),
                    "dashboards": [lb.get(i) for i in lb.curselection()],
                    "active": schedule_data.get('active', True)
                }
                if not new_schedule['name'] or not new_schedule['dashboards']: raise ValueError("Name and dashboards are required.")
                
                if is_edit: self.schedules[schedule_index] = new_schedule
                else: self.schedules.append(new_schedule)
                
                self.save_schedules()
                self.start_all_schedules()
                dlg.destroy()
            except ValueError as e: messagebox.showerror("Invalid Input", str(e), parent=dlg)

        btn = ttk.Button(main_frame, text="Save Schedule", command=on_save); btn.grid(row=5, column=1, sticky="e", pady=10)
            
    # --- Helper Functions and State Management ---
    def manage_credentials(self, first_time: bool = False):
        dialog = Toplevel(self.master); dialog.title("Manage Credentials"); dialog.transient(self.master); dialog.grab_set()
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Splunk Username:").grid(row=0, column=0, sticky="w", pady=5)
        user_var = tk.StringVar(value=self.username)
        ttk.Entry(frame, textvariable=user_var, width=40).grid(row=0, column=1, sticky="ew")
        ttk.Label(frame, text="Splunk Password:").grid(row=1, column=0, sticky="w", pady=5)
        pass_var = tk.StringVar(value=self.password)
        ttk.Entry(frame, textvariable=pass_var, show="*", width=40).grid(row=1, column=1, sticky="ew")

        def on_save():
            if save_credentials(user_var.get(), pass_var.get()):
                self.username, self.password = user_var.get(), pass_var.get()
                self.session.update({'username': self.username, 'password': self.password})
                self.connection_status.config(foreground="green")
                messagebox.showinfo("Success", "Credentials saved securely.", parent=dialog)
                dialog.destroy()
            else: messagebox.showerror("Error", "Failed to save credentials.", parent=dialog)

        ttk.Button(frame, text="Save", command=on_save, style="Accent.TButton").grid(row=2, column=1, sticky="e", pady=10)
        if first_time: messagebox.showinfo("Setup", "Please enter your Splunk credentials to begin.", parent=dialog)

    def update_dashboard_status(self, dashboard_name: str, status: str):
        """Updates a dashboard's status in the UI list safely from any thread."""
        def update_ui():
            db_id = next((db.get('id') for db in self.session['dashboards'] if db['name'] == dashboard_name), None)
            if db_id and self.treeview.exists(db_id):
                current_values = list(self.treeview.item(db_id)['values']); current_values[4] = status
                self.treeview.item(db_id, values=tuple(current_values));
        self.master.after(0, update_ui)
    
    def update_status_summary(self):
        """Updates the main status bar with a summary of dashboard counts."""
        total = len(self.session['dashboards']); selected = sum(1 for d in self.session['dashboards'] if d.get('selected', False))
        self.update_status(f"{total} dashboards loaded ({selected} selected).")

    def update_status(self, message: str):
        self.status_message.set(message); logger.info(f"Status: {message}")
        
    def load_schedules(self) -> List:
        if not os.path.exists(Config.SCHEDULE_FILE): return []
        try:
            with open(Config.SCHEDULE_FILE, 'r') as f: return json.load(f)
        except Exception as e: logger.error(f"Error loading schedules: {e}"); return []

    def save_schedules(self):
        try:
            with open(Config.SCHEDULE_FILE, 'w') as f: json.dump(self.schedules, f, indent=4)
        except OSError as e: logger.error(f"Error saving schedules: {e}")

    def load_dashboards(self):
        if not os.path.exists(Config.DASHBOARD_FILE): self.session['dashboards'] = []; return
        try:
            with open(Config.DASHBOARD_FILE, 'r', encoding='utf-8') as f: dashboards = json.load(f)
            for db in dashboards:
                if 'lists' not in db: db['lists'] = [db.get('group', 'Default')]
                if 'group' in db: del db['group']
                if 'id' not in db: db['id'] = str(uuid.uuid4())
            self.session['dashboards'] = dashboards
        except Exception as e: logger.error(f"Error loading dashboards: {e}"); self.session['dashboards'] = []
    
    def save_dashboards(self):
        try:
            with open(Config.DASHBOARD_FILE, 'w', encoding='utf-8') as f:
                to_save = [{k: v for k, v in db.items() if k != 'status'} for db in self.session['dashboards']]
                json.dump(to_save, f, indent=4)
        except OSError as e: logger.error(f"Error saving dashboards: {e}")

    def load_settings(self) -> Dict[str, Any]:
        if not os.path.exists(Config.SETTINGS_FILE): return {}
        try:
            with open(Config.SETTINGS_FILE, "r", encoding='utf-8') as f: return json.load(f)
        except Exception as e: logger.warning(f"Could not load settings: {e}"); return {}

    def save_settings(self):
        settings = {"geometry": self.master.geometry(), "dark_theme": self.is_dark_theme, "last_list": self.list_filter_var.get()}
        try:
            with open(Config.SETTINGS_FILE, "w", encoding='utf-8') as f: json.dump(settings, f, indent=4)
        except OSError as e: logger.error(f"Error saving settings: {e}")

    def on_closing(self):
        """Called when the user closes the application window to ensure settings are saved."""
        self.save_settings()
        self.master.destroy()

# =============================================================================
# SECTION 6: APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # This is the code that runs when the script is executed.
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    # Ensure settings are saved when the window is closed via the 'X' button.
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    # Start the Tkinter event loop to show the window and handle user events.
    root.mainloop()
