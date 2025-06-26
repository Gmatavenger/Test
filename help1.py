import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, filedialog
import asyncio
from datetime import datetime, timedelta, time as dt_time
import pytz
import os
import sys
import re
import json
from urllib.parse import urlencode
from threading import Thread
import logging
from logging.handlers import RotatingFileHandler
import time
import keyring

try:
    from tkcalendar import DateEntry
except ImportError:
    messagebox.showerror("Dependency Error", "The 'tkcalendar' library is not found. Please install it by running:\npip install tkcalendar")
    sys.exit(1)
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    messagebox.showerror("Dependency Error", "The 'playwright' library is not found. Please install it by running:\npip install playwright")
    sys.exit(1)

# ------------------------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, f"analysis_{datetime.now().strftime('%Y%m%d')}.log")
logger = logging.getLogger("SplunkAutomator")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler(sys.stdout))

# ------------------------------------------------------------------------------
# Global Variables & Configuration
# ------------------------------------------------------------------------------
DASHBOARD_FILE = "dashboards.json"
SCHEDULE_FILE = "schedule.json"
SETTINGS_FILE = "settings.json"
est = pytz.timezone("America/New_York")
SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# Credential Management (SECURE)
# ------------------------------------------------------------------------------
def load_credentials():
    username = keyring.get_password("SplunkAutomator", "username")
    password = keyring.get_password("SplunkAutomator", "password")
    return username, password

def save_credentials(username, password):
    try:
        keyring.set_password("SplunkAutomator", "username", username)
        keyring.set_password("SplunkAutomator", "password", password)
        logger.info("Credentials saved securely.")
        return True
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        return False

# ------------------------------------------------------------------------------
# Splunk URL Formatter
# ------------------------------------------------------------------------------
def format_time_for_url(base_url, start_dt, end_dt, relative=False):
    """
    Formats the time range for Splunk URL based on the type of time range.

    Args:
        base_url (str): The base URL of the Splunk dashboard.
        start_dt (datetime): The start time as a datetime object.
        end_dt (datetime): The end time as a datetime object.
        relative (bool): Whether the time range is relative (e.g., "Last 60 minutes").

    Returns:
        str: The formatted URL with time range parameters.
    """
    if relative:
        # Relative time range modifier
        earliest = "-60m@h"  # Example for "Last 60 minutes". Customize based on user input.
        latest = "now"
    else:
        # Specific time range with epoch format
        if start_dt.tzinfo is None:
            start_dt = est.localize(start_dt)
        if end_dt.tzinfo is None:
            end_dt = est.localize(end_dt)
        earliest = int(start_dt.timestamp())
        latest = int(end_dt.timestamp())

    params = {
        'form.time_field.earliest': earliest,
        'form.time_field.latest': latest
    }
    return f"{base_url.split('?')[0]}?{urlencode(params)}"

# ------------------------------------------------------------------------------
# Main Application Class and All Methods
# ------------------------------------------------------------------------------
class SplunkAutomatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Splunk Dashboard Automator")
        master.geometry(self.load_settings().get("geometry", "1200x800"))
        self.concurrency_limit = self.load_settings().get("concurrency_limit", 3)
        self.status_message = tk.StringVar()
        self.last_group = self.load_settings().get("last_group", "All")
        self.last_selected_dashboards = self.load_settings().get("last_selected_dashboards", [])
        self.username, self.password = load_credentials()
        self.session = {"username": self.username, "password": self.password, "dashboards": []}
        self.scheduled = False
        self.schedule_interval = 0
        self._setup_ui()
        self.load_dashboards()
        if not self.session["username"] or not self.session["password"]:
            master.after(100, lambda: self.manage_credentials(first_time=True))
        self.start_schedule_if_exists()

    def _setup_ui(self):
        # UI setup code remains unchanged
        pass

    def run_analysis_thread(self, scheduled_run=False, schedule_config=None):
        selected_dbs = [db for db in self.session['dashboards'] if db.get('selected')]
        if not selected_dbs:
            messagebox.showwarning("No Selection", "Please select dashboards.")
            return
        dialog = TimeRangeDialog(self.master)
        self.master.wait_window(dialog)
        if not dialog.result:
            return
        start_dt, end_dt = dialog.result['start'], dialog.result['end']
        relative = dialog.result.get('relative', False)
        if not self.session['username'] or not self.session['password']:
            messagebox.showerror("Credentials Error", "Splunk credentials are not set.")
            return
        self.update_progress(0, len(selected_dbs))
        for db in selected_dbs:
            self.update_dashboard_status(db['name'], "Queued")
        Thread(target=lambda: asyncio.run(self.analyze_dashboards_async(selected_dbs, start_dt, end_dt, relative)), daemon=True).start()

    async def analyze_dashboards_async(self, dashboards, start_dt, end_dt, relative):
        semaphore = asyncio.Semaphore(self.concurrency_limit)
        async with async_playwright() as p:
            tasks = [self.process_single_dashboard(p, db_data, start_dt, end_dt, relative, semaphore) for db_data in dashboards]
            await asyncio.gather(*tasks)
        self.update_status("Analysis run has finished.")
        self.master.after(0, lambda: messagebox.showinfo("Complete", "Analysis run has finished."))

    async def process_single_dashboard(self, playwright, db_data, start_dt, end_dt, relative, semaphore):
        async with semaphore:
            name = db_data['name']
            self.update_dashboard_status(name, "Launching...")
            browser = None
            try:
                browser = await playwright.chromium.launch(headless=False)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                full_url = format_time_for_url(db_data['url'], start_dt, end_dt, relative)
                self.update_dashboard_status(name, "Loading Dashboard...")
                await page.goto(full_url, timeout=120_000)
                # Additional logic remains unchanged
            except Exception as e:
                # Error handling remains unchanged
                pass
            finally:
                if browser:
                    await browser.close()
                self.progress_bar.step(1)
                self.update_progress(self.progress_bar['value'] + 1, self.progress_bar['maximum'])

    # Other methods remain unchanged

# --- Application Entry Point ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()