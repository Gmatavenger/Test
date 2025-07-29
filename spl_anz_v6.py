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
import shutil
import io

# PIL for timestamp overlay
from PIL import Image, ImageDraw, ImageFont

# Fernet for encryption
from cryptography.fernet import Fernet

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

class Config:
    LOG_DIR = "logs"
    TMP_DIR = "tmp"
    SCREENSHOT_ARCHIVE_DIR = "screenshots"
    DASHBOARD_FILE = "dashboards.json"
    SCHEDULE_FILE = "schedule.json"
    SETTINGS_FILE = "settings.json"
    DAYS_TO_KEEP = 3
    EST = pytz.timezone("America/New_York")

def ensure_dirs():
    for d in [Config.LOG_DIR, Config.TMP_DIR, Config.SCREENSHOT_ARCHIVE_DIR]:
        os.makedirs(d, exist_ok=True)
    logger.info(f"Ensured directories exist: {Config.TMP_DIR}, {Config.SCREENSHOT_ARCHIVE_DIR}")
    logger.info(f"Current working directory: {os.getcwd()}")

log_file = os.path.join(Config.LOG_DIR, f"analysis_{datetime.now().strftime('%Y%m%d')}.log")
logger = logging.getLogger("SplunkAutomator")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler(sys.stdout))

def archive_and_clean_tmp() -> None:
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    for folder in os.listdir(Config.TMP_DIR):
        folder_path = os.path.join(Config.TMP_DIR, folder)
        if os.path.isdir(folder_path) and folder != today_str:
            archive_path = os.path.join(Config.SCREENSHOT_ARCHIVE_DIR, folder)
            if os.path.exists(archive_path):
                shutil.rmtree(archive_path)
            shutil.move(folder_path, archive_path)
            logger.info(f"Archived {folder_path} to {archive_path}")
    for fname in os.listdir(Config.TMP_DIR):
        fpath = os.path.join(Config.TMP_DIR, fname)
        if os.path.isfile(fpath):
            os.remove(fpath)
            logger.info(f"Removed stray file {fpath} from tmp")

def purge_old_archives() -> None:
    now = datetime.now()
    logger.info(f"Purging contents of archives older than {Config.DAYS_TO_KEEP} days. Now: {now}")
    for folder in os.listdir(Config.SCREENSHOT_ARCHIVE_DIR):
        folder_path = os.path.join(Config.SCREENSHOT_ARCHIVE_DIR, folder)
        if not os.path.isdir(folder_path):
            continue
        try:
            folder_date = datetime.strptime(folder, "%Y-%m-%d")
            age = (now - folder_date).days
            logger.info(f"Found archive: {folder} (age: {age} days)")
            if age > Config.DAYS_TO_KEEP:
                for filename in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, filename)
                    try:
                        if os.path.isfile(file_path) or os.path.islink(file_path):
                            os.remove(file_path)
                            logger.info(f"Deleted file: {file_path}")
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            logger.info(f"Deleted subfolder: {file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete {file_path}: {e}")
                logger.info(f"Purged all contents of archive folder: {folder_path} (folder left intact)")
        except ValueError:
            logger.warning(f"Skipping non-date folder: {folder}")

def save_screenshot_to_tmp(screenshot_bytes: bytes, filename: str) -> str:
    ensure_dirs()
    today_str = datetime.now().strftime("%Y-%m-%d")
    day_tmp_dir = os.path.join(Config.TMP_DIR, today_str)
    os.makedirs(day_tmp_dir, exist_ok=True)
    file_path = os.path.join(day_tmp_dir, filename)
    image = Image.open(io.BytesIO(screenshot_bytes))
    draw = ImageDraw.Draw(image)
    timestamp = datetime.now(Config.EST).strftime("%Y-%m-%d %H:%M:%S %Z")
    # Font fallback logic
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except Exception:
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None
    draw.text((10, 10), f"Captured: {timestamp}", fill="white", font=font)
    image.save(file_path)
    logger.info(f"Saved screenshot to {file_path}")
    return file_path

# --- Encryption for .secrets ---
def get_key():
    key_file = ".secrets.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    return key

def save_credentials(username: str, password: str) -> bool:
    try:
        key = get_key()
        f = Fernet(key)
        creds = json.dumps({"username": username, "password": password}).encode()
        encrypted = f.encrypt(creds)
        with open(".secrets", "wb") as f2:
            f2.write(encrypted)
        logger.info("Credentials saved securely (encrypted).")
        return True
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        return False

def load_credentials():
    if not os.path.exists(".secrets"):
        return None, None
    try:
        key = get_key()
        f = Fernet(key)
        with open(".secrets", "rb") as f2:
            decrypted = f.decrypt(f2.read())
        data = json.loads(decrypted.decode())
        return data.get("username"), data.get("password")
    except Exception as e:
        logger.error(f"Error loading credentials: {e}")
        return None, None

# --- TimeRangeDialog class unchanged from your previous code ---

class TimeRangeDialog(Toplevel):
    # ... as before (unchanged for brevity, see your code) ...
    # (Copy your existing TimeRangeDialog here)

# --- Main Application ---
class SplunkAutomatorApp:
    MAX_CONCURRENT_DASHBOARDS = 3

    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Splunk Dashboard Automator")
        master.geometry(self.load_settings().get("geometry", "1200x800"))
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
        schedule_menu.add_command(label="Cancel Schedule", command=self.cancel_scheduled_analysis)
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        controls_frame = ttk.Frame(main_frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=(0,10))
        btn_config = [("Add", self.add_dashboard), ("Delete", self.delete_dashboard), 
                      ("Select All", self.select_all_dashboards), ("Deselect All", self.deselect_all_dashboards)]
        for i, (text, cmd) in enumerate(btn_config):
            ttk.Button(controls_frame, text=text, command=cmd).grid(row=0, column=i, padx=5)
        ttk.Label(controls_frame, text="Filter by Group:").grid(row=0, column=10, padx=(20,5))
        self.group_filter_var = tk.StringVar(value=self.last_group)
        self.group_filter = ttk.Combobox(controls_frame, textvariable=self.group_filter_var, state="readonly", width=15)
        self.group_filter.grid(row=0, column=11, padx=5)
        self.group_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())
        tree_frame = ttk.LabelFrame(main_frame, text="Dashboards")
        tree_frame.grid(row=1, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(1, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.treeview = ttk.Treeview(tree_frame, columns=("Sel","Name","URL","Group","Status"), show="headings", selectmode="extended")
        for col, width in zip(("Sel","Name","URL","Group","Status"), (40,250,400,100,300)):
            self.treeview.heading(col, text=col)
            self.treeview.column(col, width=width)
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.treeview.grid(row=0, column=0, sticky="nsew")
        self.treeview.bind("<Button-1>", self.toggle_selection)
        analysis_frame = ttk.Frame(main_frame)
        analysis_frame.grid(row=2, column=0, sticky="ew", pady=10)
        ttk.Button(analysis_frame, text="Capture Screenshots", command=self.capture_screenshots_thread).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Analyze Dashboards", command=self.run_analysis_thread).pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(analysis_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, expand=True, padx=20, side=tk.LEFT)
        status_frame = ttk.Frame(self.master)
        status_frame.grid(row=1, column=0, sticky="ew")
        ttk.Label(status_frame, textvariable=self.status_message, anchor="w").pack(fill=tk.X)
        for i in range(3): main_frame.grid_rowconfigure(i, weight=0 if i!=1 else 1)
        main_frame.grid_columnconfigure(0, weight=1)

    # ... [all other methods as before, unchanged] ...

    # --- Add Dashboard Dialog with dropdown for group and validation ---
    def add_dashboard(self):
        dlg = tk.Toplevel(self.master)
        dlg.title("Add Dashboard")
        dlg.transient(self.master)
        dlg.grab_set()
        frm = ttk.Frame(dlg, padding=15)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="Dashboard name:").grid(row=0, column=0, sticky="e", pady=5)
        name_var = tk.StringVar()
        ttk.Entry(frm, textvariable=name_var, width=40).grid(row=0, column=1, pady=5)
        ttk.Label(frm, text="Dashboard URL:").grid(row=1, column=0, sticky="e", pady=5)
        url_var = tk.StringVar()
        ttk.Entry(frm, textvariable=url_var, width=40).grid(row=1, column=1, pady=5)
        ttk.Label(frm, text="Group name:").grid(row=2, column=0, sticky="e", pady=5)
        existing_groups = sorted({d.get("group", "Default") for d in self.session['dashboards']})
        group_var = tk.StringVar()
        group_combo = ttk.Combobox(frm, textvariable=group_var, values=existing_groups, width=37)
        group_combo.grid(row=2, column=1, pady=5)
        group_combo.set(existing_groups[0] if existing_groups else "Default")
        def on_ok():
            name = name_var.get().strip()
            url = url_var.get().strip()
            group = group_var.get().strip() or "Default"
            if not name:
                messagebox.showerror("Input Error", "Dashboard name cannot be empty.", parent=dlg)
                return
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                messagebox.showerror("Invalid URL", "URL must start with http or https.", parent=dlg)
                return
            name_lower = name.lower()
            if any(d["name"].strip().lower() == name_lower for d in self.session["dashboards"]):
                messagebox.showerror("Duplicate", "Dashboard name already exists.", parent=dlg)
                return
            self.session['dashboards'].append({"name": name, "url": url, "group": group, "selected": True})
            self.save_dashboards()
            self.refresh_dashboard_list()
            self.update_group_filter()
            dlg.destroy()
        ttk.Button(frm, text="Add", command=on_ok).grid(row=3, column=0, columnspan=2, pady=10)
        dlg.wait_window()

    # --- For GUI: Capture Screenshot flow (ends after screenshot) ---
    def capture_screenshots_thread(self):
        archive_and_clean_tmp()
        selected_dbs = [db for db in self.session['dashboards'] if db.get('selected')]
        if not selected_dbs:
            messagebox.showwarning("No Selection", "Please select dashboards.")
            logger.warning("User attempted screenshot capture with no dashboards selected.")
            return
        dialog = TimeRangeDialog(self.master)
        self.master.wait_window(dialog)
        if not dialog.result:
            logger.warning("Screenshot capture cancelled: No time range selected.")
            return
        start_dt, end_dt = dialog.result['start'], dialog.result['end']
        if not self.session['username'] or not self.session['password']:
            messagebox.showerror("Credentials Error", "Splunk credentials are not set.")
            logger.error("Screenshot capture aborted: Splunk credentials not set.")
            return
        self.update_progress(0, len(selected_dbs))
        for db in selected_dbs:
            self.update_dashboard_status(db['name'], "Queued")
        logger.info(f"Starting screenshot capture for {len(selected_dbs)} dashboards. Time range: {start_dt} to {end_dt}")
        def run():
            asyncio.run(self._capture_screenshots_async(selected_dbs, start_dt, end_dt))
        Thread(target=run, daemon=True).start()

    async def _capture_screenshots_async(self, dashboards, start_dt, end_dt):
        logger.info(f"[LOG] Starting screenshot capture for {len(dashboards)} dashboards.")
        self.progress_bar['maximum'] = len(dashboards)
        ensure_dirs()
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_DASHBOARDS)
        async with async_playwright() as p:
            async def process_dashboard_wrapper(db, idx):
                async with semaphore:
                    name = db['name']
                    try:
                        await self.process_single_dashboard(p, db, start_dt, end_dt, capture_only=True)
                    except Exception as e:
                        logger.warning(f"Error during screenshot capture for {name}: {e}")
                    self.update_progress(idx + 1, len(dashboards))
            tasks = [process_dashboard_wrapper(db, idx) for idx, db in enumerate(dashboards)]
            await asyncio.gather(*tasks)
        self.update_status("Screenshot capture run has finished.")
        self.master.after(0, lambda: messagebox.showinfo("Complete", "Screenshot capture run has finished."))

    # --- Studio full-page screenshot, URL param, evidence overlay ---
    async def process_single_dashboard(self, playwright, db_data, start_dt, end_dt, capture_only=False):
        name = db_data['name']
        logger.info(f"[LOG] Starting analysis for dashboard '{name}'.")
        self.update_dashboard_status(name, "Launching...")
        browser = None
        try:
            browser = await playwright.chromium.launch(headless=False)
            logger.info(f"[LOG] Launched browser for '{name}'.")
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            is_studio = await self._wait_for_splunk_dashboard_to_load(page, name)
            full_url = self.format_time_for_url(db_data['url'], start_dt, end_dt, is_studio=is_studio)
            logger.info(f"[LOG] Dashboard '{name}' - Navigating to URL: {full_url}")
            self.update_dashboard_status(name, "Loading Dashboard...")
            await page.goto(full_url, timeout=120_000)
            logger.info(f"[LOG] Dashboard '{name}' - Page loaded.")
            username_field = page.locator('input[name="username"]')
            if await username_field.is_visible(timeout=5000):
                self.update_dashboard_status(name, "Logging in...")
                logger.info(f"[LOG] Dashboard '{name}' - Login form detected, filling username/password.")
                await username_field.fill(self.session['username'])
                await page.locator('input[name="password"]').fill(self.session['password'])
                submit_button = page.locator('button[type="submit"], input[type="submit"]').first
                await submit_button.click()
                logger.info(f"[LOG] Dashboard '{name}' - Submitted login form.")
                try:
                    await page.wait_for_url(lambda url: "account/login" not in url, timeout=15000)
                    logger.info(f"[LOG] Dashboard '{name}' - Login successful.")
                except PlaywrightTimeoutError:
                    self.update_dashboard_status(name, "Error: Login Failed.")
                    logger.error(f"[LOG] Dashboard '{name}' - Login failed after submit.")
                    self.handle_login_failure()
                    return
            filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now(Config.EST).strftime('%H%M%S')}.png"
            if is_studio:
                try:
                    height = await page.evaluate("""
                        () => {
                            const el = document.querySelector('splunk-dashboard-view');
                            return el ? el.scrollHeight : document.body.scrollHeight;
                        }
                    """)
                    await page.set_viewport_size({"width": 1280, "height": height})
                except Exception as e:
                    logger.warning(f"Could not resize viewport for Studio: {e}")
                screenshot_bytes = await page.screenshot(full_page=True)
            else:
                screenshot_bytes = await page.screenshot(full_page=True)
            save_screenshot_to_tmp(screenshot_bytes, filename)
            self.update_dashboard_status(name, f"Success: {filename}")
            logger.info(f"Screenshot for '{name}' saved to tmp/{filename}")
            if not capture_only:
                pass
        except Exception as e:
            error_msg = f"Error: {str(e).splitlines()[0]}"
            self.update_dashboard_status(name, error_msg)
            self.update_status(error_msg, "error")
            logger.error(f"Error processing '{name}': {e}", exc_info=True)
            raise
        finally:
            if browser:
                try:
                    await browser.close()
                    logger.info(f"[LOG] Browser closed for dashboard '{name}'.")
                except Exception as e:
                    logger.warning(f"[LOG] Error closing browser for '{name}': {e}")

    async def _wait_for_splunk_dashboard_to_load(self, page, name):
        is_studio = False
        try:
            await page.wait_for_selector("splunk-dashboard-view", timeout=5_000)
            is_studio = True
            logger.info(f"[LOG] Dashboard '{name}' - Detected Splunk Dashboard Studio")
        except Exception:
            logger.info(f"[LOG] Dashboard '{name}' - Detected Splunk Classic Dashboard")
        try:
            await page.wait_for_selector("splunk-dashboard-view, div.dashboard-body", timeout=120_000)
        except Exception:
            logger.warning(f"[LOG] Dashboard '{name}' - Dashboard body selector not found within timeout.")
            self.update_dashboard_status(name, "Error: Dashboard body not found.")
            return is_studio
        if is_studio:
            self.update_dashboard_status(name, "Studio: Waiting for panels to render...")
            logger.info(f"[LOG] Dashboard '{name}' - Waiting for Studio panels to render.")
            # ... (Studio-specific loading script as before) ...
        else:
            # ... (Classic loading logic as before) ...
            pass
        self.update_dashboard_status(name, "Final stabilization...")
        try:
            await page.evaluate("""() => new Promise(resolve => {
                let lastChange = Date.now();
                const observer = new MutationObserver(() => lastChange = Date.now());
                observer.observe(document.body, { childList: true, subtree: true });
                const interval = setInterval(() => {
                    if (Date.now() - lastChange > 2000) {
                        clearInterval(interval);
                        observer.disconnect();
                        resolve();
                    }
                }, 500);
            })""")
        except Exception:
            logger.info(f"[LOG] Dashboard '{name}' - No additional changes detected during stabilization.")
        logger.info(f"[LOG] Dashboard '{name}' - Dashboard fully loaded.")
        return is_studio

    def format_time_for_url(self, base_url: str, start_dt, end_dt, is_studio=False) -> str:
        params = {}
        param_prefix = "form.global_time" if is_studio else "form.time_field"
        if isinstance(start_dt, str):
            params[f'{param_prefix}.earliest'] = start_dt
        else:
            params[f'{param_prefix}.earliest'] = int(start_dt.timestamp())
        if isinstance(end_dt, str):
            params[f'{param_prefix}.latest'] = end_dt
        else:
            params[f'{param_prefix}.latest'] = int(end_dt.timestamp())
        full_url = f"{base_url.split('?')[0]}?{urlencode(params)}"
        logger.info(f"[LOG] Composed dashboard URL: {full_url}")
        return full_url

    # ... rest of the methods unchanged ...

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        logger.info("Application closing.")
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    root.minsize(700, 500)
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
