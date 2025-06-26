import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel
from playwright.async_api import async_playwright, Page, TimeoutError as PlaywrightTimeoutError
import asyncio
from datetime import datetime, timedelta, time as dt_time
import pytz
import os
import sys
import re
import json
from urllib.parse import urlparse, urlencode
from threading import Thread, Event
import signal
import logging
import time

try:
    from tkcalendar import DateEntry
except ImportError:
    messagebox.showerror("Dependency Error", "The 'tkcalendar' library is not found. Please install it by running:\npip install tkcalendar")
    sys.exit(1)

# Logging Setup
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"analysis_{datetime.now().strftime('%Y%m%d')}.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

# Global Variables & Configuration
DASHBOARD_FILE = "dashboards.json"
SCHEDULE_FILE = "schedule.json"
SECRETS_FILE = ".secrets"
est = pytz.timezone("America/New_York")
SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

app = None
treeview = None
progress_bar = None
schedule_thread = None
stop_schedule_event = Event()

SPLUNK_WAIT_TIMEOUT_MS = 120000
CONCURRENT_BROWSERS_LIMIT = 3
browser_semaphore = asyncio.Semaphore(CONCURRENT_BROWSERS_LIMIT)

# Credential Management
def load_credentials():
    if os.path.exists(SECRETS_FILE):
        try:
            with open(SECRETS_FILE, 'r') as f:
                creds = json.load(f)
                return creds.get("username"), creds.get("password")
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Could not read {SECRETS_FILE}: {e}")
    return None, None

def save_credentials(username, password):
    try:
        with open(SECRETS_FILE, 'w') as f:
            json.dump({"username": username, "password": password}, f)
        os.chmod(SECRETS_FILE, 0o600)
        logging.info(f"Credentials saved to {SECRETS_FILE}")
        return True
    except IOError as e:
        logging.error(f"Failed to save credentials: {e}")
        messagebox.showerror("Error", "Could not save credentials to file.")
        return False

USERNAME, PASSWORD = load_credentials()

# Time Range Dialog Class
class TimeRangeDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Select Time Range (EST)")
        self.geometry("700x500")
        self.result = {}
        self.est = pytz.timezone("America/New_York")
        
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame, width=150)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        options = ["Presets", "Relative", "Date Range", "Date & Time Range", "Advanced"]
        self.option_var = tk.StringVar(value=options[0])

        for option in options:
            rb = ttk.Radiobutton(left_frame, text=option, variable=self.option_var, value=option, command=self.show_selected_frame)
            rb.pack(anchor="w", pady=5)
        
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.frames = {option: ttk.Frame(self.content_frame) for option in options}
        self.build_presets_frame(self.frames["Presets"])
        self.build_relative_frame(self.frames["Relative"])
        self.build_date_range_frame(self.frames["Date Range"])
        self.build_datetime_range_frame(self.frames["Date & Time Range"])
        self.build_advanced_frame(self.frames["Advanced"])

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="Apply", command=self.on_apply).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)

        self.show_selected_frame()
        self.focus_set()

    def show_selected_frame(self):
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[self.option_var.get()].pack(fill=tk.BOTH, expand=True)

    def build_presets_frame(self, parent):
        presets = [
            "Last 15 minutes", "Last 60 minutes", "Last 4 hours", "Last 24 hours",
            "Last 7 days", "Last 30 days", "Today", "Yesterday", "Previous week",
            "Previous month", "Previous year", "Week to date", "Month to date", 
            "Year to date", "All time"
        ]
        for preset in presets:
            btn = ttk.Button(parent, text=preset, command=lambda p=preset: self.select_preset(p))
            btn.pack(pady=4, padx=10, fill=tk.X)

    def build_relative_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Relative Time Range").pack(anchor="w")
        
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)
        self.relative_amount = ttk.Entry(options_frame, width=5)
        self.relative_amount.pack(side=tk.LEFT, padx=2)
        self.relative_amount.insert(0, "1")
        
        units = ["minutes", "hours", "days", "weeks", "months", "years"]
        self.relative_unit = ttk.Combobox(options_frame, values=units, state="readonly", width=8)
        self.relative_unit.set("hours")
        self.relative_unit.pack(side=tk.LEFT, padx=2)
        ttk.Label(options_frame, text="ago until now").pack(side=tk.LEFT, padx=5)

    def build_date_range_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Date Range").pack(anchor="w")
        
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=10)
        ttk.Label(controls_frame, text="Between").pack(side=tk.LEFT)
        self.start_date = DateEntry(controls_frame)
        self.start_date.pack(side=tk.LEFT, padx=5)
        ttk.Label(controls_frame, text="and").pack(side=tk.LEFT, padx=5)
        self.end_date = DateEntry(controls_frame)
        self.end_date.pack(side=tk.LEFT, padx=5)
        ttk.Label(controls_frame, text="(00:00:00 to 23:59:59)").pack(side=tk.LEFT, padx=5)

    def build_datetime_range_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Date & Time Range").pack(anchor="w")
        
        start_frame = ttk.Frame(frame)
        start_frame.pack(fill=tk.X, pady=5)
        ttk.Label(start_frame, text="Earliest:").pack(side=tk.LEFT)
        self.dt_start_date = DateEntry(start_frame)
        self.dt_start_date.pack(side=tk.LEFT, padx=5)
        self.dt_start_time = ttk.Entry(start_frame, width=12)
        self.dt_start_time.insert(0, "00:00:00")
        self.dt_start_time.pack(side=tk.LEFT, padx=5)
        
        end_frame = ttk.Frame(frame)
        end_frame.pack(fill=tk.X, pady=5)
        ttk.Label(end_frame, text="Latest:").pack(side=tk.LEFT)
        self.dt_end_date = DateEntry(end_frame)
        self.dt_end_date.pack(side=tk.LEFT, padx=5)
        self.dt_end_time = ttk.Entry(end_frame, width=12)
        self.dt_end_time.insert(0, "23:59:59")
        self.dt_end_time.pack(side=tk.LEFT, padx=5)

    def build_advanced_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Advanced Time Range").pack(anchor="w")
        
        epoch_frame = ttk.Frame(frame)
        epoch_frame.pack(fill=tk.X, pady=10)
        ttk.Label(epoch_frame, text="Earliest (epoch):").grid(row=0, column=0, sticky="w")
        self.earliest_epoch = ttk.Entry(epoch_frame)
        self.earliest_epoch.grid(row=0, column=1, padx=5)
        ttk.Label(epoch_frame, text="Latest (epoch):").grid(row=1, column=0, sticky="w", pady=5)
        self.latest_epoch = ttk.Entry(epoch_frame)
        self.latest_epoch.grid(row=1, column=1, padx=5)

    def select_preset(self, preset):
        now = datetime.now(self.est)
        if preset == "Last 15 minutes":
            start = now - timedelta(minutes=15)
            end = now
        elif preset == "Last 60 minutes":
            start = now - timedelta(hours=1)
            end = now
        elif preset == "Last 4 hours":
            start = now - timedelta(hours=4)
            end = now
        elif preset == "Last 24 hours":
            start = now - timedelta(hours=24)
            end = now
        elif preset == "Last 7 days":
            start = now - timedelta(days=7)
            end = now
        elif preset == "Last 30 days":
            start = now - timedelta(days=30)
            end = now
        elif preset == "Today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif preset == "Yesterday":
            yesterday = now - timedelta(days=1)
            start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif preset == "Previous week":
            start = now - timedelta(days=now.weekday() + 7)
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
        elif preset == "Previous month":
            start = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = (start + timedelta(days=32)).replace(day=1) - timedelta(microseconds=1)
        elif preset == "Previous year":
            start = datetime(now.year - 1, 1, 1, tzinfo=self.est)
            end = datetime(now.year - 1, 12, 31, 23, 59, 59, 999999, tzinfo=self.est)
        elif preset == "Week to date":
            start = now - timedelta(days=now.weekday())
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif preset == "Month to date":
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif preset == "Year to date":
            start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif preset == "All time":
            start = datetime(1970, 1, 1, tzinfo=self.est)
            end = now
        self.result = {"start": start, "end": end}
        self.destroy()

    def on_apply(self):
        try:
            option = self.option_var.get()
            now = datetime.now(self.est)
            if option == "Relative":
                amount = int(self.relative_amount.get())
                unit = self.relative_unit.get()
                if unit == "minutes": start = now - timedelta(minutes=amount)
                elif unit == "hours": start = now - timedelta(hours=amount)
                elif unit == "days": start = now - timedelta(days=amount)
                elif unit == "weeks": start = now - timedelta(weeks=amount)
                elif unit == "months": start = now - timedelta(days=amount * 30)
                elif unit == "years": start = now - timedelta(days=amount * 365)
                end = now
                self.result = {"start": start, "end": end}
            elif option == "Date Range":
                start_date = self.start_date.get_date()
                end_date = self.end_date.get_date()
                start = self.est.localize(datetime.combine(start_date, dt_time.min))
                end = self.est.localize(datetime.combine(end_date, dt_time(23, 59, 59, 999999)))
                self.result = {"start": start, "end": end}
            elif option == "Date & Time Range":
                start_date = self.dt_start_date.get_date()
                end_date = self.dt_end_date.get_date()
                start_time = dt_time.fromisoformat(self.dt_start_time.get())
                end_time = dt_time.fromisoformat(self.dt_end_time.get())
                start = self.est.localize(datetime.combine(start_date, start_time))
                end = self.est.localize(datetime.combine(end_date, end_time))
                self.result = {"start": start, "end": end}
            elif option == "Advanced":
                earliest = int(self.earliest_epoch.get())
                latest = int(self.latest_epoch.get())
                start = datetime.fromtimestamp(earliest, tz=self.est)
                end = datetime.fromtimestamp(latest, tz=self.est)
                self.result = {"start": start, "end": end}
            if self.result["start"] >= self.result["end"]:
                raise ValueError("Start time must be before end time.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", f"Invalid time range: {e}", parent=self)

# Main Application Class
class SplunkAutomatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Splunk Dashboard Automator")
        master.geometry("1200x800")
        self.session = {"username": USERNAME, "password": PASSWORD, "dashboards": []}
        self.scheduled = False
        self.schedule_interval = 0
        
        style = ttk.Style(master)
        style.theme_use('clam')
        style.configure("Treeview", rowheight=25, font=("Helvetica", 10))
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        style.configure("TButton", padding=5, font=("Helvetica", 10))
        style.configure("TLabel", padding=5, font=("Helvetica", 10))

        self._setup_ui()
        self.load_dashboards()
        
        if not self.session["username"] or not self.session["password"]:
            master.after(100, lambda: self.manage_credentials(first_time=True))
        self.start_schedule_if_exists()

    def _setup_ui(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Manage Credentials", command=self.manage_credentials)

        schedule_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Schedule", menu=schedule_menu)
        schedule_menu.add_command(label="Configure Schedule", command=self.configure_schedule)
        schedule_menu.add_command(label="View Schedule", command=self.view_schedule)
        schedule_menu.add_command(label="Delete Schedule", command=self.delete_schedule)

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        btn_config = [("Add", self.add_dashboard), ("Delete", self.delete_dashboard), 
                      ("Select All", self.select_all_dashboards), ("Deselect All", self.deselect_all_dashboards)]
        for text, cmd in btn_config:
            ttk.Button(controls_frame, text=text, command=cmd).pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Filter by Group:").pack(side=tk.LEFT, padx=(20, 5))
        self.group_filter_var = tk.StringVar(value="All")
        self.group_filter = ttk.Combobox(controls_frame, textvariable=self.group_filter_var, state="readonly")
        self.group_filter.pack(side=tk.LEFT, padx=5)
        self.group_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())

        tree_frame = ttk.LabelFrame(main_frame, text="Dashboards")
        tree_frame.pack(fill=tk.BOTH, expand=True)
        global treeview
        columns = ("Sel", "Name", "URL", "Group", "Status")
        treeview = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        treeview.heading("Sel", text="✔"); treeview.column("Sel", width=40, anchor=tk.CENTER, stretch=tk.NO)
        treeview.heading("Name", text="Name"); treeview.column("Name", width=250)
        treeview.heading("URL", text="URL"); treeview.column("URL", width=400)
        treeview.heading("Group", text="Group"); treeview.column("Group", width=100)
        treeview.heading("Status", text="Status"); treeview.column("Status", width=300)

        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=treeview.yview)
        treeview.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        treeview.bind("<Button-1>", self.toggle_selection)

        analysis_frame = ttk.Frame(main_frame)
        analysis_frame.pack(fill=tk.X, pady=10)
        ttk.Button(analysis_frame, text="Analyze Selected", command=self.run_analysis_thread).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Schedule Analysis", command=self.schedule_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Cancel Schedule", command=self.cancel_scheduled_analysis).pack(side=tk.LEFT, padx=5)
        
        global progress_bar
        progress_bar = ttk.Progressbar(analysis_frame, orient="horizontal", mode="determinate")
        progress_bar.pack(fill=tk.X, expand=True, padx=20)

    def manage_credentials(self, first_time=False):
        d = Toplevel(self.master)
        d.title("Setup Credentials" if first_time else "Manage Credentials")
        d.transient(self.master); d.grab_set()

        ttk.Label(d, text="Please enter your Splunk credentials.").pack(padx=20, pady=10)
        
        user_frame = ttk.Frame(d); user_frame.pack(padx=20, pady=5, fill=tk.X)
        ttk.Label(user_frame, text="Username:", width=10).pack(side=tk.LEFT)
        user_entry = ttk.Entry(user_frame); user_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        user_entry.insert(0, self.session.get("username", ""))

        pass_frame = ttk.Frame(d); pass_frame.pack(padx=20, pady=5, fill=tk.X)
        ttk.Label(pass_frame, text="Password:", width=10).pack(side=tk.LEFT)
        pass_entry = ttk.Entry(pass_frame, show="*"); pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        pass_entry.insert(0, self.session.get("password", ""))

        def on_save():
            user, pwd = user_entry.get().strip(), pass_entry.get().strip()
            if not user or not pwd:
                messagebox.showerror("Input Error", "Fields cannot be empty.", parent=d)
                return
            if save_credentials(user, pwd):
                self.session.update({'username': user, 'password': pwd})
                messagebox.showinfo("Success", "Credentials saved.", parent=d)
                d.destroy()

        ttk.Button(d, text="Save Credentials", command=on_save).pack(pady=20)
        self.master.wait_window(d)

    def add_dashboard(self):
        name = simpledialog.askstring("Input", "Enter dashboard name:")
        if not name: return
        if any(d["name"].strip().lower() == name.strip().lower() for d in self.session["dashboards"]):
            messagebox.showerror("Duplicate", "Dashboard name already exists.")
            return
        url = simpledialog.askstring("Input", "Enter dashboard URL:")
        if not url or not url.startswith("http"):
            messagebox.showerror("Invalid URL", "URL must start with http or https.")
            return
        group = simpledialog.askstring("Input", "Enter group name:", initialvalue="Default") or "Default"
        
        self.session['dashboards'].append({"name": name.strip(), "url": url.strip(), "group": group.strip(), "selected": True})
        self.save_dashboards()
        self.refresh_dashboard_list()
        self.update_group_filter()

    def delete_dashboard(self):
        if not treeview.selection():
            messagebox.showwarning("Selection Error", "Please select a dashboard to delete.")
            return
        if messagebox.askyesno("Confirm Delete", "Delete selected dashboards?"):
            indices = sorted([int(iid) for iid in treeview.selection()], reverse=True)
            for index in indices:
                del self.session['dashboards'][index]
            self.save_dashboards()
            self.refresh_dashboard_list()
            self.update_group_filter()

    def select_all_dashboards(self):
        for db in self.session['dashboards']: db['selected'] = True
        self.refresh_dashboard_list()

    def deselect_all_dashboards(self):
        for db in self.session['dashboards']: db['selected'] = False
        self.refresh_dashboard_list()

    def toggle_selection(self, event):
        item_id = treeview.identify_row(event.y)
        if not item_id or treeview.identify_column(event.x) != "#1": return
        db = self.session['dashboards'][int(item_id)]
        db["selected"] = not db.get("selected", False)
        self.refresh_dashboard_list()

    def load_dashboards(self):
        if os.path.exists(DASHBOARD_FILE):
            try:
                with open(DASHBOARD_FILE, 'r') as f:
                    loaded_dashboards = json.load(f)
                    for db in loaded_dashboards:
                        if "selected" not in db: db["selected"] = False
                        db["status"] = "Pending"
                    self.session['dashboards'] = loaded_dashboards
            except json.JSONDecodeError:
                messagebox.showerror("Load Error", f"{DASHBOARD_FILE} is corrupted.")
        self.update_group_filter()
        self.refresh_dashboard_list()

    def save_dashboards(self):
        with open(DASHBOARD_FILE, 'w') as f:
            dashboards_to_save = [{k: v for k, v in d.items() if k != 'status'} for d in self.session['dashboards']]
            json.dump(dashboards_to_save, f, indent=4)

    def refresh_dashboard_list(self):
        selected_filter = self.group_filter_var.get()
        treeview.delete(*treeview.get_children())
        for idx, db in enumerate(self.session['dashboards']):
            if selected_filter == "All" or db.get('group', 'Default') == selected_filter:
                selected_char = "☑" if db.get("selected", False) else "☐"
                status = db.get("status", "Pending")
                treeview.insert("", "end", iid=str(idx), values=(selected_char, db['name'], db['url'], db.get('group', 'Default'), status))

    def update_group_filter(self):
        groups = {"All"}
        for d in self.session["dashboards"]:
            groups.add(d.get("group", "Default"))
        self.group_filter['values'] = sorted(list(groups))
        if self.group_filter_var.get() not in groups:
            self.group_filter_var.set("All")

    def run_analysis_thread(self, scheduled_run=False):
        if scheduled_run:
            selected_dbs = [db for db in self.session['dashboards'] if db.get('selected')]
            if not selected_dbs:
                logging.warning("No dashboards selected for scheduled analysis.")
                return
            now = datetime.now(est)
            start_dt = now - timedelta(hours=4)  # Default to last 4 hours
            end_dt = now
        else:
            selected_dbs = [db for db in self.session['dashboards'] if db.get('selected')]
            if not selected_dbs:
                messagebox.showwarning("No Selection", "Please select dashboards.")
                return
            dialog = TimeRangeDialog(self.master)
            self.master.wait_window(dialog)
            if not dialog.result: return
            start_dt, end_dt = dialog.result['start'], dialog.result['end']
        
        if not self.session['username'] or not self.session['password']:
            messagebox.showerror("Credentials Error", "Splunk credentials are not set.")
            return

        self.update_progress(0, len(selected_dbs))
        for db in selected_dbs: self.update_dashboard_status(db['name'], "Queued")
            
        analysis_thread = Thread(
            target=lambda: asyncio.run(self.analyze_dashboards_async(selected_dbs, start_dt, end_dt)),
            name="AnalysisThread"
        )
        analysis_thread.daemon = True
        analysis_thread.start()

    async def analyze_dashboards_async(self, dashboards, start_dt, end_dt):
        async with async_playwright() as p:
            tasks = [self.process_single_dashboard(p, db, start_dt, end_dt) for db in dashboards]
            await asyncio.gather(*tasks)
        logging.info("Completed analysis run.")
        if not self.scheduled:
            self.master.after(0, lambda: messagebox.showinfo("Complete", "Analysis run has finished."))

    async def process_single_dashboard(self, playwright, db_data, start_dt, end_dt):
        async with browser_semaphore:
            name = db_data['name']
            self.update_dashboard_status(name, "Launching...")
            browser = None
            try:
                browser = await playwright.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                base_url_parts = urlparse(db_data['url'])
                login_check_url = f"{base_url_parts.scheme}://{base_url_parts.netloc}"
                await page.goto(login_check_url, timeout=SPLUNK_WAIT_TIMEOUT_MS)

                if await page.locator('input[name="username"]').count() > 0:
                    self.update_dashboard_status(name, "Logging in...")
                    await page.fill('input[name="username"]', self.session['username'])
                    await page.fill('input[name="password"]', self.session['password'])
                    await page.click('button[type="submit"], input[type="submit"]')
                    try:
                        await page.wait_for_url(lambda url: "account/login" not in url, timeout=15000)
                    except PlaywrightTimeoutError:
                        self.update_dashboard_status(name, "Error: Login Failed.")
                        self.handle_login_failure()
                        return
                
                full_url = self.format_time_for_url(db_data['url'], start_dt, end_dt)
                self.update_dashboard_status(name, "Loading Dashboard...")
                await page.goto(full_url, timeout=SPLUNK_WAIT_TIMEOUT_MS)

                await self._wait_for_splunk_dashboard_to_load(page, name)

                folder = os.path.join(SCREENSHOT_DIR, datetime.now(est).strftime("%Y-%m-%d"))
                os.makedirs(folder, exist_ok=True)
                filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now(est).strftime('%H%M%S')}.png"
                path = os.path.join(folder, filename)
                await page.screenshot(path=path, full_page=True)
                
                self.update_dashboard_status(name, f"Success: {filename}")
                logging.info(f"Screenshot for '{name}' saved to {path}")
            except Exception as e:
                error_msg = f"Error: {str(e).splitlines()[0]}"
                self.update_dashboard_status(name, error_msg)
                logging.error(f"Error processing '{name}': {e}", exc_info=True)
            finally:
                if browser: await browser.close()
                self.master.after(0, lambda: progress_bar.step())

    async def _wait_for_splunk_dashboard_to_load(self, page: Page, name: str):
        self.update_dashboard_status(name, "Waiting for panels...")
        await page.wait_for_selector("div.dashboard-panel, splunk-dashboard-panel", state="visible", timeout=SPLUNK_WAIT_TIMEOUT_MS)
        
        submit_button = page.locator('button:has-text("Submit"), button:has-text("Apply")').first
        if await submit_button.is_visible(timeout=5000) and await submit_button.is_enabled():
            logging.info(f"Found 'Submit' button for '{name}', clicking it.")
            await submit_button.click()
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS // 2)

        loading_indicators = ["Waiting for data", "Loading...", "Searching...", "Loading data", "Rendering"]
        start = time.time()
        while time.time() - start < 90:
            panels = await page.locator("div.dashboard-panel, splunk-dashboard-panel").all()
            all_panels_loaded = True
            for i, panel in enumerate(panels):
                panel_text = await panel.inner_text()
                if any(indicator in panel_text for indicator in loading_indicators):
                    all_panels_loaded = False
                    break
                export_button = panel.locator('button[aria-label*="Export"], a[aria-label*="Export"]').first
                if await export_button.count() > 0 and not await export_button.is_enabled():
                    all_panels_loaded = False
                    break
            if all_panels_loaded:
                logging.info(f"All panels for '{name}' appear loaded.")
                await asyncio.sleep(3)
                return
            self.update_dashboard_status(name, f"Waiting... ({len(panels)} panels)")
            await asyncio.sleep(3)
        self.update_dashboard_status(name, "Warning: Timeout. Taking screenshot.")

    def format_time_for_url(self, base_url, start_dt, end_dt):
        if start_dt.tzinfo is None: start_dt = est.localize(start_dt)
        if end_dt.tzinfo is None: end_dt = est.localize(end_dt)
        params = {'form.time.earliest': int(start_dt.timestamp()), 'form.time.latest': int(end_dt.timestamp())}
        return f"{base_url.split('?')[0]}?{urlencode(params)}"

    def update_dashboard_status(self, name, status):
        self.master.after(0, lambda: self._update_status_in_ui(name, status))

    def _update_status_in_ui(self, name, status):
        for iid in treeview.get_children():
            if treeview.item(iid)['values'][1] == name:
                vals = list(treeview.item(iid)['values']); vals[4] = status
                treeview.item(iid, values=tuple(vals))
                for db in self.session['dashboards']:
                    if db['name'] == name: db['status'] = status; break
                return

    def update_progress(self, value, maximum=None):
        self.master.after(0, lambda: self._update_progress_in_ui(valueCCGself.scheduled = False
        self.master.after(0, lambda: messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled."))
        logging.info("Scheduled analysis cancelled by user.")
        self.save_schedule()

    def save_schedule(self):
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump({"interval": self.schedule_interval, "active": self.scheduled}, f)

    def start_schedule_if_exists(self):
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE, 'r') as f:
                    config = json.load(f)
                    self.schedule_interval = config.get("interval", 0)
                    self.scheduled = config.get("active", False)
                    if self.scheduled and self.schedule_interval >= 60:
                        self.master.after(0, self.run_scheduled_analysis)
            except (json.JSONDecodeError, IOError) as e:
                logging.error(f"Failed to load schedule: {e}")

# Application Entry Point
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        logging.info("Application closing.")
        stop_schedule_event.set()
        if schedule_thread and schedule_thread.is_alive(): schedule_thread.join()
        app.master.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", on_closing)
    signal.signal(signal.SIGINT, lambda s, f: on_closing())
    root.mainloop()
