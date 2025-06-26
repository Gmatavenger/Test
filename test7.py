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

# --- Dependencies Check ---
try:
    from tkcalendar import DateEntry
except ImportError:
    messagebox.showerror("Dependency Error", "The 'tkcalendar' library is not found. Please install it by running:\npip install tkcalendar")
    sys.exit(1)

# ------------------------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# Global Variables & Configuration
# ------------------------------------------------------------------------------
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

# --- Credential Management ---
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

# ------------------------------------------------------------------------------
# Time Range Dialog Class
# ------------------------------------------------------------------------------
class TimeRangeDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Select Time Range (EST)")
        self.geometry("600x450")
        self.result = {}
        self.est = pytz.timezone("America/New_York")
        
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame, width=150)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        options = ["Presets", "Relative", "Date & Time Range"]
        self.option_var = tk.StringVar(value=options[0])

        for option in options:
            rb = ttk.Radiobutton(left_frame, text=option, variable=self.option_var, value=option, command=self.show_selected_frame)
            rb.pack(anchor="w", pady=5)
        
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.frames = {option: ttk.Frame(self.content_frame) for option in options}
        self.build_presets_frame(self.frames["Presets"])
        self.build_relative_frame(self.frames["Relative"])
        self.build_datetime_range_frame(self.frames["Date & Time Range"])

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
        presets = ["Last 15 minutes", "Last 60 minutes", "Last 4 hours", "Last 24 hours", "Last 7 days", "Today", "Yesterday"]
        for preset in presets:
            btn = ttk.Button(parent, text=preset, command=lambda p=preset: self.select_preset(p))
            btn.pack(pady=4, padx=10, fill=tk.X)

    def build_relative_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Time range from now back to:").pack(anchor="w")
        
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)
        self.relative_amount = ttk.Entry(options_frame, width=5)
        self.relative_amount.pack(side=tk.LEFT, padx=2)
        self.relative_amount.insert(0, "1")
        
        units = ["minutes", "hours", "days"]
        self.relative_unit = ttk.Combobox(options_frame, values=units, state="readonly", width=8)
        self.relative_unit.set("hours")
        self.relative_unit.pack(side=tk.LEFT, padx=2)

    def build_datetime_range_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Earliest:").grid(row=0, column=0, sticky="w", pady=5)
        self.dt_start_date = DateEntry(frame)
        self.dt_start_date.grid(row=0, column=1, padx=5)
        self.dt_start_time = ttk.Entry(frame, width=10)
        self.dt_start_time.insert(0, "00:00:00")
        self.dt_start_time.grid(row=0, column=2, padx=5)
        
        ttk.Label(frame, text="Latest:").grid(row=1, column=0, sticky="w", pady=5)
        self.dt_end_date = DateEntry(frame)
        self.dt_end_date.grid(row=1, column=1, padx=5)
        self.dt_end_time = ttk.Entry(frame, width=10)
        self.dt_end_time.insert(0, "23:59:59")
        self.dt_end_time.grid(row=1, column=2, padx=5)

    def select_preset(self, preset):
        now = datetime.now(self.est)
        end = now
        if preset == "Last 15 minutes": start = now - timedelta(minutes=15)
        elif preset == "Last 60 minutes": start = now - timedelta(hours=1)
        elif preset == "Last 4 hours": start = now - timedelta(hours=4)
        elif preset == "Last 24 hours": start = now - timedelta(hours=24)
        elif preset == "Last 7 days": start = now - timedelta(days=7)
        elif preset == "Today": start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif preset == "Yesterday":
            yesterday = now - timedelta(days=1)
            start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
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
                else: start = now - timedelta(days=amount)
                self.result = {"start": start, "end": now}
            elif option == "Date & Time Range":
                start_date = self.dt_start_date.get_date()
                end_date = self.dt_end_date.get_date()
                start_time = dt_time.fromisoformat(self.dt_start_time.get())
                end_time = dt_time.fromisoformat(self.dt_end_time.get())
                start = self.est.localize(datetime.combine(start_date, start_time))
                end = self.est.localize(datetime.combine(end_date, end_time))
                if end <= start:
                    raise ValueError("End time must be after start time.")
                self.result = {"start": start, "end": end}
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", f"Invalid time range: {e}", parent=self)

# ------------------------------------------------------------------------------
# Main Application Class
# ------------------------------------------------------------------------------
class SplunkAutomatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Splunk Dashboard Automator")
        master.geometry("1200x800")
        self.session = {"username": USERNAME, "password": PASSWORD, "dashboards": []}
        
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

        tree_frame = ttk.LabelFrame(main_frame, text="Dashboards")
        tree_frame.pack(fill=tk.BOTH, expand=True)
        global treeview
        columns = ("Sel", "Name", "URL", "Group", "Status")
        treeview = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        treeview.heading("Sel", text="✔")
        treeview.column("Sel", width=40, anchor=tk.CENTER, stretch=tk.NO)
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
        url = simpledialog.askstring("Input", "Enter dashboard URL:")
        if not url or not url.startswith("http"):
            messagebox.showerror("Invalid URL", "URL must start with http or https.")
            return
        group = simpledialog.askstring("Input", "Enter group name:", initialvalue="Default") or "Default"
        
        self.session['dashboards'].append({"name": name, "url": url, "group": group, "selected": True})
        self.save_dashboards(); self.refresh_dashboard_list()

    def delete_dashboard(self):
        if not treeview.selection():
            messagebox.showwarning("Selection Error", "Please select a dashboard to delete.")
            return
        if messagebox.askyesno("Confirm Delete", "Delete selected dashboards?"):
            indices = sorted([int(iid) for iid in treeview.selection()], reverse=True)
            for index in indices:
                del self.session['dashboards'][index]
            self.save_dashboards(); self.refresh_dashboard_list()

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
                    self.session['dashboards'] = json.load(f)
            except json.JSONDecodeError:
                 messagebox.showerror("Load Error", f"{DASHBOARD_FILE} is corrupted.")
        self.refresh_dashboard_list()

    def save_dashboards(self):
        with open(DASHBOARD_FILE, 'w') as f:
            dashboards_to_save = [{k: v for k, v in d.items() if k != 'status'} for d in self.session['dashboards']]
            json.dump(dashboards_to_save, f, indent=4)

    def refresh_dashboard_list(self):
        selected_ids = {iid for iid in treeview.selection()}
        treeview.delete(*treeview.get_children())
        for idx, db in enumerate(self.session['dashboards']):
            status = db.get("status", "Pending")
            selected_char = "☑" if db.get("selected") else "☐"
            iid = str(idx)
            treeview.insert("", "end", iid=iid, values=(selected_char, db['name'], db['url'], db.get('group', 'Default'), status))
            if iid in selected_ids:
                treeview.selection_add(iid)

    def run_analysis_thread(self, scheduled_run=False, schedule_config=None):
        if scheduled_run and schedule_config:
            selected_dbs = [db for db in self.session['dashboards'] if db['name'] in schedule_config.get('dashboards', [])]
            now = datetime.now(est)
            start_dt = now - timedelta(hours=int(schedule_config.get('time_hours', 4)))
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
            for i, db_data in enumerate(dashboards):
                await self.process_single_dashboard(p, db_data, start_dt, end_dt)
                self.update_progress(i + 1)
        logging.info("Completed analysis run.")
        self.master.after(0, lambda: messagebox.showinfo("Complete", "Analysis run has finished."))
        
    async def process_single_dashboard(self, playwright, db_data, start_dt, end_dt):
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

            await self.wait_for_dashboard_panels(page, name)

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
    
    async def wait_for_dashboard_panels(self, page: Page, name: str):
        self.update_dashboard_status(name, "Waiting for panels...")
        await page.wait_for_selector("div.dashboard-panel", state="visible", timeout=SPLUNK_WAIT_TIMEOUT_MS)
        
        start = time.time()
        while time.time() - start < 90: # 90-second panel wait
            loading_panels = await page.locator("div.dashboard-panel:has-text('Waiting for data'), div.dashboard-panel:has-text('Loading...')").count()
            if loading_panels == 0:
                logging.info(f"All panels for '{name}' appear loaded.")
                await asyncio.sleep(2)
                return
            self.update_dashboard_status(name, f"Waiting... ({loading_panels} panels loading)")
            await asyncio.sleep(3)
        self.update_dashboard_status(name, "Warning: Timeout. Taking screenshot.")

    def format_time_for_url(self, base_url, start_dt, end_dt):
        # NOTE: Some Splunk versions use 'form.time_field.earliest'. Adjust if needed.
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
        self.master.after(0, lambda: self._update_progress_in_ui(value, maximum))

    def _update_progress_in_ui(self, value, maximum):
        if maximum is not None: progress_bar['maximum'] = maximum
        progress_bar['value'] = value

    def handle_login_failure(self):
        self.master.after(0, lambda: self.manage_credentials())

    def configure_schedule(self):
        # ... (Implementation to be added) ...
        messagebox.showinfo("Info", "Schedule configuration not yet implemented.")

    def view_schedule(self):
        # ... (Implementation to be added) ...
        messagebox.showinfo("Info", "Viewing schedules not yet implemented.")
        
    def delete_schedule(self):
        # ... (Implementation to be added) ...
        messagebox.showinfo("Info", "Deleting schedules not yet implemented.")

    def start_schedule_if_exists(self):
        # ... (Implementation to be added) ...
        pass

# --- Application Entry Point ---
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
