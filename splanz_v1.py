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
# Time Range Dialog Class
# ------------------------------------------------------------------------------
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
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        for i, preset in enumerate(presets):
            btn = ttk.Button(
                scrollable_frame, 
                text=preset, 
                width=20,
                command=lambda p=preset: self.select_preset(p)
            )
            btn.pack(pady=2, padx=10, fill=tk.X)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def build_relative_frame(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Time range from now back to:").pack(anchor="w")
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)
        self.relative_amount = ttk.Entry(options_frame, width=5)
        self.relative_amount.pack(side=tk.LEFT, padx=2)
        self.relative_amount.insert(0, "1")
        units = ["minutes", "hours", "days", "weeks", "months", "years"]
        self.relative_unit = ttk.Combobox(options_frame, values=units, state="readonly", width=8)
        self.relative_unit.current(1)  # Default to hours
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
        end = now
        if preset == "Last 15 minutes":
            start = now - timedelta(minutes=15)
        elif preset == "Last 60 minutes":
            start = now - timedelta(hours=1)
        elif preset == "Last 4 hours":
            start = now - timedelta(hours=4)
        elif preset == "Last 24 hours":
            start = now - timedelta(hours=24)
        elif preset == "Last 7 days":
            start = now - timedelta(days=7)
        elif preset == "Last 30 days":
            start = now - timedelta(days=30)
        elif preset == "Today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
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
        elif preset == "Month to date":
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif preset == "Year to date":
            start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        elif preset == "All time":
            start = datetime(1970, 1, 1, tzinfo=self.est)
        self.result = {"start": start, "end": end}
        self.destroy()

    def on_apply(self):
        try:
            now = datetime.now(self.est)
            option = self.option_var.get()
            if option == "Relative":
                amount = int(self.relative_amount.get())
                unit = self.relative_unit.get()
                if unit == "minutes":
                    start = now - timedelta(minutes=amount)
                elif unit == "hours":
                    start = now - timedelta(hours=amount)
                elif unit == "days":
                    start = now - timedelta(days=amount)
                elif unit == "weeks":
                    start = now - timedelta(weeks=amount)
                elif unit == "months":
                    start = now - timedelta(days=amount*30)
                elif unit == "years":
                    start = now - timedelta(days=amount*365)
                self.result = {"start": start, "end": now}
            elif option == "Date Range":
                start_date = self.start_date.get_date()
                end_date = self.end_date.get_date()
                start = self.est.localize(datetime.combine(start_date, dt_time.min))
                end = self.est.localize(datetime.combine(end_date, dt_time(23, 59, 59, 999999)))
                self.result = {"start": start, "end": end}
            elif option == "Date & Time Range":
                start_date = self.dt_start_date.get_date()
                end_date = self.dt_end_date.get_date()
                start_time = self.parse_time(self.dt_start_time.get())
                end_time = self.parse_time(self.dt_end_time.get())
                start = self.est.localize(datetime.combine(start_date, start_time))
                end = self.est.localize(datetime.combine(end_date, end_time))
                if end <= start:
                    raise ValueError("End time must be after start time.")
                self.result = {"start": start, "end": end}
            elif option == "Advanced":
                earliest = int(self.earliest_epoch.get())
                latest = int(self.latest_epoch.get())
                start = datetime.fromtimestamp(earliest, tz=self.est)
                end = datetime.fromtimestamp(latest, tz=self.est)
                if end <= start:
                    raise ValueError("End time must be after start time.")
                self.result = {"start": start, "end": end}
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", f"Invalid time range: {e}", parent=self)

    def parse_time(self, time_str):
        parts = time_str.split(':')
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 else 0
        second = int(parts[2]) if len(parts) > 2 else 0
        return dt_time(hour, minute, second)

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
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Manage Credentials", command=self.manage_credentials)
        settings_menu.add_command(label="Set Concurrency", command=self.set_concurrency)
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
        self.treeview = ttk.Treeview(tree_frame, columns=("Sel","Name","URL","Group","Status"), show="headings")
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
        ttk.Button(analysis_frame, text="Analyze Selected", command=self.run_analysis_thread).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Schedule Analysis", command=self.schedule_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Label(analysis_frame, text="Concurrency:").pack(side=tk.LEFT, padx=5)
        self.concurrent_spin = tk.Spinbox(analysis_frame, from_=1, to=10, width=3, command=self.update_concurrency)
        self.concurrent_spin.delete(0, tk.END)
        self.concurrent_spin.insert(0, str(self.concurrency_limit))
        self.concurrent_spin.pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(analysis_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, expand=True, padx=20, side=tk.LEFT)
        status_frame = ttk.Frame(self.master)
        status_frame.grid(row=1, column=0, sticky="ew")
        ttk.Label(status_frame, textvariable=self.status_message, anchor="w").pack(fill=tk.X)
        for i in range(3): main_frame.grid_rowconfigure(i, weight=0 if i!=1 else 1)
        main_frame.grid_columnconfigure(0, weight=1)

    def update_status(self, msg, level="info"):
        self.status_message.set(msg)
        if level == "error":
            logger.error(msg)
        else:
            logger.info(msg)

    def manage_credentials(self, first_time=False):
        dlg = tk.Toplevel(self.master)
        dlg.title("Setup Credentials" if first_time else "Manage Credentials")
        dlg.transient(self.master)
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        frm = ttk.Frame(dlg, padding=15)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="Splunk Username:").grid(row=0, column=0, sticky="e", pady=5)
        user_var = tk.StringVar(value=self.session.get("username", ""))
        user_entry = ttk.Entry(frm, textvariable=user_var, width=30)
        user_entry.grid(row=0, column=1, pady=5)
        user_entry.focus_set()
        ttk.Label(frm, text="Splunk Password:").grid(row=1, column=0, sticky="e", pady=5)
        pass_var = tk.StringVar(value=self.session.get("password", ""))
        pass_entry = ttk.Entry(frm, textvariable=pass_var, show="*", width=30)
        pass_entry.grid(row=1, column=1, pady=5)
        show_pw_var = tk.BooleanVar()
        def toggle_pw():
            pass_entry.config(show="" if show_pw_var.get() else "*")
        show_pw = ttk.Checkbutton(frm, text="Show", variable=show_pw_var, command=toggle_pw)
        show_pw.grid(row=1, column=2, padx=5)
        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=(10,0), sticky="ew")
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        def save_and_close():
            username = user_var.get().strip()
            password = pass_var.get().strip()
            if not username or not password:
                messagebox.showerror("Input Error", "Both username and password are required.", parent=dlg)
                return
            self.session["username"] = username
            self.session["password"] = password
            save_credentials(username, password)
            messagebox.showinfo("Credentials Saved", "Credentials have been updated for this session.", parent=dlg)
            logger.info("User updated credentials for current session.")
            dlg.destroy()
        def cancel():
            dlg.destroy()
        ttk.Button(btn_frame, text="Save", command=save_and_close).grid(row=0, column=0, sticky="ew", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=cancel).grid(row=0, column=1, sticky="ew", padx=5)
        dlg.bind("<Return>", lambda e: save_and_close())
        dlg.bind("<Escape>", lambda e: cancel())
        self.master.wait_window(dlg)

    def set_concurrency(self):
        answer = simpledialog.askinteger("Concurrency", "Set number of concurrent browsers (1-10):", initialvalue=self.concurrency_limit, minvalue=1, maxvalue=10)
        if answer:
            self.concurrency_limit = answer
            self.concurrent_spin.delete(0, tk.END)
            self.concurrent_spin.insert(0, str(answer))
            self.save_settings()

    def update_concurrency(self):
        try:
            val = int(self.concurrent_spin.get())
            if 1 <= val <= 10:
                self.concurrency_limit = val
                self.save_settings()
        except:
            pass

    def add_dashboard(self):
        name = simpledialog.askstring("Input", "Enter dashboard name:")
        if not name: return
        url = simpledialog.askstring("Input", "Enter dashboard URL:")
        if not url or not url.startswith("http"):
            messagebox.showerror("Invalid URL", "URL must start with http or https.")
            return
        if any(d["name"].strip().lower() == name.strip().lower() for d in self.session["dashboards"]):
            messagebox.showerror("Duplicate", "Dashboard name already exists.")
            return
        group = simpledialog.askstring("Input", "Enter group name:", initialvalue="Default") or "Default"
        self.session['dashboards'].append({"name": name, "url": url, "group": group, "selected": True})
        self.save_dashboards()
        self.refresh_dashboard_list()
        self.update_group_filter()

    def delete_dashboard(self):
        if not self.treeview.selection():
            messagebox.showwarning("Selection Error", "Please select a dashboard to delete.")
            return
        if messagebox.askyesno("Confirm Delete", "Delete selected dashboards?"):
            indices = sorted([int(iid) for iid in self.treeview.selection()], reverse=True)
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
        item_id = self.treeview.identify_row(event.y)
        if not item_id or self.treeview.identify_column(event.x) != "#1": return
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
        self.update_group_filter()

    def save_dashboards(self):
        with open(DASHBOARD_FILE, 'w') as f:
            dashboards_to_save = [{k: v for k, v in d.items() if k != 'status'} for d in self.session['dashboards']]
            json.dump(dashboards_to_save, f, indent=4)

    def refresh_dashboard_list(self):
        selected_ids = {iid for iid in self.treeview.selection()}
        self.treeview.delete(*self.treeview.get_children())
        selected_filter = self.group_filter_var.get()
        for idx, db in enumerate(self.session['dashboards']):
            group_name = db.get("group", "Default")
            if selected_filter == "All" or group_name == selected_filter:
                status = db.get("status", "Pending")
                selected_char = "☑" if db.get("selected") else "☐"
                iid = str(idx)
                self.treeview.insert("", "end", iid=iid, values=(selected_char, db['name'], db['url'], group_name, status))
                if iid in selected_ids:
                    self.treeview.selection_add(iid)
        self.save_settings()

    def update_group_filter(self):
        groups = {"All"}
        for d in self.session['dashboards']:
            groups.add(d.get("group", "Default"))
        group_filter_values = sorted(list(groups))
        self.group_filter['values'] = group_filter_values
        if self.group_filter_var.get() not in group_filter_values:
            self.group_filter_var.set("All")
        self.refresh_dashboard_list()

    def export_results(self):
        if not self.session['dashboards']:
            messagebox.showinfo("Nothing to export", "No dashboards loaded.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not file: return
        import csv
        with open(file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Name", "URL", "Group", "Status"])
            for db in self.session['dashboards']:
                writer.writerow([db['name'], db['url'], db.get('group',"Default"), db.get('status',"")])
        self.update_status(f"Exported results to {file}")

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_settings(self):
        settings = {
            "geometry": self.master.geometry(),
            "concurrency_limit": self.concurrency_limit,
            "last_group": self.group_filter_var.get(),
            "last_selected_dashboards": [d['name'] for d in self.session['dashboards'] if d.get('selected')]
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=4)

    def run_analysis_thread(self, scheduled_run=False, schedule_config=None):
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
        Thread(target=lambda: asyncio.run(self.analyze_dashboards_async(selected_dbs, start_dt, end_dt)), daemon=True).start()

    async def analyze_dashboards_async(self, dashboards, start_dt, end_dt):
        semaphore = asyncio.Semaphore(self.concurrency_limit)
        async with async_playwright() as p:
            tasks = [self.process_single_dashboard(p, db_data, start_dt, end_dt, semaphore) for db_data in dashboards]
            await asyncio.gather(*tasks)
        self.update_status("Analysis run has finished.")
        self.master.after(0, lambda: messagebox.showinfo("Complete", "Analysis run has finished."))

    async def process_single_dashboard(self, playwright, db_data, start_dt, end_dt, semaphore):
        async with semaphore:
            name = db_data['name']
            self.update_dashboard_status(name, "Launching...")
            browser = None
            try:
                browser = await playwright.chromium.launch(headless=False)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                full_url = self.format_time_for_url(db_data['url'], start_dt, end_dt)
                self.update_dashboard_status(name, "Loading Dashboard...")
                await page.goto(full_url, timeout=120_000)
                username_field = page.locator('input[name="username"]')
                if await username_field.is_visible(timeout=5000):
                    self.update_dashboard_status(name, "Logging in...")
                    await username_field.fill(self.session['username'])
                    await page.locator('input[name="password"]').fill(self.session['password'])
                    submit_button = page.locator('button[type="submit"], input[type="submit"]').first
                    await submit_button.click()
                    try:
                        await page.wait_for_url(lambda url: "account/login" not in url, timeout=15000)
                    except PlaywrightTimeoutError:
                        self.update_dashboard_status(name, "Error: Login Failed.")
                        self.handle_login_failure()
                        return
                await self._wait_for_splunk_dashboard_to_load(page, name)
                folder = os.path.join(SCREENSHOT_DIR, datetime.now(est).strftime("%Y-%m-%d"))
                os.makedirs(folder, exist_ok=True)
                filename = f"{re.sub('[^A-Za-z0-9]+', '_', name)}_{datetime.now(est).strftime('%H%M%S')}.png"
                path = os.path.join(folder, filename)
                await page.screenshot(path=path, full_page=True)
                self.update_dashboard_status(name, f"Success: {filename}")
                logger.info(f"Screenshot for '{name}' saved to {path}")
            except Exception as e:
                error_msg = f"Error: {str(e).splitlines()[0]}"
                self.update_dashboard_status(name, error_msg)
                self.update_status(error_msg, "error")
                logger.error(f"Error processing '{name}': {e}", exc_info=True)
            finally:
                if browser: await browser.close()
                self.progress_bar.step(1)
                self.update_progress(self.progress_bar['value'] + 1, self.progress_bar['maximum'])

    async def _wait_for_splunk_dashboard_to_load(self, page, name):
        self.update_dashboard_status(name, "Waiting for panels...")
        await page.wait_for_selector("div.dashboard-body, splunk-dashboard-view", timeout=120_000)
        submit_button = page.locator('button:has-text("Submit"), button:has-text("Apply")').first
        if await submit_button.is_visible(timeout=5000) and await submit_button.is_enabled(timeout=5000):
            self.update_dashboard_status(name, "Submitting query...")
            await submit_button.click()
            await page.wait_for_load_state('networkidle', timeout=60_000)
        await page.wait_for_selector("div.dashboard-panel, splunk-dashboard-panel", state="visible", timeout=120_000)
        loading_indicators = ["Waiting for data", "Loading...", "Searching...", "Loading data", "Rendering"]
        start_wait = time.time()
        while time.time() - start_wait < 90:
            panels = await page.locator("div.dashboard-panel, splunk-dashboard-panel").all()
            loading_panels = 0
            for panel in panels:
                panel_text = await panel.inner_text()
                if any(indicator in panel_text for indicator in loading_indicators):
                    loading_panels += 1
                    continue
                export_button = panel.locator('button[aria-label*="Export"], a[aria-label*="Export"]').first
                if await export_button.count() > 0 and not await export_button.is_enabled():
                    loading_panels += 1
            if loading_panels == 0:
                logger.info(f"All panels for '{name}' appear loaded.")
                await asyncio.sleep(2)
                return
            self.update_dashboard_status(name, f"Waiting... ({loading_panels} panels loading)")
            await asyncio.sleep(3)
        self.update_dashboard_status(name, "Warning: Timeout. Taking screenshot.")
        logger.warning(f"Timed out waiting for dashboard '{name}' to load completely")

    def format_time_for_url(self, base_url, start_dt, end_dt):
        if start_dt.tzinfo is None: start_dt = est.localize(start_dt)
        if end_dt.tzinfo is None: end_dt = est.localize(end_dt)
        params = {
            'form.time.earliest': int(start_dt.timestamp()),
            'form.time.latest': int(end_dt.timestamp())
        }
        return f"{base_url.split('?')[0]}?{urlencode(params)}"

    def update_dashboard_status(self, name, status):
        self.master.after(0, lambda: self._update_status_in_ui(name, status))

    def _update_status_in_ui(self, name, status):
        for iid in self.treeview.get_children():
            if self.treeview.item(iid)['values'][1] == name:
                vals = list(self.treeview.item(iid)['values']); vals[4] = status
                self.treeview.item(iid, values=tuple(vals))
                for db in self.session['dashboards']:
                    if db['name'] == name: db['status'] = status; break

    def update_progress(self, value, maximum=None):
        self.master.after(0, lambda: self._update_progress_in_ui(value, maximum))

    def _update_progress_in_ui(self, value, maximum):
        if maximum is not None: self.progress_bar['maximum'] = maximum
        self.progress_bar['value'] = value

    def handle_login_failure(self):
        self.master.after(0, lambda: self.manage_credentials())

    def configure_schedule(self):
        interval_str = simpledialog.askstring("Schedule Analysis", "Enter interval in minutes (min 1):")
        if not interval_str:
            return
        try:
            interval = int(interval_str)
            if interval < 1: 
                raise ValueError("Interval must be at least 1 minute.")
        except ValueError as e:
            messagebox.showerror("Invalid Interval", str(e))
            return
        dashboards = [db['name'] for db in self.session['dashboards'] if db.get('selected')]
        if not dashboards:
            messagebox.showwarning("No Selection", "Please select dashboards to schedule.")
            return
        time_hours = simpledialog.askinteger("Time Range", "Hours to look back (default=4):", initialvalue=4)
        if time_hours is None or time_hours < 1:
            messagebox.showerror("Invalid Value", "Hours must be at least 1")
            return
        schedule_config = {
            "interval_minutes": interval,
            "dashboards": dashboards,
            "time_hours": time_hours
        }
        try:
            with open(SCHEDULE_FILE, 'w') as f:
                json.dump(schedule_config, f, indent=4)
            messagebox.showinfo("Schedule Saved", f"Analysis scheduled every {interval} minutes.")
            self.scheduled = True
            self.schedule_interval = interval
            self.run_scheduled_analysis(schedule_config)
        except IOError as e:
            logger.error(f"Failed to save schedule: {e}")
            messagebox.showerror("Error", "Could not save schedule configuration.")

    def start_schedule_if_exists(self):
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE, 'r') as f:
                    schedule_config = json.load(f)
                    self.schedule_interval = schedule_config.get("interval_minutes", 60)
                    self.scheduled = True
                    self.run_scheduled_analysis(schedule_config)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid schedule file: {e}")
        else:
            self.scheduled = False

    def run_scheduled_analysis(self, schedule_config=None):
        if not self.scheduled:
            return
        if schedule_config:
            Thread(
                target=lambda: asyncio.run(
                    self.analyze_dashboards_async(
                        [db for db in self.session['dashboards'] if db['name'] in schedule_config['dashboards']],
                        datetime.now(est) - timedelta(hours=schedule_config['time_hours']),
                        datetime.now(est)
                    )
                ),
                daemon=True
            ).start()
        if self.scheduled:
            self.master.after(self.schedule_interval * 60000, self.run_scheduled_analysis, schedule_config)

    def schedule_analysis(self):
        self.configure_schedule()

    def cancel_scheduled_analysis(self):
        if not self.scheduled:
            messagebox.showinfo("Info", "No active schedule to cancel.")
            return
        self.scheduled = False
        try:
            if os.path.exists(SCHEDULE_FILE):
                os.remove(SCHEDULE_FILE)
            messagebox.showinfo("Schedule Cancelled", "Scheduled analysis has been cancelled.")
        except Exception as e:
            logger.error(f"Error cancelling schedule: {e}")
            messagebox.showerror("Error", "Could not cancel schedule.")

# --- Application Entry Point ---
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        logger.info("Application closing.")
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
