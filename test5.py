import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from playwright.async_api import async_playwright, Page, expect
import asyncio
import time
from datetime import datetime, timedelta, time
import pytz
import os
import sys
import re
import json
import uuid
from urllib.parse import urlparse, urlencode
from threading import Thread
import signal
import logging

# --- Dependencies Check ---
try:
    from tkcalendar import DateEntry
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Error: Missing dependency -> {e.name}")
    print("Please install the required packages by running:")
    print("pip install tkcalendar python-dotenv")
    sys.exit(1)

# ------------------------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dashboard_analysis.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ------------------------------------------------------------------------------
# Load Secrets from .secrets file
# ------------------------------------------------------------------------------
try:
    if os.path.exists(".secrets"):
        load_dotenv(".secrets")
    else:
        logging.warning(".secrets file not found. Credentials can be set in the UI.")
except Exception as e:
    # Use a temporary root to show the error message if the main one isn't ready
    temp_root = tk.Tk()
    temp_root.withdraw()
    messagebox.showerror("Secrets Load Error", f"Failed to load .secrets file: {e}")
    temp_root.destroy()

# ------------------------------------------------------------------------------
# Global Variables & Session Setup
# ------------------------------------------------------------------------------
# Attempt to load from environment, will be None if not found
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")

# Session cache for runtime data
session = {
    "dashboards": [],
    "username": USERNAME,
    "password": PASSWORD,
}

DASHBOARD_FILE = "dashboards.json"
# Use EST for folder naming and timestamps.
est = pytz.timezone("America/New_York")
SCREENSHOT_DIR = os.path.join("screenshots", datetime.now(est).strftime("%Y-%m-%d"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Global placeholders for UI elements
app = None
progress_bar = None
treeview = None
group_filter = None

# Global variables for scheduled runs
scheduled = False
schedule_interval = 0  # in seconds

# Define a default wait timeout for Splunk operations
SPLUNK_WAIT_TIMEOUT_MS = 120000 # 120 seconds for robustness

# Concurrency limit for Playwright browsers
CONCURRENT_BROWSERS_LIMIT = 3 # Adjust based on system resources
browser_semaphore = asyncio.Semaphore(CONCURRENT_BROWSERS_LIMIT)

# ------------------------------------------------------------------------------
# Time Range Dialog Class
# ------------------------------------------------------------------------------
class TimeRangeDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Select Time Range (EST)")
        self.geometry("700x500")
        self.result = {}
        self.est = pytz.timezone("America/New_York")
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        self.focus_set()
        
        # Main layout
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Time Range Types
        left_frame = ttk.Frame(main_frame, width=150)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
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
            rb.pack(anchor="w", pady=5)
        
        # Right panel - Content
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create frames for each option
        self.frames = {}
        for option in options:
            frame = ttk.Frame(self.content_frame)
            self.frames[option] = frame
            if option == "Presets":
                self.build_presets_frame(frame)
            elif option == "Relative":
                self.build_relative_frame(frame)
            elif option == "Date Range":
                self.build_date_range_frame(frame)
            elif option == "Date & Time Range":
                self.build_datetime_range_frame(frame)
            elif option == "Advanced":
                self.build_advanced_frame(frame)
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Apply", command=self.on_apply).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Show initial frame
        self.show_selected_frame()
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self.destroy)
    
    def show_selected_frame(self):
        # Hide all frames
        for frame in self.frames.values():
            frame.pack_forget()
        
        # Show selected frame
        selected = self.option_var.get()
        self.frames[selected].pack(fill=tk.BOTH, expand=True)
    
    def build_presets_frame(self, parent):
        presets = [
            "Last 15 minutes", "Last 60 minutes", "Last 4 hours", "Last 24 hours",
            "Last 7 days", "Last 30 days", "Today", "Yesterday", "Previous week",
            "Previous month", "Previous year", "Week to date", "Month to date", 
            "Year to date", "All time"
        ]
        
        # Create scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Add preset buttons
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
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Relative Time Range").pack(anchor="w")
        
        # Relative time options
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
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Date Range").pack(anchor="w")
        
        # Date range controls
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(controls_frame, text="Between").pack(side=tk.LEFT)
        self.start_date = DateEntry(controls_frame)
        self.start_date.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="and").pack(side=tk.LEFT, padx=5)
        self.end_date = DateEntry(controls_frame)
        self.end_date.pack(side=tk.LEFT, padx=5)
        
        # Time defaults to whole day
        ttk.Label(controls_frame, text="(00:00:00 to 23:59:59)").pack(side=tk.LEFT, padx=5)
    
    def build_datetime_range_frame(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Date & Time Range").pack(anchor="w")
        
        # Start datetime
        start_frame = ttk.Frame(frame)
        start_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(start_frame, text="Earliest:").pack(side=tk.LEFT)
        self.dt_start_date = DateEntry(start_frame)
        self.dt_start_date.pack(side=tk.LEFT, padx=5)
        
        self.dt_start_time = ttk.Entry(start_frame, width=12)
        self.dt_start_time.insert(0, "00:00:00")
        self.dt_start_time.pack(side=tk.LEFT, padx=5)
        
        # End datetime
        end_frame = ttk.Frame(frame)
        end_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(end_frame, text="Latest:").pack(side=tk.LEFT)
        self.dt_end_date = DateEntry(end_frame)
        self.dt_end_date.pack(side=tk.LEFT, padx=5)
        
        self.dt_end_time = ttk.Entry(end_frame, width=12)
        self.dt_end_time.insert(0, "23:59:59")
        self.dt_end_time.pack(side=tk.LEFT, padx=5)
    
    def build_advanced_frame(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Advanced Time Range").pack(anchor="w")
        
        # Epoch time inputs
        epoch_frame = ttk.Frame(frame)
        epoch_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(epoch_frame, text="Earliest (epoch):").grid(row=0, column=0, sticky="w")
        self.earliest_epoch = ttk.Entry(epoch_frame)
        self.earliest_epoch.grid(row=0, column=1, padx=5)
        
        ttk.Label(epoch_frame, text="Latest (epoch):").grid(row=1, column=0, sticky="w", pady=5)
        self.latest_epoch = ttk.Entry(epoch_frame)
        self.latest_epoch.grid(row=1, column=1, padx=5)
        
        # Documentation link
        doc_frame = ttk.Frame(frame)
        doc_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(doc_frame, text="Documentation:").pack(side=tk.LEFT)
        ttk.Label(doc_frame, text="[Z]", foreground="blue", cursor="hand2").pack(side=tk.LEFT, padx=5)
    
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
                
                start = self.est.localize(datetime.combine(start_date, time.min))
                end = self.est.localize(datetime.combine(end_date, time(23, 59, 59, 999999)))
                
                self.result = {"start": start, "end": end}
            
            elif option == "Date & Time Range":
                start_date = self.dt_start_date.get_date()
                end_date = self.dt_end_date.get_date()
                
                # Parse time strings
                start_time = self.parse_time(self.dt_start_time.get())
                end_time = self.parse_time(self.dt_end_time.get())
                
                start = self.est.localize(datetime.combine(start_date, start_time))
                end = self.est.localize(datetime.combine(end_date, end_time))
                
                self.result = {"start": start, "end": end}
            
            elif option == "Advanced":
                earliest = int(self.earliest_epoch.get())
                latest = int(self.latest_epoch.get())
                
                start = datetime.fromtimestamp(earliest, tz=self.est)
                end = datetime.fromtimestamp(latest, tz=self.est)
                
                self.result = {"start": start, "end": end}
            
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", f"Invalid time range: {str(e)}")
    
    def parse_time(self, time_str):
        """Parse HH:MM:SS time string into time object"""
        parts = time_str.split(':')
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 else 0
        second = int(parts[2]) if len(parts) > 2 else 0
        return time(hour, minute, second)

# ------------------------------------------------------------------------------
# Main Application Class
# ------------------------------------------------------------------------------
class SplunkAutomatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Splunk Dashboard Automator")
        master.geometry("1000x750")

        # --- Style ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", padding=6, font=("Helvetica", 10))
        style.configure("TButton", padding=6, font=("Helvetica", 10, "bold"))
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))

        # --- Menu ---
        menubar = tk.Menu(master)
        master.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Manage Credentials", command=self.manage_credentials)

        # --- Main Frame ---
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Controls Frame ---
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(controls_frame, text="Add", command=self.add_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Delete", command=self.delete_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Select All", command=self.select_all_dashboards).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Deselect All", command=self.deselect_all_dashboards).pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Filter by Group:").pack(side=tk.LEFT, padx=(20, 5))
        global group_filter
        self.group_filter_var = tk.StringVar()
        group_filter = ttk.Combobox(controls_frame, textvariable=self.group_filter_var, state="readonly")
        group_filter.pack(side=tk.LEFT, padx=5)
        group_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_dashboard_list())

        # --- Dashboard List (Treeview) ---
        tree_frame = ttk.LabelFrame(main_frame, text="Dashboards")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        global treeview
        columns = ("Selected", "Name", "URL", "Group", "Status")
        treeview = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        treeview.heading("Selected", text="Sel")
        treeview.column("Selected", width=40, anchor=tk.CENTER)
        treeview.heading("Name", text="Name")
        treeview.column("Name", width=200)
        treeview.heading("URL", text="URL")
        treeview.column("URL", width=350)
        treeview.heading("Group", text="Group")
        treeview.column("Group", width=100, anchor=tk.CENTER)
        treeview.heading("Status", text="Status")
        treeview.column("Status", width=200)

        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=treeview.yview)
        treeview.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        treeview.bind("<Button-1>", self.toggle_selection)

        # --- Analysis Frame ---
        analysis_frame = ttk.Frame(main_frame)
        analysis_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(analysis_frame, text="Analyze Selected", command=self.analyze_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Schedule Analysis", command=self.schedule_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Cancel Schedule", command=self.cancel_scheduled_analysis).pack(side=tk.LEFT, padx=5)

        global progress_bar
        progress_bar = ttk.Progressbar(analysis_frame, orient="horizontal", mode="determinate")
        progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=20)
        
        # --- Initial Load ---
        self.load_dashboards()
        self.update_group_filter()
        self.refresh_dashboard_list()
        
    def manage_credentials(self):
        new_username = simpledialog.askstring("Manage Credentials", "Enter Splunk username:",
                                              initialvalue=session.get("username", ""))
        if new_username is not None:
            session["username"] = new_username.strip()
        new_password = simpledialog.askstring("Manage Credentials", "Enter Splunk password:",
                                              show="*", initialvalue=session.get("password", ""))
        if new_password is not None:
            session["password"] = new_password.strip()
        messagebox.showinfo("Credentials Updated", "Credentials have been updated for this session.")
        logging.info("User updated credentials for current session.")

    def add_dashboard(self):
        name = simpledialog.askstring("Dashboard Name", "Enter dashboard name:")
        if not name: return
        url = simpledialog.askstring("Dashboard URL", "Enter dashboard URL:")
        if not url or not url.startswith("http"):
            messagebox.showerror("Invalid URL", "Dashboard URL must start with http or https.")
            return
        group = simpledialog.askstring("Dashboard Group", "Enter dashboard group (optional):", initialvalue="Default")
        if not group: group = "Default"
        
        if any(d["name"].strip().lower() == name.strip().lower() for d in session["dashboards"]):
            messagebox.showerror("Duplicate", "Dashboard name already exists.")
            return
            
        session["dashboards"].append({"name": name.strip(), "url": url.strip(), "group": group.strip(), "selected": False, "status": "Pending"})
        self.save_dashboards()
        self.refresh_dashboard_list()
        self.update_group_filter()
        logging.info(f"Added dashboard: {name} (Group: {group})")

    def delete_dashboard(self):
        selected_items_ids = treeview.selection()
        if not selected_items_ids:
            messagebox.showinfo("Delete Dashboard", "Select dashboards to delete.")
            return
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected dashboards?"):
            return
        
        # The iid of the treeview item is its original index in the list
        indices_to_delete = sorted([int(item_id) for item_id in selected_items_ids], reverse=True)
        names_deleted = []
        for idx in indices_to_delete:
            if 0 <= idx < len(session["dashboards"]):
                names_deleted.append(session["dashboards"][idx]["name"])
                del session["dashboards"][idx]
        
        self.save_dashboards()
        self.refresh_dashboard_list()
        self.update_group_filter()
        logging.info(f"Deleted dashboards: {', '.join(names_deleted)}")

    def refresh_dashboard_list(self):
        for i in treeview.get_children():
            treeview.delete(i)
        
        selected_filter = self.group_filter_var.get()
        for idx, dashboard in enumerate(session["dashboards"]):
            group_name = dashboard.get("group", "Default")
            if selected_filter == "All" or group_name == selected_filter:
                checkbox_state = "☑" if dashboard.get("selected", False) else "☐"
                status = dashboard.get("status", "Pending")
                treeview.insert("", "end", iid=str(idx),
                                values=(checkbox_state, dashboard["name"], dashboard["url"], group_name, status))

    def toggle_selection(self, event):
        item_id = treeview.identify_row(event.y)
        if not item_id: return
        
        column = treeview.identify_column(event.x)
        if column == "#1": # Checkbox column
            dashboard_idx = int(item_id)
            if 0 <= dashboard_idx < len(session["dashboards"]):
                dashboard = session["dashboards"][dashboard_idx]
                dashboard["selected"] = not dashboard.get("selected", False)
                checkbox_state = "☑" if dashboard["selected"] else "☐"
                treeview.set(item_id, "Selected", checkbox_state)

    def select_all_dashboards(self):
        for dashboard in session["dashboards"]:
            dashboard["selected"] = True
        self.refresh_dashboard_list()

    def deselect_all_dashboards(self):
        for dashboard in session["dashboards"]:
            dashboard["selected"] = False
        self.refresh_dashboard_list()

    def update_group_filter(self):
        groups = {"All"}
        for d in session["dashboards"]:
            groups.add(d.get("group", "Default"))
        
        group_filter_values = sorted(list(groups))
        group_filter['values'] = group_filter_values
        if self.group_filter_var.get() not in group_filter_values:
            self.group_filter_var.set("All")
        self.refresh_dashboard_list()

    def get_selected_dashboards(self):
        return [d for d in session["dashboards"] if d.get("selected", False)]
    
    def analyze_selected(self):
        selected_dbs = self.get_selected_dashboards()
        if not selected_dbs:
            messagebox.showwarning("Analyze", "Please select at least one dashboard.")
            return
        if not session["username"] or not session["password"]:
            messagebox.showerror("Credentials Missing", "Please set credentials via Settings -> Manage Credentials.")
            return
        
        start, end = self.get_time_range()
        if not start or not end:
            logging.info("Time range selection cancelled.")
            return
        
        for db in selected_dbs:
            self.update_dashboard_status_ui(db["name"], "Pending...")
        
        progress_bar['maximum'] = len(selected_dbs)
        progress_bar['value'] = 0

        logging.info(f"Starting manual analysis for {len(selected_dbs)} dashboards from {start} to {end}")
        
        # Run asyncio logic in a background thread to not block the GUI
        Thread(target=lambda: asyncio.run(self.analyze_dashboards_async(selected_dbs, start, end)), daemon=True).start()

    def schedule_analysis(self):
        global scheduled, schedule_interval
        if scheduled:
            messagebox.showinfo("Scheduled", "Analysis is already scheduled. Please cancel it first.")
            return
        interval_str = simpledialog.askstring("Schedule Analysis", "Enter interval in seconds (min 60s):")
        try:
            interval = int(interval_str)
            if interval < 60: raise ValueError("Interval must be at least 60 seconds.")
        except (ValueError, TypeError) as ve:
            messagebox.showerror("Invalid Interval", str(ve))
            return
        
        scheduled = True
        schedule_interval = interval
        messagebox.showinfo("Scheduled", f"Analysis scheduled every {interval} seconds.")
        logging.info(f"Scheduled analysis every {interval} seconds.")
        self.master.after(0, self.run_scheduled_analysis)

    def run_scheduled_analysis(self):
        if not scheduled:
            logging.info("Scheduled analysis loop terminated.")
            return
        
        logging.info("Initiating scheduled analysis run.")
        # Run in a background thread to prevent GUI blocking
        Thread(target=self._run_scheduled_analysis_background, daemon=True).start()
        
        # Schedule the next run
        self.master.after(schedule_interval * 1000, self.run_scheduled_analysis)

    def _run_scheduled_analysis_background(self):
        now_est = datetime.now(est)
        # Default to last 4 hours for scheduled runs, as datetime objects
        start_dt = now_est - timedelta(hours=4)
        end_dt = now_est
        
        selected_dbs = self.get_selected_dashboards()
        if not selected_dbs:
            logging.warning("No dashboards selected for scheduled analysis.")
            return

        self.master.after(0, lambda: progress_bar.config(maximum=len(selected_dbs), value=0))
        for db in selected_dbs:
            self.master.after(0, self.update_dashboard_status_ui, db["name"], "Pending...")

        # Format for logging, but use the datetime objects for the analysis call
        logging.info(f"Running scheduled analysis for {len(selected_dbs)} dashboards from {start_dt:%Y-%m-%d %H:%M} to {end_dt:%Y-%m-%d %H:%M}")
        asyncio.run(self.analyze_dashboards_async(selected_dbs, start_dt, end_dt))

    def cancel_scheduled_analysis(self):
        global scheduled
        if not scheduled:
            messagebox.showinfo("Scheduled", "No analysis is currently scheduled.")
            return
        scheduled = False
        messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled.")
        logging.info("Scheduled analysis cancelled by user.")
    
    def load_dashboards(self):
        if os.path.exists(DASHBOARD_FILE):
            try:
                with open(DASHBOARD_FILE, "r") as f:
                    loaded_dashboards = json.load(f)
                    for dashboard in loaded_dashboards:
                        if "selected" not in dashboard: dashboard["selected"] = False
                        dashboard["status"] = "Pending"
                    session["dashboards"] = loaded_dashboards
                logging.info(f"Loaded {len(session['dashboards'])} dashboards.")
            except Exception as e:
                messagebox.showerror("Load Error", f"Error reading {DASHBOARD_FILE}: {e}")
                session["dashboards"] = []
        else:
            logging.info(f"{DASHBOARD_FILE} not found. Starting with an empty list.")

    def save_dashboards(self):
        with open(DASHBOARD_FILE, "w") as f:
            # Don't save transient status
            dashboards_to_save = [{k: v for k, v in d.items() if k != 'status'} for d in session["dashboards"]]
            json.dump(dashboards_to_save, f, indent=2)
        logging.info(f"Saved {len(session['dashboards'])} dashboards.")
        
    def get_time_range(self):
        dialog = TimeRangeDialog(self.master)
        self.master.wait_window(dialog)
        
        if not dialog.result:
            logging.info("Time range selection cancelled.")
            return None, None
        
        return dialog.result["start"], dialog.result["end"]
        
    def format_time_for_url(self, base_url, start_dt, end_dt):
        """Converts datetimes to epoch and formats them into a Splunk URL."""
        if not isinstance(start_dt, datetime) or not isinstance(end_dt, datetime):
            return base_url # Return base if inputs are invalid

        # Ensure datetimes are timezone-aware
        if start_dt.tzinfo is None: start_dt = est.localize(start_dt)
        if end_dt.tzinfo is None: end_dt = est.localize(end_dt)
        
        earliest_epoch = int(start_dt.timestamp())
        latest_epoch = int(end_dt.timestamp())
        
        params = {
            'form.time_field.earliest': earliest_epoch,
            'form.time_field.latest': latest_epoch
        }
        
        # Append params to URL
        query_string = urlencode(params)
        return f"{base_url}?{query_string}"

    async def analyze_dashboards_async(self, dashboards_to_run, start_time, end_time):
        async with async_playwright() as p:
            tasks = [self.analyze_dashboard_instance_async(p, db, start_time, end_time) for db in dashboards_to_run]
            await asyncio.gather(*tasks)
        logging.info("Analysis run finished for all selected dashboards.")
        messagebox.showinfo("Finished", "Dashboard analysis is complete.")
    
    async def analyze_dashboard_instance_async(self, playwright, dashboard_data, start_time, end_time):
        async with browser_semaphore:
            name = dashboard_data["name"]
            url = dashboard_data["url"]
            self.master.after(0, self.update_dashboard_status_ui, name, "Processing...")
            
            # This is the key step: create the full URL with time parameters
            full_url = self.format_time_for_url(url, start_time, end_time)
            
            browser = None
            try:
                browser = await playwright.chromium.launch(headless=True) # Use headless for automation
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                logging.info(f"Navigating to: {full_url}")
                await page.goto(full_url, wait_until='domcontentloaded', timeout=SPLUNK_WAIT_TIMEOUT_MS)

                # --- Handle Login ---
                # Check if login page is present by looking for a username field
                username_field = page.locator('input[name="username"]')
                if await username_field.is_visible(timeout=5000):
                    logging.info("Login page detected. Attempting to log in.")
                    await username_field.fill(session["username"])
                    await page.locator('input[name="password"]').fill(session["password"])
                    await page.locator('button[type="submit"], input[type="submit"]').click()
                    # Wait for navigation after login
                    await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS)
                    logging.info("Login successful.")
                else:
                    logging.info("Login page not detected, assuming already logged in.")

                # --- Wait for Dashboard to Load and Take Screenshot ---
                await self._wait_for_splunk_dashboard_to_load(page)

                sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
                timestamp = datetime.now(est).strftime("%Y%m%d-%H%M%S")
                screenshot_path = os.path.join(SCREENSHOT_DIR, f"{sanitized_name}_{timestamp}.png")
                await page.screenshot(path=screenshot_path, full_page=True)
                
                self.master.after(0, self.update_dashboard_status_ui, name, f"Success: {os.path.basename(screenshot_path)}")
                logging.info(f"Successfully captured dashboard '{name}' to {screenshot_path}")

            except Exception as e:
                error_msg = str(e).split('\n')[0] # Keep error message concise
                self.master.after(0, self.update_dashboard_status_ui, name, f"Failed: {error_msg}")
                logging.error(f"Failed to process dashboard '{name}': {e}", exc_info=False)
            finally:
                if browser:
                    await browser.close()
                if progress_bar:
                    self.master.after(0, progress_bar.step)

    async def _wait_for_splunk_dashboard_to_load(self, page: Page):
        """Intelligently waits for Splunk dashboard panels to fully load."""
        logging.info(f"Waiting for dashboard elements to load...")
        
        # Wait for the main dashboard container
        await page.wait_for_selector("div.dashboard-body, splunk-dashboard-view", timeout=SPLUNK_WAIT_TIMEOUT_MS)
        
        # Check if we need to click a submit button
        submit_button = page.locator('button:has-text("Submit"), button:has-text("Apply")').first
        if await submit_button.is_visible(timeout=5000) and await submit_button.is_enabled(timeout=5000):
            logging.info("Found 'Submit' button, clicking it.")
            await submit_button.click()
            # Wait for the loading to start
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS / 2)
        else:
            logging.debug("No 'Submit' button found or needed.")

        # Wait for panels to appear
        await page.wait_for_selector("div.dashboard-panel, splunk-dashboard-panel", state="visible", timeout=SPLUNK_WAIT_TIMEOUT_MS)

        # Iteratively check that panels are not showing "loading" messages and export buttons are enabled
        loading_indicators = ["Waiting for data", "Loading...", "Searching...", "Loading data", "Rendering"]
        start_wait = time.time()
        iteration = 0
        
        while time.time() - start_wait < (SPLUNK_WAIT_TIMEOUT_MS / 1000):
            iteration += 1
            panels = await page.locator("div.dashboard-panel, splunk-dashboard-panel").all()
            logging.info(f"Checking {len(panels)} panels for loading state (iteration {iteration})")
            
            all_panels_loaded = True
            for i, panel in enumerate(panels):
                # Check for loading text
                panel_text = await panel.inner_text()
                if any(indicator in panel_text for indicator in loading_indicators):
                    logging.info(f"Panel {i+1} has loading text: {panel_text[:50]}...")
                    all_panels_loaded = False
                    continue  # Continue checking other panels
                
                # Check for export button as a sign of readiness
                export_button = panel.locator('button[aria-label*="Export"], a[aria-label*="Export"]').first
                if await export_button.count() > 0:
                    if not await export_button.is_enabled():
                        logging.info(f"Panel {i+1} has export button but it's disabled")
                        all_panels_loaded = False
                        continue
                    else:
                        logging.debug(f"Panel {i+1} export button is enabled")
                else:
                    # Fallback: Check for visual elements that indicate loading
                    loading_spinner = panel.locator('.loading, .spinner, .waiting')
                    if await loading_spinner.count() > 0 and await loading_spinner.is_visible():
                        logging.info(f"Panel {i+1} has loading spinner")
                        all_panels_loaded = False
                        continue
            
            if all_panels_loaded:
                logging.info("All dashboard panels appear to be loaded.")
                # Final wait to ensure everything is rendered
                await asyncio.sleep(3)
                return
            
            # Wait before re-checking
            await asyncio.sleep(2)
        
        # If we get here, timeout occurred
        logging.warning("Timed out waiting for all dashboard panels to finish loading.")
        # Take a screenshot anyway for debugging
        await page.screenshot(path=os.path.join(SCREENSHOT_DIR, f"timeout_{int(time.time())}.png"))
        raise TimeoutError("Timed out waiting for all dashboard panels to finish loading.")

# ------------------------------------------------------------------------------
# Signal & Exit Handling
# ------------------------------------------------------------------------------
def cleanup_and_exit(*_):
    session["username"] = None
    session["password"] = None
    logging.info("Application exiting. Credentials cleared.")
    if app:
        app.master.quit()
        app.master.destroy()
    sys.exit(0)

# ------------------------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)
    
    root = tk.Tk()
    app = SplunkAutomatorApp(root)
    root.protocol("WM_DELETE_WINDOW", cleanup_and_exit)
    root.mainloop()
