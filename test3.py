import os
import sys
import re
import json
import uuid
import asyncio
import signal
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
from threading import Thread

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext
from tkcalendar import DateEntry

from playwright.async_api import async_playwright
from dotenv import load_dotenv
import pytz

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
# Load Secrets
# ------------------------------------------------------------------------------
try:
    if os.path.exists(".secrets"):
        load_dotenv(".secrets")
    else:
        raise FileNotFoundError(".secrets file not found")
except Exception as e:
    temp_root = tk.Tk()
    temp_root.withdraw()
    messagebox.showerror("Secrets Load Error", f"Failed to load .secrets file: {e}")
    sys.exit(1)

# ------------------------------------------------------------------------------
# Global Variables & Session Setup
# ------------------------------------------------------------------------------
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")

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

# For scheduled runs
scheduled = False
schedule_interval = 0  # in seconds

# ------------------------------------------------------------------------------
# Signal & Exit Handling
# ------------------------------------------------------------------------------
def cleanup_and_exit(*_):
    session["username"] = None
    session["password"] = None
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------
def load_dashboards():
    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r") as f:
            session["dashboards"] = json.load(f)

def save_dashboards():
    with open(DASHBOARD_FILE, "w") as f:
        json.dump(session["dashboards"], f, indent=2)

def sanitize_filename(url):
    netloc = urlparse(url).netloc.replace('.', '_')
    uid = uuid.uuid4().hex[:6]
    return f"{netloc}_{uid}"

# ------------------------------------------------------------------------------
# Credential Management
# ------------------------------------------------------------------------------
def manage_credentials():
    new_username = simpledialog.askstring("Manage Credentials", "Enter new username:", 
                                          initialvalue=session.get("username", ""))
    if new_username is not None:
        session["username"] = new_username.strip()
    new_password = simpledialog.askstring("Manage Credentials", "Enter new password:", 
                                          show="*", initialvalue=session.get("password", ""))
    if new_password is not None:
        session["password"] = new_password.strip()
    messagebox.showinfo("Credentials Updated", "Credentials have been updated.")
    logging.info("User updated credentials.")

# ------------------------------------------------------------------------------
# Dashboard Management & Grouping
# ------------------------------------------------------------------------------
def add_dashboard():
    name = simpledialog.askstring("Dashboard Name", "Enter dashboard name:")
    if not name:
        return
    url = simpledialog.askstring("Dashboard URL", "Enter dashboard URL:")
    if not url or not url.startswith("http"):
        return
    group = simpledialog.askstring("Dashboard Group", "Enter dashboard group (optional):")
    if not group:
        group = "Default"
    if any(d["name"].strip() == name.strip() for d in session["dashboards"]):
        messagebox.showerror("Duplicate", "Dashboard name already exists.")
        return
    session["dashboards"].append({"name": name.strip(), "url": url.strip(), "group": group.strip()})
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()

def delete_dashboard():
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showinfo("Delete Dashboard", "Select dashboards to delete.")
        return
    if not messagebox.askyesno("Confirm Delete", "Are you sure to delete selected dashboards?"):
        return
    selected_names = [listbox.get(i) for i in selected_indices]
    session["dashboards"] = [d for d in session["dashboards"] if d["name"] not in selected_names]
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()

def refresh_dashboard_list():
    listbox.delete(0, tk.END)
    selected_filter = group_filter.get() if group_filter else "All"
    for dashboard in session["dashboards"]:
        if selected_filter == "All" or dashboard.get("group", "Default") == selected_filter:
            listbox.insert(tk.END, dashboard["name"])

def update_group_filter():
    groups = {"All"}
    for d in session["dashboards"]:
        groups.add(d.get("group", "Default"))
    group_filter_values = sorted(list(groups))
    group_filter['values'] = group_filter_values
    group_filter.set("All")

# ------------------------------------------------------------------------------
# Advanced Time Range Selection Using EST and Dropdown Options
# ------------------------------------------------------------------------------
def get_time_range():
    """
    Displays a pop-up to choose the time range in EST.
    Users can choose from several relative options or select "Custom Absolute".
    """
    popup = tk.Toplevel(app)
    result = {}
    popup.title("Select Time Range (EST)")
    
    # Dropdown options for relative time selection in EST.
    options = [
        "Last 1 Hour (EST)",
        "Last 4 Hours (EST)",
        "Today (EST)",
        "Yesterday (EST)",
        "Last 7 Days (EST)",
        "Custom Absolute"
    ]
    tk.Label(popup, text="Select Time Range:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    time_option = ttk.Combobox(popup, values=options, state="readonly")
    time_option.current(0)
    time_option.grid(row=0, column=1, padx=5, pady=5)
    
    # Frame for custom absolute selection (hidden by default).
    abs_frame = tk.Frame(popup)
    abs_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
    tk.Label(abs_frame, text="Start Date:").grid(row=0, column=0, sticky="w")
    start_date = DateEntry(abs_frame)
    start_date.grid(row=0, column=1, pady=2)
    tk.Label(abs_frame, text="Start Time (HH:MM):").grid(row=1, column=0, sticky="w")
    start_time = tk.Entry(abs_frame)
    start_time.grid(row=1, column=1, pady=2)
    tk.Label(abs_frame, text="End Date:").grid(row=2, column=0, sticky="w")
    end_date = DateEntry(abs_frame)
    end_date.grid(row=2, column=1, pady=2)
    tk.Label(abs_frame, text="End Time (HH:MM):").grid(row=3, column=0, sticky="w")
    end_time = tk.Entry(abs_frame)
    end_time.grid(row=3, column=1, pady=2)
    abs_frame.grid_remove()
    
    def toggle_abs_frame(event):
        if time_option.get() == "Custom Absolute":
            abs_frame.grid()
        else:
            abs_frame.grid_remove()
    
    time_option.bind("<<ComboboxSelected>>", toggle_abs_frame)
    
    def submit():
        try:
            now_est = datetime.now(est)
            selection = time_option.get()
            if selection == "Last 1 Hour (EST)":
                start = (now_est - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
                end = now_est.strftime("%Y-%m-%d %H:%M")
            elif selection == "Last 4 Hours (EST)":
                start = (now_est - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M")
                end = now_est.strftime("%Y-%m-%d %H:%M")
            elif selection == "Today (EST)":
                start = now_est.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")
                end = now_est.strftime("%Y-%m-%d %H:%M")
            elif selection == "Yesterday (EST)":
                yesterday = now_est - timedelta(days=1)
                start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M")
                end = yesterday.replace(hour=23, minute=59, second=59, microsecond=0).strftime("%Y-%m-%d %H:%M")
            elif selection == "Last 7 Days (EST)":
                start = (now_est - timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
                end = now_est.strftime("%Y-%m-%d %H:%M")
            elif selection == "Custom Absolute":
                s_time = start_time.get().strip()
                e_time = end_time.get().strip()
                if not re.match(r"^\d{2}:\d{2}$", s_time) or not re.match(r"^\d{2}:\d{2}$", e_time):
                    raise ValueError("Time must be in HH:MM format.")
                start_str = f"{start_date.get_date():%Y-%m-%d} {s_time}"
                end_str = f"{end_date.get_date():%Y-%m-%d} {e_time}"
                start_dt = datetime.strptime(start_str, "%Y-%m-%d %H:%M")
                end_dt = datetime.strptime(end_str, "%Y-%m-%d %H:%M")
                if end_dt <= start_dt:
                    raise ValueError("End time must be after start time.")
                start = start_str
                end = end_str
            else:
                raise ValueError("Invalid selection")
            result["start"] = start
            result["end"] = end
            popup.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", str(e))
    
    tk.Button(popup, text="Submit", command=submit).grid(row=2, column=0, columnspan=2, pady=10)
    popup.grab_set()
    popup.wait_window()
    return result.get("start"), result.get("end")

# ------------------------------------------------------------------------------
# Scheduled Analysis Functionality
# ------------------------------------------------------------------------------
def schedule_analysis():
    interval_str = simpledialog.askstring("Schedule Analysis", 
                                            "Enter interval in seconds for repeated analysis:")
    try:
        interval = int(interval_str)
        if interval <= 0:
            raise ValueError
    except Exception:
        messagebox.showerror("Invalid Interval", "Please enter a valid positive integer for seconds.")
        return
    global scheduled, schedule_interval
    scheduled = True
    schedule_interval = interval
    messagebox.showinfo("Scheduled", f"Analysis scheduled every {interval} seconds.")
    logging.info("Scheduled analysis every %s seconds", interval)
    run_scheduled_analysis()

def run_scheduled_analysis():
    if not scheduled:
        return
    analyze_selected()  # trigger analysis (non-blocking)
    app.after(schedule_interval * 1000, run_scheduled_analysis)

def cancel_scheduled_analysis():
    global scheduled
    scheduled = False
    messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled.")
    logging.info("Scheduled analysis cancelled.")

# ------------------------------------------------------------------------------
# Dashboard Analysis & Progress Tracking
# ------------------------------------------------------------------------------
def analyze_selected():
    selected_names = [listbox.get(i) for i in listbox.curselection()]
    if not selected_names:
        messagebox.showwarning("Analyze Dashboards", "Select at least one dashboard.")
        return
    if not session["username"] or not session["password"]:
        messagebox.showerror("Credentials Missing", 
                             "Please set valid credentials in .secrets or update via Settings.")
        return
    start, end = get_time_range()
    if not start or not end:
        return
    # Collect URLs from selected dashboards.
    selected_urls = [d["url"] for d in session["dashboards"] if d["name"] in selected_names]
    progress_bar['maximum'] = len(selected_urls)
    progress_bar['value'] = 0
    Thread(target=lambda: asyncio.run(analyze_dashboards(selected_urls, start, end)),
           daemon=True).start()

async def analyze_dashboards(urls, start, end):
    results = []
    completed = 0
    tasks = [visit_dashboard(url, start, end) for url in urls]
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        completed += 1
        app.after(0, lambda c=completed: progress_bar.config(value=c))
    app.after(0, lambda: show_results(results, start, end))

async def visit_dashboard(url, start, end):
    """
    Visits the dashboard and waits until the dashboard panels
    (assumed to be <div class="dashboard-panel"> elements) are loaded.
    In particular, the function waits until each panel has a nonzero height
    and its content no longer includes “Waiting for input”.
    """
    retries = 3
    for attempt in range(1, retries + 1):
        try:
            playwright = await async_playwright().start()
            try:
                browser = await p.chromium.launch(headless=False,executable_path="C:\Program Files\Google\Chrome\Application\chrome.exe")
                try:
                    context = await browser.new_context()
                    try:
                        page = await context.new_page()
                        await page.goto(url, wait_until="networkidle")
                        
                        # Wait for panels to appear.
                        #await page.wait_for_selector("div.dashboard-panel", timeout=30000)
                        await self._wait_for_dashboard_load_async(page, wait_timeout)
                        # Wait until each panel is rendered (nonzero height) and does NOT include "Waiting for input"
                        await page.wait_for_function(
                            """() => {
                                const panels = document.querySelectorAll("div.dashboard-panel");
                                return Array.from(panels).every(panel => 
                                    panel.offsetHeight > 0 && !panel.innerText.includes("Waiting for input"));
                            }""",
                            timeout=30000
                        )

                        # In case a login is required.
                        if await page.query_selector('input[placeholder="Username"]'):
                            if not session["username"] or not session["password"]:
                                raise RuntimeError("Login required but credentials not set.")
                            await page.fill('input[placeholder="Username"]', session["username"])
                            await page.fill('input[placeholder="Password"]', session["password"])
                            await page.press('input[placeholder="Password"]', "Enter")
                            await page.wait_for_load_state("networkidle")
                            # Wait again for panels to load after login.
                            await page.wait_for_selector("div.dashboard-panel", timeout=30000)
                            await page.wait_for_function(
                                """() => {
                                    const panels = document.querySelectorAll("div.dashboard-panel");
                                    return Array.from(panels).every(panel => 
                                        panel.offsetHeight > 0 && !panel.innerText.includes("Waiting for input"));
                                }""",
                                timeout=30000
                            )
                        
                        safe = sanitize_filename(url)
                        # Use EST time for the screenshot stamp.
                        stamp = datetime.now(est).strftime("%Y%m%d_%H%M%S")
                        screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe}_{stamp}.png")
                        await page.screenshot(path=screenshot_path, full_page=True)
                        return f"✅ {url} ({start} to {end}): Screenshot -> {screenshot_path}"
                    finally:
                        await context.close()
                finally:
                    await browser.close()
            finally:
                await playwright.stop()
        except Exception as e:
            logging.error(f"Attempt {attempt} failed for {url}: {e}")
            if attempt == retries:
                return f"❌ {url}: {e}"
            await asyncio.sleep(2)

def show_results(messages, start, end):
    win = tk.Toplevel(app)
    win.title("Analysis Summary")
    out = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=80, height=25)
    out.pack(expand=True, fill='both')
    for msg in messages:
        out.insert(tk.END, msg + "\n\n")
    out.config(state=tk.DISABLED)

    def export_report():
        report_filename = f"report_{datetime.now(est).strftime('%Y%m%d_%H%M%S')}.html"
        try:
            with open(report_filename, "w") as f:
                f.write("<html><head><title>Dashboard Analysis Report</title></head><body>")
                f.write(f"<h2>Dashboard Analysis Report</h2>")
                f.write(f"<p>Time Range: {start} to {end}</p>")
                f.write("<ul>")
                for msg in messages:
                    f.write(f"<li>{msg}</li>")
                f.write("</ul></body></html>")
            messagebox.showinfo("Report Exported", f"Report saved as {report_filename}")
            logging.info("Report exported to %s", report_filename)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {e}")

    tk.Button(win, text="Export Report to HTML", command=export_report).pack(pady=10)

# ------------------------------------------------------------------------------
# Main Application UI Setup
# ------------------------------------------------------------------------------
app = tk.Tk()
app.title("Splunk Dashboard Desktop Client")
app.geometry("800x600")

# Menu for Settings.
menu_bar = tk.Menu(app)
settings_menu = tk.Menu(menu_bar, tearoff=0)
settings_menu.add_command(label="Manage Credentials", command=manage_credentials)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
app.config(menu=menu_bar)

# Control frame (buttons and group filter).
control_frame = tk.Frame(app)
control_frame.pack(pady=10)

tk.Button(control_frame, text="Add Dashboard", command=add_dashboard).grid(row=0, column=0, padx=5)
tk.Button(control_frame, text="Delete Dashboard", command=delete_dashboard).grid(row=0, column=1, padx=5)
tk.Button(control_frame, text="Analyze Selected", command=analyze_selected).grid(row=0, column=2, padx=5)
tk.Button(control_frame, text="Schedule Analysis", command=schedule_analysis).grid(row=0, column=3, padx=5)
tk.Button(control_frame, text="Cancel Scheduled Analysis", command=cancel_scheduled_analysis).grid(row=0, column=4, padx=5)

# Group filter for dashboards.
tk.Label(control_frame, text="Filter by Group:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
group_filter = ttk.Combobox(control_frame, state="readonly")
group_filter.grid(row=1, column=1, padx=5, pady=5)
group_filter.bind("<<ComboboxSelected>>", lambda e: refresh_dashboard_list())
update_group_filter()

# Dashboard list.
tk.Label(app, text="Saved Dashboards:").pack()
listbox = tk.Listbox(app, selectmode=tk.MULTIPLE, width=80, height=15)
listbox.pack(pady=10)

# Progress bar for analysis.
progress_bar = ttk.Progressbar(app, orient="horizontal", mode="determinate", length=400)
progress_bar.pack(pady=10)

load_dashboards()
refresh_dashboard_list()
app.mainloop()
