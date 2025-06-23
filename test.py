import os
import sys
import re
import json
import uuid
import asyncio
import signal
import logging
from playwright.async_api import Page
from threading import Thread
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple

# Third-party libraries
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext
from tkcalendar import DateEntry
from playwright.async_api import async_playwright, Playwright, Browser, Page
from dotenv import load_dotenv

# --- Constants ---
SECRETS_FILE = ".secrets"
DASHBOARD_FILE = "dashboards.json"
LOG_FILE = "dashboard_analysis.log"
SCREENSHOT_DIR_BASE = "screenshots"

# CSS Selectors for login (centralized for easy updates)
USERNAME_SELECTOR = 'input[placeholder="Username"]'
PASSWORD_SELECTOR = 'input[placeholder="Password"]'

# Splunk Panel Selectors and Readiness Check
PANEL_SELECTOR = "div.dashboard-panel"
PANEL_LOADING_INDICATOR_SELECTOR = ".panel-loading"
PANEL_READY_CONDITION = '''
() => {
    const panels = document.querySelectorAll("div.dashboard-panel");
    if (!panels.length) return false;
    return Array.from(panels).every(panel => {
        return !panel.querySelector(".splunk-spinner, .loading, .panel-loading, .dashboard-element-loading");
    });
}
'''

# --- Logging Setup ---
def setup_logging():
    """Configures logging to file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )


# --- Utility Functions ---
def sanitize_filename(url: str) -> str:
    """Creates a safe filename from a URL."""
    netloc = urlparse(url).netloc.replace('.', '_')
    uid = uuid.uuid4().hex[:6]
    return f"{netloc}_{uid}"

def update_secrets_file(key: str, value: str):
    """Updates a key-value pair in the .secrets file."""
    if not os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, "w") as f:
            f.write(f"{key}={value}\n")
        return

    with open(SECRETS_FILE, "r") as f:
        lines = f.readlines()

    key_found = False
    with open(SECRETS_FILE, "w") as f:
        for line in lines:
            if line.strip().startswith(f"{key}="):
                f.write(f'{key}="{value}"\n')
                key_found = True
            else:
                f.write(line)
        if not key_found:
            f.write(f'{key}="{value}"\n')


class SplunkAutomator:
    """Handles all Playwright browser automation tasks."""

    def __init__(self, credentials: Dict[str, str]):
        self.username = credentials.get("username")
        self.password = credentials.get("password")
        self.screenshot_dir = os.path.join(SCREENSHOT_DIR_BASE, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        os.makedirs(self.screenshot_dir, exist_ok=True)

    async def _login_if_required(self, page: Page):
        """Logs into Splunk if the login form is present."""
        try:
            # Use a short timeout to quickly check for the login form
            username_input = await page.wait_for_selector(USERNAME_SELECTOR, timeout=3000)
            if username_input:
                logging.info(f"Login page detected for {page.url}.")
                if not self.username or not self.password:
                    raise ValueError("Login required, but credentials are not set.")
                await page.fill(USERNAME_SELECTOR, self.username)
                await page.fill(PASSWORD_SELECTOR, self.password)
                await page.press(PASSWORD_SELECTOR, "Enter")
                await page.wait_for_load_state("networkidle", timeout=60000)
                logging.info("Login successful.")
        except (asyncio.TimeoutError, ValueError):
            # This is not an error, it just means we're likely already logged in.
            logging.info("No login form detected or already logged in.")
        except Exception as e:
            logging.error(f"An unexpected error occurred during login attempt: {e}")
            raise # Re-raise the exception to be caught by the calling function
    
    async def _wait_for_panels_to_load(self, page: Page):
        """
        Waits for all dashboard panels to finish loading.
        Optimized using Splunk panel structure references.
        """
        logging.info("Waiting for all dashboard panels to finish loading...")
        try:
            await page.wait_for_function(PANEL_READY_CONDITION, timeout=300000)
            logging.info("All panels have loaded.")
        except asyncio.TimeoutError:
            logging.warning(f"Timeout exceeded while waiting for panels to load on {page.url}.")
        except Exception as e:
            logging.error(f"Error waiting for panels: {type(e).__name__}: {e}")


    async def visit_dashboard(self, browser: Browser, url: str, time_range: Tuple[str, str]) -> str:
        """Navigates to a single dashboard, logs in, and takes a screenshot."""
        start_str, end_str = time_range
        page = None
        try:
            context = await browser.new_context()
            page = await context.new_page()
            
            # Construct URL with time range if applicable (modify this as per your dashboard's URL structure)
            # This is an example for Splunk: &earliest=...&latest=...
            timed_url = f"{url}?earliest={start_str}&latest={end_str}"
            
            await page.goto(timed_url, wait_until="networkidle", timeout=90000)
            await self._login_if_required(page)

            # Wait for dashboard to render after potential login and redirects
            await page.wait_for_timeout(5000)

            safe_name = sanitize_filename(url)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            screenshot_path = os.path.join(self.screenshot_dir, f"screenshot_{safe_name}_{timestamp}.png")
            
            await page.screenshot(path=screenshot_path, full_page=True)
            return f"✅ Success for {url}\n   Screenshot -> {os.path.abspath(screenshot_path)}"
        
        except Exception as e:
            logging.error(f"Failed to process {url}: {e}")
            return f"❌ Failure for {url}\n   Reason: {e}"
        finally:
            if page:
                await page.close()

    async def run_analysis(self, urls: List[str], time_range: Tuple[str, str], progress_callback) -> List[str]:
        """
        Orchestrates the analysis of multiple dashboards.
        FIX: Launches one browser for all tasks for efficiency.
        """
        results = []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True,executable_path="C:\Program Files\Google\Chrome\Application\chrome.exe")
            try:
                for i, url in enumerate(urls):
                    result = await self.visit_dashboard(browser, url, time_range)
                    results.append(result)
                    progress_callback(i + 1)
            finally:
                await browser.close()
        return results


class SplunkApp:
    """Main Tkinter GUI Application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Splunk Dashboard Desktop Client")
        self.root.geometry("850x650")
        
        self.session = {"username": os.getenv("SPLUNK_USERNAME"), "password": os.getenv("SPLUNK_PASSWORD")}
        self.dashboards = self._load_dashboards()
        self.is_schedule_running = False

        self._setup_ui()
        self._load_ui_data()

        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        signal.signal(signal.SIGINT, self._on_closing)
        signal.signal(signal.SIGTERM, self._on_closing)

    def _setup_ui(self):
        """Initializes all GUI components."""
        # --- Menu ---
        menu_bar = tk.Menu(self.root)
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Manage Credentials", command=self._manage_credentials)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        self.root.config(menu=menu_bar)

        # --- Control Frame ---
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill='x')

        ttk.Button(control_frame, text="Add Dashboard", command=self._add_dashboard).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Delete Dashboard", command=self._delete_dashboard).pack(side='left', padx=5)
        self.analyze_btn = ttk.Button(control_frame, text="Analyze Selected", command=self._analyze_selected)
        self.analyze_btn.pack(side='left', padx=5)
        
        # --- Scheduling Frame ---
        schedule_frame = ttk.LabelFrame(self.root, text="Scheduling", padding="10")
        schedule_frame.pack(fill='x', padx=10, pady=5)
        
        self.schedule_btn = ttk.Button(schedule_frame, text="Start Scheduled Analysis", command=self._schedule_analysis)
        self.schedule_btn.pack(side='left', padx=5)
        self.cancel_schedule_btn = ttk.Button(schedule_frame, text="Cancel Scheduled Analysis", command=self._cancel_scheduled_analysis, state=tk.DISABLED)
        self.cancel_schedule_btn.pack(side='left', padx=5)
        
        # --- Dashboard List Frame ---
        list_frame = ttk.Frame(self.root, padding="10")
        list_frame.pack(fill='both', expand=True)
        
        # Group filter
        ttk.Label(list_frame, text="Filter by Group:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.group_filter_var = tk.StringVar()
        self.group_filter = ttk.Combobox(list_frame, textvariable=self.group_filter_var, state="readonly", width=30)
        self.group_filter.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.group_filter.bind("<<ComboboxSelected>>", lambda e: self._refresh_dashboard_list())

        # Listbox
        ttk.Label(list_frame, text="Saved Dashboards:").grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=(10,0))
        self.listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE, width=100, height=15)
        self.listbox.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox['yscrollcommand'] = scrollbar.set
        scrollbar.grid(row=2, column=2, sticky='ns')

        list_frame.grid_rowconfigure(2, weight=1)
        list_frame.grid_columnconfigure(1, weight=1)

        # --- Progress Bar ---
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", length=400)
        self.progress_bar.pack(pady=10, padx=10, fill='x')

    def _load_ui_data(self):
        """Loads dashboards into the UI after setup."""
        self._update_group_filter()
        self._refresh_dashboard_list()

    # --- Data Persistence ---
    def _load_dashboards(self) -> List[Dict]:
        """Loads dashboards from DASHBOARD_FILE."""
        if os.path.exists(DASHBOARD_FILE):
            try:
                with open(DASHBOARD_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Load Error", f"Could not decode {DASHBOARD_FILE}. Starting fresh.")
                return []
        return []

    def _save_dashboards(self):
        """Saves dashboards to DASHBOARD_FILE."""
        with open(DASHBOARD_FILE, "w") as f:
            json.dump(self.dashboards, f, indent=4)

    # --- Credential Management ---
    def _manage_credentials(self):
        """Dialog to update and save credentials."""
        new_username = simpledialog.askstring(
            "Manage Credentials", "Enter new username:",
            initialvalue=self.session.get("username", "")
        )
        if new_username is not None:
            self.session["username"] = new_username.strip()
            update_secrets_file("SPLUNK_USERNAME", self.session["username"])

        new_password = simpledialog.askstring(
            "Manage Credentials", "Enter new password:",
            show="*", initialvalue=self.session.get("password", "")
        )
        if new_password is not None:
            self.session["password"] = new_password.strip()
            update_secrets_file("SPLUNK_PASSWORD", self.session["password"])

        messagebox.showinfo("Credentials Updated", "Credentials have been updated and saved to .secrets file.")
        logging.info("User updated credentials.")

    # --- Dashboard & UI Management ---
    def _add_dashboard(self):
        name = simpledialog.askstring("Dashboard Name", "Enter dashboard name:")
        if not name: return
        url = simpledialog.askstring("Dashboard URL", "Enter dashboard URL:")
        if not url or not url.startswith("http"): return
        group = simpledialog.askstring("Dashboard Group", "Enter dashboard group (optional):", initialvalue="Default")
        if not group: group = "Default"
        
        if any(d["name"].strip().lower() == name.strip().lower() for d in self.dashboards):
            messagebox.showerror("Duplicate", "Dashboard name already exists.")
            return

        self.dashboards.append({"name": name.strip(), "url": url.strip(), "group": group.strip()})
        self._save_dashboards()
        self._update_group_filter()
        self._refresh_dashboard_list()

    def _delete_dashboard(self):
        selected_indices = self.listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Delete", "Please select one or more dashboards to delete.")
            return
        
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected dashboard(s)?"):
            return

        selected_names = {self.listbox.get(i) for i in selected_indices}
        self.dashboards = [d for d in self.dashboards if d["name"] not in selected_names]
        
        self._save_dashboards()
        self._update_group_filter()
        self._refresh_dashboard_list()

    def _refresh_dashboard_list(self):
        """Repopulates the listbox based on the current group filter."""
        self.listbox.delete(0, tk.END)
        selected_filter = self.group_filter_var.get()
        
        display_dashboards = sorted(self.dashboards, key=lambda d: d['name'])

        for dashboard in display_dashboards:
            if selected_filter == "All" or dashboard.get("group", "Default") == selected_filter:
                self.listbox.insert(tk.END, dashboard["name"])

    def _update_group_filter(self):
        """Updates the values in the group filter combobox."""
        groups = {"All"}
        for d in self.dashboards:
            groups.add(d.get("group", "Default"))
        
        current_selection = self.group_filter_var.get()
        self.group_filter['values'] = sorted(list(groups))
        
        if current_selection in groups:
            self.group_filter_var.set(current_selection)
        else:
            self.group_filter_var.set("All")

    # --- Analysis Logic ---
    def _analyze_selected(self, time_range_override: Optional[Tuple[str, str]] = None):
        """Initiates the analysis process for selected dashboards."""
        selected_names = [self.listbox.get(i) for i in self.listbox.curselection()]
        if not selected_names:
            messagebox.showwarning("Analyze Dashboards", "Please select at least one dashboard to analyze.")
            return

        if not self.session.get("username") or not self.session.get("password"):
            messagebox.showerror("Credentials Missing", "Please set valid credentials via Settings -> Manage Credentials.")
            return
        
        time_range = time_range_override or self._get_time_range()
        if not all(time_range):
            return # User cancelled the time range dialog

        urls_to_analyze = [d["url"] for d in self.dashboards if d["name"] in selected_names]
        
        self.progress_bar['maximum'] = len(urls_to_analyze)
        self.progress_bar['value'] = 0
        self.analyze_btn.config(state=tk.DISABLED)

        # Run automation in a separate thread to not block the GUI
        analysis_thread = Thread(
            target=self._run_analysis_thread,
            args=(urls_to_analyze, time_range),
            daemon=True
        )
        analysis_thread.start()

    def _run_analysis_thread(self, urls: List[str], time_range: Tuple[str, str]):
        """The function that runs in the background thread."""
        logging.info(f"Starting analysis for {len(urls)} dashboards.")
        
        automator = SplunkAutomator(self.session)
        
        def progress_callback(completed_count):
            self.root.after(0, lambda: self.progress_bar.config(value=completed_count))

        results = asyncio.run(automator.run_analysis(urls, time_range, progress_callback))
        
        logging.info("Analysis finished.")
        # Schedule the results display and UI reset back on the main thread
        self.root.after(0, lambda: self._on_analysis_complete(results, time_range))

    def _on_analysis_complete(self, results: List[str], time_range: Tuple[str, str]):
        """Actions to take on the main thread after analysis is done."""
        self.analyze_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self._show_results(results, time_range)

    # --- Time Range Dialog ---
    def _get_time_range(self) -> Optional[Tuple[str, str]]:
        # This function is complex and mostly UI logic, so major refactoring is not
        # essential, but it could be turned into its own Toplevel subclass for cleanliness.
        # The existing logic is kept but could be improved.
        # For simplicity, I'll keep it as is. The original logic works.
        popup = tk.Toplevel(self.root)
        result = {}
        popup.title("Choose Time Range")
    
        # Mode selection
        tk.Label(popup, text="Time Range Mode:").grid(row=0, column=0, padx=5, pady=5)
        mode_var = tk.StringVar(value="Custom")
        mode_combo = ttk.Combobox(popup, textvariable=mode_var, values=["Custom", "Last 1 hour", "Last 24 hours", "Last 7 days"], state="readonly")
        mode_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Frame for custom mode entries
        custom_frame = tk.Frame(popup)
        custom_frame.grid(row=1, column=0, columnspan=2)
        
        tk.Label(custom_frame, text="Start Date:").grid(row=0, column=0, padx=5, pady=5)
        start_date = DateEntry(custom_frame, date_pattern='yyyy-mm-dd')
        start_date.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(custom_frame, text="End Date:").grid(row=2, column=0, padx=5, pady=5)
        end_date = DateEntry(custom_frame, date_pattern='yyyy-mm-dd')
        end_date.grid(row=2, column=1, padx=5, pady=5)
        
        def submit():
            try:
                if mode_var.get() != "Custom":
                    now = datetime.now()
                    delta_map = {"Last 1 hour": timedelta(hours=1), "Last 24 hours": timedelta(days=1), "Last 7 days": timedelta(days=7)}
                    start_dt = now - delta_map[mode_var.get()]
                    end_dt = now
                    # Format for Splunk's earliest/latest
                    result["start"] = start_dt.strftime("%m/%d/%Y:%H:%M:%S")
                    result["end"] = end_dt.strftime("%m/%d/%Y:%H:%M:%S")
                else:
                    start_str = f"{start_date.get_date():%m/%d/%Y}:00:00:00"
                    end_str = f"{end_date.get_date():%m/%d/%Y}:23:59:59"
                    if datetime.strptime(end_str, "%m/%d/%Y:%H:%M:%S") <= datetime.strptime(start_str, "%m/%d/%Y:%H:%M:%S"):
                        raise ValueError("End date must be after start date.")
                    result["start"] = start_str
                    result["end"] = end_str
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Invalid Input", str(e), parent=popup)
        
        tk.Button(popup, text="Submit", command=submit).grid(row=2, column=0, columnspan=2, pady=10)
        
        popup.transient(self.root)
        popup.grab_set()
        self.root.wait_window(popup)
        return result.get("start"), result.get("end")

    # --- Scheduling ---
    def _schedule_analysis(self):
        interval_str = simpledialog.askstring("Schedule Analysis", "Enter interval in seconds for repeated analysis:", parent=self.root)
        try:
            self.schedule_interval = int(interval_str)
            if self.schedule_interval <= 10: # Enforce a minimum
                raise ValueError("Interval must be greater than 10 seconds.")
        except (ValueError, TypeError):
            messagebox.showerror("Invalid Interval", "Please enter a valid integer greater than 10.")
            return

        self.is_schedule_running = True
        self.schedule_btn.config(state=tk.DISABLED)
        self.cancel_schedule_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Scheduled", f"Analysis scheduled every {self.schedule_interval} seconds.")
        logging.info(f"Scheduled analysis to run every {self.schedule_interval} seconds.")
        self._run_scheduled_task()

    def _run_scheduled_task(self):
        if not self.is_schedule_running:
            return
        
        logging.info("Triggering scheduled analysis run...")
        # Automatically use a relative time for scheduled runs, e.g., last hour
        time_range = ((datetime.now() - timedelta(hours=1)).strftime("%m/%d/%Y:%H:%M:%S"), datetime.now().strftime("%m/%d/%Y:%H:%M:%S"))
        self._analyze_selected(time_range_override=time_range)
        
        # Schedule the next run
        self.root.after(self.schedule_interval * 1000, self._run_scheduled_task)

    def _cancel_scheduled_analysis(self):
        self.is_schedule_running = False
        self.schedule_btn.config(state=tk.NORMAL)
        self.cancel_schedule_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled.")
        logging.info("Scheduled analysis cancelled by user.")

    # --- Results and Reporting ---
    def _show_results(self, messages: List[str], time_range: Tuple[str, str]):
        win = tk.Toplevel(self.root)
        win.title("Analysis Summary")
        win.geometry("800x600")

        out = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=100, height=30)
        out.pack(expand=True, fill='both', padx=10, pady=5)
        
        for msg in messages:
            out.insert(tk.END, msg + "\n\n")
        out.config(state=tk.DISABLED)

        # Export button
        export_btn = ttk.Button(win, text="Export Report to HTML", command=lambda: self._export_report(messages, time_range))
        export_btn.pack(pady=10)

    def _export_report(self, messages: List[str], time_range: Tuple[str, str]):
        report_filename = f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            with open(report_filename, "w", encoding='utf-8') as f:
                f.write("<!DOCTYPE html><html lang='en'><head><title>Dashboard Analysis Report</title>")
                f.write("<style>body { font-family: sans-serif; line-height: 1.6; } li { margin-bottom: 1em; } </style>")
                f.write("</head><body>")
                f.write("<h1>Dashboard Analysis Report</h1>")
                f.write(f"<p><b>Time Range:</b> {time_range[0]} to {time_range[1]}</p>")
                f.write("<ul>")
                for msg in messages:
                    # Sanitize message for HTML
                    safe_msg = msg.replace("\n", "<br>")
                    f.write(f"<li>{safe_msg}</li>")
                f.write("</ul></body></html>")
            messagebox.showinfo("Report Exported", f"Report saved as {report_filename}")
            logging.info(f"Report exported to {report_filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {e}")
            logging.error(f"Failed to export report: {e}")

    # --- Application Lifecycle ---
    def _on_closing(self, *args):
        """Handle cleanup on application exit."""
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            logging.info("Application shutting down.")
            self.root.destroy()
            # Clear sensitive info from memory
            self.session.clear()


if __name__ == "__main__":
    setup_logging()

    # Load secrets from .env file
    try:
        if not os.path.exists(SECRETS_FILE):
            raise FileNotFoundError(f"{SECRETS_FILE} not found. Please create it with SPLUNK_USERNAME and SPLUNK_PASSWORD.")
        load_dotenv(SECRETS_FILE)
    except Exception as e:
        logging.critical(f"Failed to load secrets: {e}")
        # Use a temporary root to show the error if the main app fails to start
        temp_root = tk.Tk()
        temp_root.withdraw()
        messagebox.showerror("Secrets Load Error", f"Failed to load {SECRETS_FILE} file: {e}")
        sys.exit(1)

    root = tk.Tk()
    app = SplunkApp(root)
    root.mainloop()
