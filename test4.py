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

from playwright.async_api import async_playwright, Playwright, BrowserContext, Page
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
        # If .secrets not found, prompt for credentials on first analysis attempt
        logging.warning(".secrets file not found. Credentials will be prompted for and session-cached.")
except Exception as e:
    temp_root = tk.Tk()
    temp_root.withdraw()
    messagebox.showerror("Secrets Load Error", f"Failed to load .secrets file: {e}")
    # Do not exit, allow user to set credentials via UI

# ------------------------------------------------------------------------------
# Global Variables & Session Setup
# ------------------------------------------------------------------------------
# Credentials are not loaded from .env at startup if .secrets is missing,
# but can be set via the UI and stored in session cache.
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

# Global variables for UI elements, initialized to None.
# These will be assigned their actual Tkinter objects later in the script.
app = None
progress_bar = None
treeview = None
group_filter = None

# For scheduled runs - Declare global variables
scheduled = False
schedule_interval = 0  # in seconds

# Define a default wait timeout for Splunk operations
SPLUNK_WAIT_TIMEOUT_MS = 120000 # Increased to 120 seconds for more robustness

# Concurrency limit for Playwright browsers
CONCURRENT_BROWSERS_LIMIT = 3 # Adjust this based on your system resources and Splunk server capacity

# Semaphore to control concurrency
browser_semaphore = asyncio.Semaphore(CONCURRENT_BROWSERS_LIMIT)

# ------------------------------------------------------------------------------
# Signal & Exit Handling
# ------------------------------------------------------------------------------
def cleanup_and_exit(*_):
    # Clear session credentials on exit for security
    session["username"] = None
    session["password"] = None
    logging.info("Application exiting. Credentials cleared.")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------
def load_dashboards():
    if os.path.exists(DASHBOARD_FILE):
        try:
            with open(DASHBOARD_FILE, "r") as f:
                loaded_dashboards = json.load(f)
                # Ensure "selected" key exists and initialize status
                for dashboard in loaded_dashboards:
                    if "selected" not in dashboard:
                        dashboard["selected"] = False
                    dashboard["status"] = "Pending" # Initialize status
                session["dashboards"] = loaded_dashboards
            logging.info(f"Loaded {len(session['dashboards'])} dashboards from {DASHBOARD_FILE}")
        except json.JSONDecodeError as e:
            messagebox.showerror("Load Error", f"Error reading {DASHBOARD_FILE}: {e}. File might be corrupted.")
            session["dashboards"] = [] # Reset dashboards if file is corrupted
        except Exception as e:
            messagebox.showerror("Load Error", f"An unexpected error occurred while loading {DASHBOARD_FILE}: {e}")
            session["dashboards"] = []
    else:
        logging.info(f"{DASHBOARD_FILE} not found. Starting with an empty dashboard list.")


def save_dashboards():
    with open(DASHBOARD_FILE, "w") as f:
        # Do not save the 'status' key, as it's transient
        dashboards_to_save = [{k: v for k, v in d.items() if k != 'status'} for d in session["dashboards"]]
        json.dump(dashboards_to_save, f, indent=2)
    logging.info(f"Saved {len(session['dashboards'])} dashboards to {DASHBOARD_FILE}")

def sanitize_filename(url):
    # Get hostname and path relevant parts
    parsed_url = urlparse(url)
    netloc_sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', parsed_url.netloc) # Allow dots for domain parts
    path_sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', parsed_url.path)
    
    # Trim path to prevent excessively long filenames, taking last few segments
    path_segments = [s for s in path_sanitized.split('_') if s]
    if len(path_segments) > 3:
        path_segments = path_segments[-3:] # Take last 3 segments
    short_path = '_'.join(path_segments)

    uid = uuid.uuid4().hex[:6] # Unique identifier for collision avoidance
    
    # Combine components. Keep it concise.
    filename_parts = [netloc_sanitized]
    if short_path:
        filename_parts.append(short_path)
    filename_parts.append(uid)

    final_filename = '_'.join(filename_parts)
    return final_filename[:200] # Trim overall length to be safe for file systems


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
    messagebox.showinfo("Credentials Updated", "Credentials have been updated for this session.")
    logging.info("User updated credentials for current session.")

# ------------------------------------------------------------------------------
# Dashboard Management & Grouping with Checkboxes
# ------------------------------------------------------------------------------
def add_dashboard():
    name = simpledialog.askstring("Dashboard Name", "Enter dashboard name:")
    if not name:
        return
    url = simpledialog.askstring("Dashboard URL", "Enter dashboard URL:")
    if not url or not url.startswith("http"):
        messagebox.showerror("Invalid URL", "Dashboard URL must start with http or https.")
        return
    group = simpledialog.askstring("Dashboard Group", "Enter dashboard group (optional):")
    if not group:
        group = "Default"
    if any(d["name"].strip().lower() == name.strip().lower() for d in session["dashboards"]):
        messagebox.showerror("Duplicate", "Dashboard name already exists (case-insensitive).")
        return
    session["dashboards"].append({"name": name.strip(), "url": url.strip(), "group": group.strip(), "selected": False, "status": "Pending"})
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()
    logging.info(f"Added dashboard: {name} (URL: {url}, Group: {group})")

def delete_dashboard():
    # Added check to ensure treeview is initialized before use
    if treeview is None:
        messagebox.showerror("Error", "UI not fully initialized. Please restart the application.")
        return
    selected_items_ids = treeview.selection()
    if not selected_items_ids:
        messagebox.showinfo("Delete Dashboard", "Select dashboards to delete.")
        return
    if not messagebox.askyesno("Confirm Delete", "Are you sure to delete selected dashboards?"):
        return
    
    names_to_delete = []
    indices_to_delete = sorted([int(item_id) for item_id in selected_items_ids], reverse=True)

    for idx in indices_to_delete:
        if 0 <= idx < len(session["dashboards"]):
            names_to_delete.append(session["dashboards"][idx]["name"])
            del session["dashboards"][idx]
    
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()
    logging.info(f"Deleted dashboards: {', '.join(names_to_delete)}")


def refresh_dashboard_list():
    # Added check to ensure treeview is initialized before use
    if treeview is None:
        logging.error("refresh_dashboard_list called before treeview is initialized.")
        return
    
    for i in treeview.get_children():
        treeview.delete(i)
    
    selected_filter = group_filter.get() if group_filter else "All"
    for idx, dashboard in enumerate(session["dashboards"]):
        group_name = dashboard.get("group", "Default")
        if selected_filter == "All" or group_name == selected_filter:
            checkbox_state = "☑" if dashboard.get("selected", False) else "☐"
            status = dashboard.get("status", "Pending")
            treeview.insert("", "end", iid=str(idx), 
                            values=(checkbox_state, dashboard["name"], dashboard["url"], group_name, status))

def toggle_selection(event):
    if treeview is None: # Safety check
        return
    item_id = treeview.identify_row(event.y)
    if not item_id:
        return
    
    column = treeview.identify_column(event.x)
    if column == "#1": # Check if the click was on the first column (checkbox column)
        # Get the index of the dashboard from the iid
        dashboard_idx = int(item_id)
        if 0 <= dashboard_idx < len(session["dashboards"]):
            dashboard = session["dashboards"][dashboard_idx]
            dashboard["selected"] = not dashboard.get("selected", False)
            # Update the checkbox symbol directly in the treeview for immediate feedback
            checkbox_state = "☑" if dashboard["selected"] else "☐"
            treeview.set(item_id, "Selected", checkbox_state)
            logging.debug(f"Toggled selection for '{dashboard['name']}' to {dashboard['selected']}")

def select_all_dashboards():
    for dashboard in session["dashboards"]:
        dashboard["selected"] = True
        dashboard["status"] = "Pending"
    refresh_dashboard_list()
    logging.info("Selected all dashboards.")

def deselect_all_dashboards():
    for dashboard in session["dashboards"]:
        dashboard["selected"] = False
        dashboard["status"] = "Pending"
    refresh_dashboard_list()
    logging.info("Deselected all dashboards.")

def update_group_filter():
    # Added check to ensure group_filter is initialized before use
    if group_filter is None:
        logging.error("update_group_filter called before group_filter is initialized.")
        return

    groups = {"All"}
    for d in session["dashboards"]:
        groups.add(d.get("group", "Default"))
    group_filter_values = sorted(list(groups))
    group_filter['values'] = group_filter_values
    if group_filter.get() not in group_filter_values: # Handle case where current filter value no longer exists
        group_filter.set("All") 
    refresh_dashboard_list() # Refresh to apply new filter

def get_selected_dashboards():
    return [d for d in session["dashboards"] if d.get("selected", False)]


def update_dashboard_status_ui(dashboard_name, status_message):
    """Updates the status column for a specific dashboard in the Treeview."""
    # Added check to ensure treeview is initialized before use
    if treeview is None:
        logging.error(f"update_dashboard_status_ui called before treeview is initialized for {dashboard_name}.")
        return

    for idx, dashboard in enumerate(session["dashboards"]):
        if dashboard["name"] == dashboard_name:
            dashboard["status"] = status_message
            # Find the item in the treeview by its iid (which is its index)
            item_id = str(idx)
            if treeview.exists(item_id):
                treeview.set(item_id, "Status", status_message)
                # Scroll to the item to make it visible if it's currently processing
                treeview.yview_moveto(treeview.index(item_id) / treeview.size(""))
            break


# ------------------------------------------------------------------------------
# Advanced Time Range Selection Using EST and Dropdown Options
# ------------------------------------------------------------------------------
def get_time_range():
    """
    Displays a pop-up to choose the time range in EST.
    Users can choose from several relative options or select "Custom Absolute".
    """
    # Added check to ensure app is initialized before Toplevel is created
    if app is None:
        messagebox.showerror("Error", "Application not fully initialized. Cannot open time range dialog.")
        return None, None
        
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
                    raise ValueError("Time must be in HH:MM format (e.g., 09:30).")
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
    
    tk.Button(popup, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)
    popup.grab_set()
    popup.wait_window()
    return result.get("start"), result.get("end")

# ------------------------------------------------------------------------------
# Scheduled Analysis Functionality
# ------------------------------------------------------------------------------
def schedule_analysis():
    global scheduled, schedule_interval 

    if scheduled:
        messagebox.showinfo("Scheduled", "Analysis is already scheduled. Please cancel it first.")
        return

    interval_str = simpledialog.askstring("Schedule Analysis", 
                                            "Enter interval in seconds for repeated analysis (min 60s):")
    try:
        interval = int(interval_str)
        if interval < 60: # Minimum 1 minute interval
            raise ValueError("Interval must be at least 60 seconds.")
    except (ValueError, TypeError) as ve:
        messagebox.showerror("Invalid Interval", str(ve))
        return
    
    scheduled = True
    schedule_interval = interval
    messagebox.showinfo("Scheduled", f"Analysis scheduled every {interval} seconds.")
    logging.info("Scheduled analysis every %s seconds. Starting first run.", interval)
    
    # Start the first scheduled analysis run, using app.after to stay on main thread
    # Ensure app is initialized before calling app.after
    if app:
        app.after(0, run_scheduled_analysis)
    else:
        logging.error("Cannot schedule analysis: Tkinter app is not initialized.")
        messagebox.showerror("Error", "Application not fully initialized. Cannot schedule analysis.")


def _run_scheduled_analysis_background():
    """
    This function runs in a background thread and performs the actual scheduled analysis.
    It does not interact with the GUI directly (except via app.after for updates).
    """
    now_est = datetime.now(est)
    start = (now_est - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M")
    end = now_est.strftime("%Y-%m-%d %H:%M")
    
    selected_dashboards = get_selected_dashboards() 
    if not selected_dashboards:
        logging.warning("No dashboards selected for scheduled analysis.")
        return

    # Update GUI elements using app.after (important for thread safety)
    # Reset status of selected dashboards before starting
    for db in selected_dashboards:
        # Check if app exists before calling app.after
        if app:
            app.after(0, update_dashboard_status_ui, db["name"], "Pending...")
    
    if app and progress_bar: # Check if app and progress_bar exist
        app.after(0, lambda: progress_bar.config(maximum=len(selected_dashboards), value=0))
    else:
        logging.warning("Could not update progress bar for scheduled analysis: UI elements not ready.")

    selected_dashboard_data = [{"url": d["url"], "name": d["name"]} for d in selected_dashboards]
    logging.info(f"Initiating scheduled analysis for {len(selected_dashboard_data)} dashboards from {start} to {end}")

    asyncio.run(analyze_dashboards_async(selected_dashboard_data, start, end))


def run_scheduled_analysis():
    """
    Manages the scheduling loop. This function is called by app.after.
    It kicks off the background analysis and then reschedules itself.
    """
    global scheduled 

    if not scheduled:
        logging.info("Scheduled analysis loop terminated.")
        return
    
    logging.info("Initiating scheduled analysis run.")
    # Run the actual analysis logic in a separate thread to prevent blocking the GUI
    Thread(target=_run_scheduled_analysis_background, daemon=True).start()
    
    # Schedule the next run on the main thread
    if app: # Ensure app is initialized before scheduling next run
        app.after(schedule_interval * 1000, run_scheduled_analysis)


def cancel_scheduled_analysis():
    global scheduled 
    if not scheduled:
        messagebox.showinfo("Scheduled", "No analysis is currently scheduled.")
        return
    scheduled = False
    messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled.")
    logging.info("Scheduled analysis cancelled by user.")

# ------------------------------------------------------------------------------
# Dashboard Analysis & Progress Tracking
# ------------------------------------------------------------------------------
def analyze_selected():
    """
    Handles manual "Analyze Selected" action, including GUI for time range.
    """
    selected_dashboards = get_selected_dashboards()
    if not selected_dashboards:
        messagebox.showwarning("Analyze Dashboards", "Select at least one dashboard.")
        return
    if not session["username"] or not session["password"]:
        messagebox.showerror("Credentials Missing", 
                             "Please set valid credentials via Settings -> Manage Credentials.")
        return
    
    # get_time_range() uses Toplevel and simpledialog, must be on main thread
    start, end = get_time_range()
    if not start or not end:
        logging.info("Time range selection cancelled by user for manual analysis.")
        return # User cancelled time range selection
    
    # Update status to "Pending" for selected dashboards before analysis
    for db in selected_dashboards:
        if app: # Ensure app is initialized before calling app.after
            app.after(0, update_dashboard_status_ui, db["name"], "Pending...")

    selected_dashboard_data = [{"url": d["url"], "name": d["name"]} for d in selected_dashboards]
    
    if progress_bar: # Ensure progress_bar is initialized before use
        progress_bar['maximum'] = len(selected_dashboard_data)
        progress_bar['value'] = 0
    else:
        logging.warning("Progress bar not initialized. Cannot update progress.")

    logging.info(f"Starting manual analysis for {len(selected_dashboard_data)} dashboards from {start} to {end}")
    
    # Run the asyncio logic in a separate thread to prevent blocking the Tkinter GUI
    Thread(target=lambda: asyncio.run(analyze_dashboards_async(selected_dashboard_data, start, end)),
           daemon=True).start()


# --- Intelligent Splunk Dashboard Waiting Function ---
async def _wait_for_splunk_dashboard_to_load(page: Page, timeout_ms: int = SPLUNK_WAIT_TIMEOUT_MS):
    """
    Intelligently waits for Splunk dashboard panels to load their content.
    This includes:
    1. Waiting for the main dashboard content area to be present.
    2. Waiting for all 'dashboard-panel' (or splunk-dashboard-panel) elements to appear.
    3. Clicking a 'Submit' or 'Apply' button if available after time range selection.
    4. Iteratively checking if panels have non-zero height, display valid content (not loading text),
       and crucially, if export/open-in-search buttons are enabled.
    """
    logging.info(f"Waiting for dashboard elements to load (timeout: {timeout_ms / 1000}s)...")
    
    # Wait for the main dashboard content container.
    # Prioritize newer Splunk custom elements if present, fallback to older divs.
    await page.wait_for_selector("splunk-dashboard-view, div.dashboard-body, div.dashboard-view", timeout=timeout_ms)
    
    # Wait for at least one dashboard panel to be visible.
    # Prioritize newer Splunk custom elements.
    await page.wait_for_selector("splunk-dashboard-panel, div.dashboard-panel", state="visible", timeout=timeout_ms)

    # Attempt to click a 'Submit' or 'Apply' button if available after time range selection.
    # This is critical if the dashboard has form inputs that need to be applied.
    try:
        logging.info("Checking for 'Submit' or 'Apply' buttons after time range selection.")
        # Common selectors for submit/apply buttons in Splunk forms/dashboards
        # Use a more generic selector to find buttons that trigger form submission
        submit_button = await page.query_selector(
            'button:has-text("Submit"), button:has-text("Apply"), '
            'a[role="button"]:has-text("Submit"), a[role="button"]:has-text("Apply"), '
            'div[data-test-name="form-submit-button"], div[data-test-name="submit-button"]'
        )
        if submit_button and await submit_button.is_enabled() and await submit_button.is_visible():
            logging.info("Found an enabled and visible 'Submit'/'Apply' button, clicking it.")
            await submit_button.click()
            # Wait for network activity to settle after the click, as this often triggers data loads
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS / 2) 
            logging.info("Clicked 'Submit'/'Apply' button. Waiting for dashboard content to refresh.")
        else:
            logging.debug("No active 'Submit' or 'Apply' button found or needed.")
    except Exception as e:
        logging.debug(f"Error checking/clicking 'Submit'/'Apply' button: {e}. This might be expected if the dashboard doesn't have such a button.")

    # Common Splunk loading indicators we want to avoid inside panels:
    loading_indicators = [
        "Waiting for input", "No results found", "Loading...", "Waiting for data...",
        "Generating data...", "No results for this time range.", "Could not retrieve search results.",
        "Search is waiting for inputs.", "Searching..."
    ]
    
    # Loop and check panel states for a maximum duration
    start_time = datetime.now()
    while (datetime.now() - start_time).total_seconds() * 1000 < timeout_ms:
        panels_state = await page.evaluate("""
            (loadingIndicators) => {
                const panels = document.querySelectorAll("splunk-dashboard-panel, div.dashboard-panel");
                if (panels.length === 0) return { allLoaded: false, reason: 'no_panels_found' };

                let allPanelsRendered = true;
                let allPanelsLoaded = true;
                let panelsWithLoadingText = [];
                let panelsWithDisabledExport = [];

                panels.forEach(panel => {
                    // Check if panel is visible and has some height/width (rendered)
                    if (panel.offsetHeight === 0 || panel.offsetWidth === 0 || window.getComputedStyle(panel).visibility === 'hidden') {
                        allPanelsRendered = false;
                    }

                    // Check for loading/waiting text within the panel's direct text content or children
                    const panelText = panel.innerText;
                    const isLoading = loadingIndicators.some(indicator => panelText.includes(indicator));
                    if (isLoading) {
                        allPanelsLoaded = false;
                        panelsWithLoadingText.push(panelText.substring(0, Math.min(panelText.length, 50)) + "...");
                    }

                    // --- Crucial Check: Export/Open in Search Button Status ---
                    // This typically becomes enabled only when data is fully loaded in the panel.
                    const exportButton = panel.querySelector(
                        'a[data-test-name*="export-button"], button[data-test-name*="export-button"], ' +
                        'a[aria-label*="Export"], button[aria-label*="Export"], ' +
                        'a:has-text("Export"), button:has-text("Export"), ' +
                        'a:has-text("Open in Search"), button:has-text("Open in Search")'
                    );
                    
                    // If an export button exists, check if it's disabled.
                    // A disabled export button usually means data isn't ready.
                    // Also check for its visibility to ensure it's part of the active UI.
                    if (exportButton && exportButton.hasAttribute('disabled') && exportButton.offsetParent !== null) {
                        allPanelsLoaded = false;
                        panelsWithDisabledExport.push("Panel with disabled export button: " + (panel.querySelector('.panel-title, .viz-title')?.innerText || 'No Title'));
                    } else if (exportButton && exportButton.offsetParent === null) {
                        // Button exists but not visible (e.g., hidden by CSS, not fully rendered)
                        allPanelsLoaded = false;
                        panelsWithDisabledExport.push("Panel with non-visible export button: " + (panel.querySelector('.panel-title, .viz-title')?.innerText || 'No Title'));
                    }
                });

                if (allPanelsRendered && allPanelsLoaded && panelsWithDisabledExport.length === 0) {
                    return { allLoaded: true };
                } else if (!allPanelsRendered) {
                    return { allLoaded: false, reason: 'not_rendered_or_visible' };
                } else if (panelsWithLoadingText.length > 0) {
                    return { allLoaded: false, reason: 'loading_text_present', panelsWithLoadingText: panelsWithLoadingText };
                } else if (panelsWithDisabledExport.length > 0) {
                    return { allLoaded: false, reason: 'export_button_disabled_or_hidden', panelsWithDisabledExport: panelsWithDisabledExport };
                } else {
                    return { allLoaded: false, reason: 'unknown_loading_state' };
                }
            }
        """, loading_indicators)

        if panels_state["allLoaded"]:
            logging.info("All Splunk dashboard panels appear to be loaded and ready.")
            # Give a small buffer for any final rendering after all checks pass
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS / 4) # Final network idle check
            await asyncio.sleep(2) 
            return True
        else:
            reason = panels_state.get('reason', 'unknown')
            log_msg = f"Dashboard not fully loaded yet. Reason: {reason}"
            if 'panelsWithLoadingText' in panels_state and panels_state['panelsWithLoadingText']:
                log_msg += f". Panels with loading text: {', '.join(panels_state['panelsWithLoadingText'])}"
            if 'panelsWithDisabledExport' in panels_state and panels_state['panelsWithDisabledExport']:
                log_msg += f". Panels with disabled/hidden export: {', '.join(panels_state['panelsWithDisabledExport'])}"
            logging.debug(log_msg)

        await asyncio.sleep(3) # Wait 3 seconds before checking again for stability

    raise TimeoutError(f"Splunk dashboard panels did not load within {timeout_ms / 1000} seconds. Last detected state: {panels_state.get('reason', 'N/A')}")


async def visit_dashboard(dashboard_data, start, end):
    """
    Visits the dashboard, handles login if necessary, and waits until the dashboard panels
    are loaded using the intelligent waiting logic.
    """
    url = dashboard_data["url"]
    name = dashboard_data["name"]
    retries = 2
    result_message = ""
    if app:
        app.after(0, update_dashboard_status_ui, name, "In Progress...")
    else:
        logging.warning(f"App not initialized, cannot update UI status for {name}.")

    async with browser_semaphore:
        browser = None  # Initialize browser outside the loop
        context = None  # Initialize context outside the loop
        page = None     # Initialize page outside the loop

        try: # Outer try-finally to ensure browser/context are always closed at the very end
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True) # Launch browser once per dashboard task
                context = await browser.new_context()

                for attempt in range(1, retries + 1):
                    try:
                        page = await context.new_page() # Create a new page for each attempt
                        logging.info(f"Navigating to {name} ({url}) (Attempt {attempt}/{retries})")
                        if app:
                            app.after(0, update_dashboard_status_ui, name, f"Loading ({attempt}/{retries})...")
                        
                        await page.goto(url, wait_until="load", timeout=SPLUNK_WAIT_TIMEOUT_MS)

                        # Check for login page first
                        if await page.query_selector('input[placeholder="Username"]'):
                            logging.info("Splunk login page detected for %s.", name)
                            if not session["username"] or not session["password"]:
                                raise RuntimeError("Login required but credentials not set. Please set them via Settings -> Manage Credentials.")
                            
                            if app:
                                app.after(0, update_dashboard_status_ui, name, "Logging in...")
                            await page.fill('input[placeholder="Username"]', session["username"])
                            await page.fill('input[placeholder="Password"]', session["password"])
                            
                            await page.press('input[placeholder="Password"]', "Enter")
                            logging.info("Attempted login for %s, waiting for navigation...", name)
                            
                            await page.wait_for_url(url, wait_until="domcontentloaded", timeout=SPLUNK_WAIT_TIMEOUT_MS) 
                            
                            await asyncio.sleep(2) 
                            
                            if app:
                                app.after(0, update_dashboard_status_ui, name, "Waiting for panels (logged in)...")
                            await _wait_for_splunk_dashboard_to_load(page, SPLUNK_WAIT_TIMEOUT_MS)
                            logging.info("Splunk dashboard loaded after login for %s.", name)

                        else:
                            logging.info("No login page detected for %s, proceeding with dashboard load wait.", name)
                            if app:
                                app.after(0, update_dashboard_status_ui, name, "Waiting for panels...")
                            await _wait_for_splunk_dashboard_to_load(page, SPLUNK_WAIT_TIMEOUT_MS)

                        # Take screenshot after ensuring the dashboard is fully loaded
                        safe_filename = sanitize_filename(url)
                        stamp = datetime.now(est).strftime("%Y%m%d_%H%M%S")
                        screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe_filename}_{stamp}.png")
                        
                        logging.info(f"Taking screenshot of {name} at {screenshot_path}")
                        if app:
                            app.after(0, update_dashboard_status_ui, name, "Taking screenshot...")
                        await page.screenshot(path=screenshot_path, full_page=True)
                        result_message = f"✅ {name} ({start} to {end}): Screenshot -> {screenshot_path}"
                        if app:
                            app.after(0, update_dashboard_status_ui, name, "Success")
                        
                        # Close the page explicitly after successful use
                        if page:
                            await page.close()
                        return result_message # Success, exit function
                        
                    except Exception as e:
                        error_msg = f"Error during page operations for {name} ({url}) (Attempt {attempt}/{retries}): {e}"
                        logging.error(error_msg)
                        
                        # Capture a screenshot on error for debugging, if page object exists
                        if page:
                            stamp_error = datetime.now(est).strftime("%Y%m%d_%H%M%S")
                            error_screenshot_path = os.path.join(SCREENSHOT_DIR, f"error_screenshot_{sanitize_filename(url)}_{stamp_error}_attempt{attempt}.png")
                            try:
                                await page.screenshot(path=error_screenshot_path, full_page=True)
                                logging.error(f"Error screenshot saved to {error_screenshot_path}")
                            except Exception as se:
                                logging.error(f"Failed to capture error screenshot for {name}: {se}")
                        
                        result_message = f"❌ {name}: Failed after {attempt} attempts. Last error: {e}"
                        if app:
                            app.after(0, update_dashboard_status_ui, name, f"Failed (Attempt {attempt})")

                        # Close the page before retrying with a new page
                        if page:
                            await page.close()

                        if attempt < retries:
                            logging.info(f"Retrying {name} in 5 seconds...")
                            await asyncio.sleep(5) # Wait before retrying
                        else:
                            return result_message # All retries exhausted, exit function

        finally: # This finally ensures browser and context are closed after ALL attempts
            if context:
                await context.close()
            if browser:
                await browser.close()
            logging.info(f"Browser closed for {name}")

    return result_message # Should only be reached if all retries fail


async def analyze_dashboards_async(dashboards_data, start, end):
    """
    Asynchronously analyzes a list of dashboard URLs with concurrency control.
    """
    results = []
    completed = 0
    
    # Create tasks for each dashboard visit
    tasks = [visit_dashboard(data, start, end) for data in dashboards_data]

    # Process tasks as they complete
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        completed += 1
        # Update the progress bar on the main thread
        if app and progress_bar: # Ensure app and progress_bar exist before updating UI
            app.after(0, lambda c=completed: progress_bar.config(value=c))
        logging.info(f"Completed {completed}/{len(dashboards_data)} dashboards.")
    
    logging.info("All dashboard analyses completed.")
    if app: # Ensure app exists before showing results
        app.after(0, lambda: show_results(results, start, end)) # Show final results


def show_results(messages, start, end):
    # Ensure app is initialized before Toplevel is created
    if app is None:
        logging.error("Cannot show results: Tkinter app is not initialized.")
        messagebox.showerror("Error", "Application not fully initialized. Cannot show results.")
        return

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
                    # Basic HTML escaping for messages
                    escaped_msg = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    f.write(f"<li>{escaped_msg}</li>")
                f.write("</ul></body></html>")
            messagebox.showinfo("Report Exported", f"Report saved as {report_filename}")
            logging.info("Report exported to %s", report_filename)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {e}")
            logging.error(f"Failed to export report to {report_filename}: {e}")

    tk.Button(win, text="Export Report to HTML", command=export_report).pack(pady=10)

# ------------------------------------------------------------------------------
# Main Application UI Setup
# ------------------------------------------------------------------------------

# It's good practice to encapsulate the UI setup in a function to control execution order.
def setup_ui():
    global app, progress_bar, treeview, group_filter # Declare globals to assign to them

    app = tk.Tk()
    app.title("Splunk Dashboard Desktop Client")
    app.geometry("1000x700")

    menu_bar = tk.Menu(app)
    settings_menu = tk.Menu(menu_bar, tearoff=0)
    settings_menu.add_command(label="Manage Credentials", command=manage_credentials)
    menu_bar.add_cascade(label="Settings", menu=settings_menu)
    app.config(menu=menu_bar)

    control_frame = tk.Frame(app)
    control_frame.pack(pady=10)

    tk.Button(control_frame, text="Add Dashboard", command=add_dashboard).grid(row=0, column=0, padx=5)
    tk.Button(control_frame, text="Delete Dashboard", command=delete_dashboard).grid(row=0, column=1, padx=5)
    tk.Button(control_frame, text="Analyze Selected", command=analyze_selected).grid(row=0, column=2, padx=5)
    tk.Button(control_frame, text="Schedule Analysis", command=schedule_analysis).grid(row=0, column=3, padx=5)
    tk.Button(control_frame, text="Cancel Scheduled Analysis", command=cancel_scheduled_analysis).grid(row=0, column=4, padx=5)

    filter_select_frame = tk.Frame(app)
    filter_select_frame.pack(pady=5, fill=tk.X, padx=10)

    tk.Label(filter_select_frame, text="Filter by Group:").pack(side=tk.LEFT, padx=5)
    group_filter = ttk.Combobox(filter_select_frame, state="readonly", width=15)
    group_filter.pack(side=tk.LEFT, padx=5)
    group_filter.bind("<<ComboboxSelected>>", lambda e: refresh_dashboard_list())
    # update_group_filter will be called after refresh_dashboard_list below

    tk.Button(filter_select_frame, text="Select All", command=select_all_dashboards).pack(side=tk.LEFT, padx=15)
    tk.Button(filter_select_frame, text="Deselect All", command=deselect_all_dashboards).pack(side=tk.LEFT, padx=5)

    tk.Label(app, text="Saved Dashboards: (Click on checkbox column to select)").pack(pady=(10,0))
    treeview_frame = tk.Frame(app)
    treeview_frame.pack(pady=5, fill=tk.BOTH, expand=True, padx=10)

    columns = ("Selected", "Name", "URL", "Group", "Status")
    treeview = ttk.Treeview(treeview_frame, columns=columns, show="headings")

    treeview.heading("Selected", text="☑", anchor=tk.CENTER)
    treeview.column("Selected", width=40, anchor=tk.CENTER, stretch=tk.NO)
    treeview.heading("Name", text="Dashboard Name")
    treeview.column("Name", width=200, stretch=tk.YES)
    treeview.heading("URL", text="URL")
    treeview.column("URL", width=350, stretch=tk.YES)
    treeview.heading("Group", text="Group")
    treeview.column("Group", width=100, stretch=tk.YES)
    treeview.heading("Status", text="Status")
    treeview.column("Status", width=120, stretch=tk.NO)

    treeview.bind("<Button-1>", toggle_selection)
    treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    treeview_scrollbar = ttk.Scrollbar(treeview_frame, orient="vertical", command=treeview.yview)
    treeview.configure(yscrollcommand=treeview_scrollbar.set)
    treeview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    progress_bar = ttk.Progressbar(app, orient="horizontal", mode="determinate", length=600)
    progress_bar.pack(pady=20)

    # Initialize dashboards AFTER UI elements are created
    load_dashboards() 
    # Refresh the list AFTER treeview and group_filter are established
    refresh_dashboard_list()
    update_group_filter() # Ensure filter options are populated after dashboards are loaded

# Call the UI setup function and then start the main loop
if __name__ == "__main__":
    setup_ui()
    app.mainloop()
