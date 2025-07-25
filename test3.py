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

# Define a default wait timeout for Splunk operations
SPLUNK_WAIT_TIMEOUT_MS = 90000 # Increased to 90 seconds for more robustness

# ------------------------------------------------------------------------------
# Signal & Exit Handling
# ------------------------------------------------------------------------------
def cleanup_and_exit(*_):
    session["username"] = None
    session["password"] = None
    logging.info("Application exiting.")
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
            # Ensure "selected" key exists for old entries
            for dashboard in session["dashboards"]:
                if "selected" not in dashboard:
                    dashboard["selected"] = False
        logging.info(f"Loaded {len(session['dashboards'])} dashboards from {DASHBOARD_FILE}")

def save_dashboards():
    with open(DASHBOARD_FILE, "w") as f:
        json.dump(session["dashboards"], f, indent=2)
    logging.info(f"Saved {len(session['dashboards'])} dashboards to {DASHBOARD_FILE}")

def sanitize_filename(url):
    netloc = urlparse(url).netloc.replace('.', '_').replace(':', '_') # Replace colon for filename safety
    # Use a part of UUID for uniqueness, avoiding extremely long names
    uid = uuid.uuid4().hex[:6]
    # Simple alphanumeric filter for URL path to keep it short and safe
    path_segment = re.sub(r'[^a-zA-Z0-9_]', '', urlparse(url).path.replace('/', '_'))
    return f"{netloc}_{path_segment}_{uid}"


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
    session["dashboards"].append({"name": name.strip(), "url": url.strip(), "group": group.strip(), "selected": False})
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()
    logging.info(f"Added dashboard: {name} (URL: {url}, Group: {group})")

def delete_dashboard():
    selected_items = treeview.selection()
    if not selected_items:
        messagebox.showinfo("Delete Dashboard", "Select dashboards to delete.")
        return
    if not messagebox.askyesno("Confirm Delete", "Are you sure to delete selected dashboards?"):
        return
    
    names_to_delete = []
    for item_id in selected_items:
        name = treeview.item(item_id, "values")[0] # Get dashboard name from the values tuple
        names_to_delete.append(name)
    
    session["dashboards"] = [d for d in session["dashboards"] if d["name"] not in names_to_delete]
    save_dashboards()
    refresh_dashboard_list()
    update_group_filter()
    logging.info(f"Deleted dashboards: {', '.join(names_to_delete)}")


def refresh_dashboard_list():
    for i in treeview.get_children():
        treeview.delete(i)
    
    selected_filter = group_filter.get() if group_filter else "All"
    for idx, dashboard in enumerate(session["dashboards"]):
        group_name = dashboard.get("group", "Default")
        if selected_filter == "All" or group_name == selected_filter:
            checkbox_state = "☑" if dashboard.get("selected", False) else "☐"
            # Insert item into treeview with checkbox state as the first column
            treeview.insert("", "end", iid=str(idx), 
                            values=(checkbox_state, dashboard["name"], dashboard["url"], group_name))

def toggle_selection(event):
    item_id = treeview.identify_row(event.y)
    if not item_id:
        return
    
    column = treeview.identify_column(event.x)
    if column == "#1": # Check if the click was on the first column (checkbox column)
        # Get the dashboard name from the selected item
        current_values = treeview.item(item_id, "values")
        dashboard_name = current_values[1] # Name is now at index 1

        # Find the dashboard in the session data and toggle its 'selected' status
        for dashboard in session["dashboards"]:
            if dashboard["name"] == dashboard_name:
                dashboard["selected"] = not dashboard.get("selected", False)
                break
        
        # Refresh the entire list to update the checkbox visually
        refresh_dashboard_list()

def update_group_filter():
    groups = {"All"}
    for d in session["dashboards"]:
        groups.add(d.get("group", "Default"))
    group_filter_values = sorted(list(groups))
    group_filter['values'] = group_filter_values
    group_filter.set("All") # Reset filter to All after update

def get_selected_dashboards():
    # Iterate through the actual session data to get selected URLs
    return [d for d in session["dashboards"] if d.get("selected", False)]


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
    
    tk.Button(popup, text="Submit", command=submit).grid(row=2, column=0, columnspan=2, pady=10)
    popup.grab_set()
    popup.wait_window()
    return result.get("start"), result.get("end")

# ------------------------------------------------------------------------------
# Scheduled Analysis Functionality
# ------------------------------------------------------------------------------
def schedule_analysis():
    interval_str = simpledialog.askstring("Schedule Analysis", 
                                            "Enter interval in seconds for repeated analysis (min 60s):")
    try:
        interval = int(interval_str)
        if interval < 60: # Minimum 1 minute interval
            raise ValueError("Interval must be at least 60 seconds.")
    except (ValueError, TypeError) as ve:
        messagebox.showerror("Invalid Interval", str(ve))
        return
    global scheduled, schedule_interval
    scheduled = True
    schedule_interval = interval
    messagebox.showinfo("Scheduled", f"Analysis scheduled every {interval} seconds.")
    logging.info("Scheduled analysis every %s seconds", interval)
    # Start the scheduled analysis, ensuring it runs in a non-blocking way
    run_scheduled_analysis()

def run_scheduled_analysis():
    if not scheduled:
        logging.info("Scheduled analysis cancelled from within the loop.")
        return
    logging.info("Initiating scheduled analysis.")
    # Ensure this runs in a separate thread to not block the GUI
    # analyze_selected will itself create Playwright threads
    Thread(target=analyze_selected, daemon=True).start()
    app.after(schedule_interval * 1000, run_scheduled_analysis) # Schedule next run

def cancel_scheduled_analysis():
    global scheduled
    scheduled = False
    messagebox.showinfo("Scheduled", "Scheduled analysis has been cancelled.")
    logging.info("Scheduled analysis cancelled by user.")

# ------------------------------------------------------------------------------
# Dashboard Analysis & Progress Tracking
# ------------------------------------------------------------------------------
def analyze_selected():
    selected_dashboards = get_selected_dashboards()
    if not selected_dashboards:
        messagebox.showwarning("Analyze Dashboards", "Select at least one dashboard.")
        return
    if not session["username"] or not session["password"]:
        messagebox.showerror("Credentials Missing", 
                             "Please set valid credentials in .secrets or update via Settings.")
        return
    
    start, end = get_time_range()
    if not start or not end:
        logging.info("Time range selection cancelled by user.")
        return # User cancelled time range selection
    
    selected_urls = [d["url"] for d in selected_dashboards]
    progress_bar['maximum'] = len(selected_urls)
    progress_bar['value'] = 0
    logging.info(f"Starting analysis for {len(selected_urls)} dashboards from {start} to {end}")
    
    # Run the asyncio logic in a separate thread to prevent blocking the Tkinter GUI
    Thread(target=lambda: asyncio.run(analyze_dashboards_async(selected_urls, start, end)),
           daemon=True).start()


# --- Intelligent Splunk Dashboard Waiting Function ---
async def _wait_for_splunk_dashboard_to_load(page: Page, timeout_ms: int = SPLUNK_WAIT_TIMEOUT_MS):
    """
    Intelligently waits for Splunk dashboard panels to load their content.
    This includes:
    1. Waiting for the main dashboard content area to be present.
    2. Waiting for all 'dashboard-panel' elements to appear.
    3. Clicking a 'Submit' or 'Apply' button if available after time range selection.
    4. Iteratively checking if panels have non-zero height and all export options are enabled,
       and don't contain common loading/waiting indicators.
    """
    logging.info(f"Waiting for dashboard elements to load (timeout: {timeout_ms / 1000}s)...")
    
    await page.wait_for_selector("div.dashboard-body, div.dashboard-view", timeout=timeout_ms)
    await page.wait_for_selector("div.dashboard-panel", state="visible", timeout=timeout_ms)

    # Attempt to click a 'Submit' or 'Apply' button if available after time range selection
    try:
        logging.info("Checking for 'Submit' or 'Apply' buttons after time range selection.")
        # Common selectors for submit/apply buttons in Splunk forms/dashboards
        # Using a more robust selector that looks for role="button" or common button tags with specific text
        submit_button = await page.query_selector('button:has-text("Submit"), button:has-text("Apply"), [role="button"]:has-text("Submit"), [role="button"]:has-text("Apply")')
        if submit_button and await submit_button.is_enabled():
            logging.info("Found an enabled 'Submit'/'Apply' button, clicking it.")
            await submit_button.click()
            # Wait for network activity to settle after the click, as this often triggers data loads
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS / 2) 
    except Exception as e:
        logging.debug(f"No 'Submit' or 'Apply' button found or clickable: {e}. This might be expected if the dashboard doesn't have such a button.")

    # Common Splunk loading indicators we want to avoid:
    loading_indicators = [
        "Waiting for input",
        "No results found", # Sometimes this is a valid state, but often indicates a non-loaded search
        "Loading...",
        "Waiting for data...",
        "Generating data...",
        "No results for this time range.", # Could also be valid, but worth considering
        "Could not retrieve search results.", # Error indicator
        "Search is waiting for inputs." # Another input related indicator
    ]
    
    # Loop and check panel states
    start_time = datetime.now()
    while (datetime.now() - start_time).total_seconds() * 1000 < timeout_ms:
        panels_state = await page.evaluate(f"""(loadingIndicators) => {{
            const panels = document.querySelectorAll("div.dashboard-panel");
            if (panels.length === 0) return {{ allLoaded: false, reason: 'no_panels' }};

            let allPanelsRendered = true;
            let allPanelsLoaded = true;
            let panelsWithLoadingText = [];
            let panelsWithDisabledExport = [];

            panels.forEach(panel => {{
                // Check if panel is visible and has some height
                if (panel.offsetHeight === 0 || panel.offsetWidth === 0) {{
                    allPanelsRendered = false;
                }}

                // Check for loading/waiting text within the panel
                const panelText = panel.innerText;
                const isLoading = loadingIndicators.some(indicator => panelText.includes(indicator));
                if (isLoading) {{
                    allPanelsLoaded = false;
                    panelsWithLoadingText.push(panelText.substring(0, Math.min(panelText.length, 50)) + "...");
                }}

                // Check if export/open in search button is enabled, indicating data is ready
                // Adjust these selectors based on your Splunk version's actual button classes/text
                // Look for common export buttons, which are usually `<a>` or `<button>` tags within actions
                const exportButton = panel.querySelector('a[data-test-name*="export-button"], button[data-test-name*="export-button"], a[aria-label*="Export"], button[aria-label*="Export"], a:has-text("Export"), button:has-text("Export"), a:has-text("Open in Search"), button:has-text("Open in Search")');
                
                // If an export button exists, check if it's disabled. A disabled export button usually means data isn't ready.
                if (exportButton && exportButton.hasAttribute('disabled')) {{
                    allPanelsLoaded = false;
                    panelsWithDisabledExport.push("Panel with disabled export button");
                }}
            }});

            if (allPanelsRendered && allPanelsLoaded && panelsWithDisabledExport.length === 0) {{
                return {{ allLoaded: true }};
            }} else if (!allPanelsRendered) {{
                return {{ allLoaded: false, reason: 'not_rendered' }};
            }} else if (panelsWithLoadingText.length > 0) {{
                return {{ allLoaded: false, reason: 'loading_text_present', panelsWithLoadingText: panelsWithLoadingText }};
            }} else if (panelsWithDisabledExport.length > 0) {{
                return {{ allLoaded: false, reason: 'export_button_disabled', panelsWithDisabledExport: panelsWithDisabledExport }};
            }} else {{
                return {{ allLoaded: false, reason: 'unknown' }};
            }}
        }}""", loading_indicators)

        if panels_state["allLoaded"]:
            logging.info("All Splunk dashboard panels appear to be loaded and ready.")
            await asyncio.sleep(2) # Give a slightly longer buffer for any final rendering after all checks pass
            return True
        else:
            reason = panels_state.get('reason', 'unknown')
            log_msg = f"Dashboard not fully loaded yet. Reason: {reason}"
            if 'panelsWithLoadingText' in panels_state and panels_state['panelsWithLoadingText']:
                log_msg += f". Panels with loading text: {panels_state['panelsWithLoadingText']}"
            if 'panelsWithDisabledExport' in panels_state and panels_state['panelsWithDisabledExport']:
                log_msg += f". Panels with disabled export: {panels_state['panelsWithDisabledExport']}"
            logging.debug(log_msg) # Use debug for frequent checks during polling

        await asyncio.sleep(3) # Increased wait to 3 seconds before checking again for stability

    raise TimeoutError(f"Splunk dashboard panels did not load within {timeout_ms / 1000} seconds.")


async def visit_dashboard(url, start, end):
    """
    Visits the dashboard, handles login if necessary, and waits until the dashboard panels
    are loaded using the intelligent waiting logic.
    """
    retries = 3
    for attempt in range(1, retries + 1):
        browser = None
        context = None
        page = None
        try:
            async with async_playwright() as p:
                # Set headless=False for debugging, change to True for production
                browser = await p.chromium.launch(headless=True) 
                # Create a new context for each dashboard to ensure isolation
                context = await browser.new_context() 
                page = await context.new_page()
                logging.info(f"Navigating to {url} (Attempt {attempt}/{retries})")
                
                # Navigate to the URL and wait for the initial page load
                await page.goto(url, wait_until="load", timeout=SPLUNK_WAIT_TIMEOUT_MS)

                # Check for login page first
                if await page.query_selector('input[placeholder="Username"]'):
                    logging.info("Splunk login page detected.")
                    if not session["username"] or not session["password"]:
                        raise RuntimeError("Login required but credentials not set. Please set them in settings.")
                    await page.fill('input[placeholder="Username"]', session["username"])
                    await page.fill('input[placeholder="Password"]', session["password"])
                    await page.press('input[placeholder="Password"]', "Enter")
                    logging.info("Attempted login, waiting for navigation...")
                    
                    # Wait for navigation after login to the original URL
                    await page.wait_for_url(url, wait_until="domcontentloaded", timeout=SPLUNK_WAIT_TIMEOUT_MS) 
                    
                    # Small pause before intelligent wait to allow elements to render
                    await asyncio.sleep(2) 
                    await _wait_for_splunk_dashboard_to_load(page, SPLUNK_WAIT_TIMEOUT_MS)
                    logging.info("Splunk dashboard loaded after login.")

                else:
                    logging.info("No login page detected, proceeding with dashboard load wait.")
                    # Directly apply intelligent wait if no login was needed
                    await _wait_for_splunk_dashboard_to_load(page, SPLUNK_WAIT_TIMEOUT_MS)

                # Take screenshot after ensuring the dashboard is fully loaded
                safe_filename = sanitize_filename(url)
                # Use EST time for the screenshot stamp.
                stamp = datetime.now(est).strftime("%Y%m%d_%H%M%S")
                screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe_filename}_{stamp}.png")
                
                logging.info(f"Taking screenshot of {url} at {screenshot_path}")
                await page.screenshot(path=screenshot_path, full_page=True)
                return f"✅ {url} ({start} to {end}): Screenshot -> {screenshot_path}"

        except Exception as e:
            logging.error(f"Error during page operations for {url} (Attempt {attempt}/{retries}): {e}")
            # Capture a screenshot on error for debugging, if page object exists
            if page:
                error_screenshot_path = os.path.join(SCREENSHOT_DIR, f"error_screenshot_{sanitize_filename(url)}_{stamp if 'stamp' in locals() else 'unknown'}_attempt{attempt}.png")
                try:
                    await page.screenshot(path=error_screenshot_path, full_page=True)
                    logging.error(f"Error screenshot saved to {error_screenshot_path}")
                except Exception as se:
                    logging.error(f"Failed to capture error screenshot: {se}")
            
            if attempt == retries:
                return f"❌ {url}: Failed after {retries} attempts. Last error: {e}"
            logging.info(f"Retrying {url} in 5 seconds...") # Increased retry wait
            await asyncio.sleep(5) # Wait before retrying
         finally:
            try:
                if context:
                    await context.close()
            except Exception as e:
                logging.warning(f"Error closing context: {e}")
            try:
                if browser:
                    await browser.close()
            except Exception as e:
                logging.warning(f"Error closing browser: {e}")
            logging.info(f"Browser cleanup done for {url}")

# around screenshot call, update this block
                # Take screenshot after ensuring the dashboard is fully loaded
                safe_filename = sanitize_filename(url)
                stamp = datetime.now(est).strftime("%Y%m%d_%H%M%S")
                screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe_filename}_{stamp}.png")

                try:
                    if page.is_closed():
                        logging.warning("Page was already closed before screenshot.")
                        return f"⚠️ {url}: Page closed before screenshot"
                    logging.info(f"Taking screenshot of {url} at {screenshot_path}")
                    await page.screenshot(path=screenshot_path, full_page=True)
                except Exception as e:
                    logging.error(f"Failed to take screenshot: {e}")
                    return f"❌ {url}: Screenshot failed. Error: {e}"

                return f"✅ {url} ({start} to {end}): Screenshot -> {screenshot_path}"
...


async def analyze_dashboards_async(urls, start, end):
    """
    Asynchronously analyzes a list of dashboard URLs.
    This function creates and manages the Playwright browser context for each URL
    and updates the progress bar.
    """
    results = []
    completed = 0
    # Create tasks for each dashboard visit
    tasks = [visit_dashboard(url, start, end) for url in urls]

    # Process tasks as they complete
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        completed += 1
        # Update the progress bar on the main thread
        app.after(0, lambda c=completed: progress_bar.config(value=c))
        logging.info(f"Completed {completed}/{len(urls)} dashboards.")
    
    logging.info("All dashboard analyses completed.")
    # Show results on the main thread
    app.after(0, lambda: show_results(results, start, end))


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
app = tk.Tk()
app.title("Splunk Dashboard Desktop Client")
app.geometry("900x700") # Increased window size for Treeview

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

# Dashboard list (using Treeview for checkboxes)
tk.Label(app, text="Saved Dashboards: (Click on checkbox to select)").pack(pady=(10,0))
treeview_frame = tk.Frame(app)
treeview_frame.pack(pady=5, fill=tk.BOTH, expand=True)

treeview = ttk.Treeview(treeview_frame, columns=("Selected", "Name", "URL", "Group"), show="headings")

treeview.heading("Selected", text="☑", anchor=tk.CENTER)
treeview.column("Selected", width=40, anchor=tk.CENTER, stretch=tk.NO)
treeview.heading("Name", text="Dashboard Name")
treeview.column("Name", width=200, stretch=tk.YES)
treeview.heading("URL", text="URL")
treeview.column("URL", width=350, stretch=tk.YES)
treeview.heading("Group", text="Group")
treeview.column("Group", width=100, stretch=tk.YES)

# Bind the click event to the treeview to handle checkbox toggling
treeview.bind("<Button-1>", toggle_selection)

treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar to the treeview
treeview_scrollbar = ttk.Scrollbar(treeview_frame, orient="vertical", command=treeview.yview)
treeview.configure(yscrollcommand=treeview_scrollbar.set)
treeview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


# Progress bar for analysis.
progress_bar = ttk.Progressbar(app, orient="horizontal", mode="determinate", length=600)
progress_bar.pack(pady=20)

load_dashboards()
refresh_dashboard_list()
app.mainloop()
