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
    temp_root = tk.Tk()
    temp_root.withdraw()
    messagebox.showerror("Secrets Load Error", f"Failed to load .secrets file: {e}")
    temp_root.destroy()

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
est = pytz.timezone("America/New_York")
SCREENSHOT_DIR = os.path.join("screenshots", datetime.now(est).strftime("%Y-%m-%d"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

SPLUNK_WAIT_TIMEOUT_MS = 120000
CONCURRENT_BROWSERS_LIMIT = 3
browser_semaphore = asyncio.Semaphore(CONCURRENT_BROWSERS_LIMIT)

class SplunkAutomatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Splunk Dashboard Automator")
        master.geometry("1000x750")
        self.initialize_ui(master)

    def initialize_ui(self, master):
        # UI implementation omitted for brevity
        pass

    async def analyze_dashboard_instance_async(self, playwright, dashboard_data, start_time, end_time):
        async with browser_semaphore:
            name = dashboard_data["name"]
            url = dashboard_data["url"]
            self.master.after(0, self.update_dashboard_status_ui, name, "Processing...")

            full_url = self.format_time_for_url(url, start_time, end_time)

            browser = None
            try:
                browser = await playwright.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                logging.info(f"Navigating to: {full_url}")
                await page.goto(full_url, wait_until='domcontentloaded', timeout=SPLUNK_WAIT_TIMEOUT_MS)

                username_field = page.locator('input[name="username"]')
                if await username_field.is_visible(timeout=5000):
                    logging.info("Login page detected. Attempting to log in.")
                    await username_field.fill(session["username"])
                    await page.locator('input[name="password"]').fill(session["password"])
                    await page.locator('button[type="submit"], input[type="submit"]').click()
                    await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS)
                    logging.info("Login successful.")
                else:
                    logging.info("Login page not detected, assuming already logged in.")

                await self._wait_for_splunk_dashboard_to_load(page)
                await asyncio.sleep(10)

                sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
                timestamp = datetime.now(est).strftime("%Y%m%d-%H%M%S")
                screenshot_path = os.path.join(SCREENSHOT_DIR, f"{sanitized_name}_{timestamp}.png")
                await page.screenshot(path=screenshot_path, full_page=True)

                self.master.after(0, self.update_dashboard_status_ui, name, f"Success: {os.path.basename(screenshot_path)}")
                logging.info(f"Successfully captured dashboard '{name}' to {screenshot_path}")

            except Exception as e:
                error_msg = str(e).split('\n')[0]
                self.master.after(0, self.update_dashboard_status_ui, name, f"Failed: {error_msg}")
                logging.error(f"Failed to process dashboard '{name}': {e}", exc_info=False)
            finally:
                if browser:
                    await browser.close()
                if progress_bar:
                    self.master.after(0, progress_bar.step)

    async def _wait_for_splunk_dashboard_to_load(self, page: Page):
        logging.info(f"Waiting for dashboard elements to load...")
        await page.wait_for_selector("div.dashboard-body, splunk-dashboard-view", timeout=SPLUNK_WAIT_TIMEOUT_MS)

        submit_button = page.locator('button:has-text("Submit"), button:has-text("Apply")').first
        if await submit_button.is_visible(timeout=5000) and await submit_button.is_enabled(timeout=5000):
            logging.info("Found 'Submit' button, clicking it.")
            await submit_button.click()
            await page.wait_for_load_state('networkidle', timeout=SPLUNK_WAIT_TIMEOUT_MS / 2)
        else:
            logging.debug("No 'Submit' button found or needed.")

        await page.wait_for_selector("div.dashboard-panel, splunk-dashboard-panel", state="visible", timeout=SPLUNK_WAIT_TIMEOUT_MS)

        loading_indicators = ["Waiting for data", "Loading...", "Searching...", "Loading data", "Rendering"]
        start_wait = time.time()
        iteration = 0

        while time.time() - start_wait < (SPLUNK_WAIT_TIMEOUT_MS / 1000):
            iteration += 1
            panels = await page.locator("div.dashboard-panel, splunk-dashboard-panel").all()
            logging.info(f"Checking {len(panels)} panels for loading state (iteration {iteration})")

            all_panels_loaded = True
            for i, panel in enumerate(panels):
                panel_text = await panel.inner_text()
                if any(indicator in panel_text for indicator in loading_indicators):
                    logging.info(f"Panel {i + 1} has loading text: {panel_text[:50]}...")
                    all_panels_loaded = False
                    continue

                export_button = panel.locator('button[aria-label*="Export"], a[aria-label*="Export"]').first
                if await export_button.count() > 0:
                    if not await export_button.is_enabled():
                        logging.info(f"Panel {i + 1} has export button but it's disabled")
                        all_panels_loaded = False
                        continue
                else:
                    loading_spinner = panel.locator('.loading, .spinner, .waiting')
                    if await loading_spinner.count() > 0 and await loading_spinner.is_visible():
                        logging.info(f"Panel {i + 1} has loading spinner")
                        all_panels_loaded = False
                        continue

            if all_panels_loaded:
                logging.info("All dashboard panels appear to be loaded.")
                await asyncio.sleep(3)
                return

            await asyncio.sleep(2)

        logging.warning("Timed out waiting for all dashboard panels to finish loading.")
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