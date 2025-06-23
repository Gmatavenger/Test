import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, scrolledtext
from tkcalendar import DateEntry
import json
import os
import asyncio
import re
import traceback
import uuid
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from datetime import datetime, timezone, timedelta
from threading import Thread
import signal
import sys

session_cache = {
    "splunk_username": None,
    "splunk_password": None,
    "onboarded_dashboards": [],
}

DASHBOARD_STORE = "dashboards.json"
SCREENSHOT_DIR_BASE = "screenshots"
SCREENSHOT_DIR = os.path.join(SCREENSHOT_DIR_BASE, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

VALID_URL_REGEX = re.compile(r'^https?://.+')

def graceful_shutdown(*args):
    clear_credentials()
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

def load_dashboards():
    try:
        if os.path.exists(DASHBOARD_STORE):
            with open(DASHBOARD_STORE, "r") as f:
                dashboards = json.load(f)
                session_cache["onboarded_dashboards"] = dashboards
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load dashboards: {e}")
        session_cache["onboarded_dashboards"] = []

def save_dashboards():
    try:
        with open(DASHBOARD_STORE, "w") as f:
            json.dump(session_cache["onboarded_dashboards"], f, indent=2)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save dashboards: {e}")

def add_dashboard():
    name = simpledialog.askstring("Dashboard Name", "Enter a name for the dashboard:")
    url = simpledialog.askstring("Dashboard URL", "Enter the dashboard URL:")
    if not name or not url:
        return
    if not VALID_URL_REGEX.match(url):
        messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http or https.")
        return
    if not name.strip():
        messagebox.showerror("Invalid Name", "Dashboard name cannot be empty.")
        return
    if any(d["name"] == name for d in session_cache["onboarded_dashboards"]):
        messagebox.showerror("Duplicate", "Dashboard name already exists.")
        return
    session_cache["onboarded_dashboards"].append({"name": name.strip(), "url": url.strip()})
    save_dashboards()
    refresh_dashboard_list()

def prompt_login():
    login_popup = tk.Toplevel()
    login_popup.title("Splunk Login")

    tk.Label(login_popup, text="Username:").grid(row=0, column=0, padx=5, pady=5)
    username_entry = tk.Entry(login_popup)
    username_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(login_popup, text="Password:").grid(row=1, column=0, padx=5, pady=5)
    password_entry = tk.Entry(login_popup, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    def toggle_password():
        if password_entry.cget("show") == "*":
            password_entry.config(show="")
        else:
            password_entry.config(show="*")

    eye_button = tk.Button(login_popup, text="👁️", command=toggle_password)
    eye_button.grid(row=1, column=2, padx=5)

    def submit():
        session_cache["splunk_username"] = username_entry.get()
        session_cache["splunk_password"] = password_entry.get()
        login_popup.destroy()
        messagebox.showinfo("Logged In", "Login credentials saved for this session.")

    tk.Button(login_popup, text="Submit", command=submit).grid(row=2, column=0, columnspan=3, pady=10)
    login_popup.grab_set()
    login_popup.wait_window()

def analyze_selected():
    selected = [dashboards_box.get(idx) for idx in dashboards_box.curselection()]
    if not selected:
        messagebox.showwarning("No Selection", "Please select one or more dashboards to analyze.")
        return

    def get_datetime_input():
        popup = tk.Toplevel()
        popup.title("Select Date and Time")

        tk.Label(popup, text="Start Date:").grid(row=0, column=0, padx=5, pady=5)
        start_date = DateEntry(popup)
        start_date.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(popup, text="Start Time (HH:MM):").grid(row=1, column=0, padx=5, pady=5)
        start_time_entry = tk.Entry(popup)
        start_time_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(popup, text="End Date:").grid(row=2, column=0, padx=5, pady=5)
        end_date = DateEntry(popup)
        end_date.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(popup, text="End Time (HH:MM):").grid(row=3, column=0, padx=5, pady=5)
        end_time_entry = tk.Entry(popup)
        end_time_entry.grid(row=3, column=1, padx=5, pady=5)

        result = {}

        def on_submit():
            try:
                if not re.match(r"^\d{2}:\d{2}$", start_time_entry.get()) or not re.match(r"^\d{2}:\d{2}$", end_time_entry.get()):
                    raise ValueError("Time format should be HH:MM.")
                start = f"{start_date.get()} {start_time_entry.get()}"
                end = f"{end_date.get()} {end_time_entry.get()}"
                start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M")
                end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M")

                if end_dt <= start_dt:
                    raise ValueError("End time must be after start time.")
                if start_dt > datetime.now() or end_dt > datetime.now():
                    raise ValueError("Dates cannot be in the future.")

                result['start'] = start
                result['end'] = end
                popup.destroy()
            except ValueError as ve:
                messagebox.showerror("Invalid Input", str(ve))

        tk.Button(popup, text="Submit", command=on_submit).grid(row=4, column=0, columnspan=2, pady=10)
        popup.grab_set()
        popup.wait_window()
        return result.get('start'), result.get('end')

    start_time, end_time = get_datetime_input()
    if not start_time or not end_time:
        return

    selected_urls = [d["url"] for d in session_cache["onboarded_dashboards"] if d["name"] in selected]

    def run_async():
        try:
            asyncio.run(run_all_dashboards(selected_urls, start_time, end_time))
        except Exception as e:
            messagebox.showerror("Async Error", f"One or more analyses failed: {str(e)}")

    Thread(target=run_async).start()

def clear_credentials():
    session_cache["splunk_username"] = None
    session_cache["splunk_password"] = None

def sanitize_filename(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.replace('.', '_')
    unique_id = uuid.uuid4().hex[:8]
    return f"{netloc}_{unique_id}"

async def run_all_dashboards(urls, start_time, end_time):
    messages = []
    results = await asyncio.gather(*(process_dashboard(url, start_time, end_time) for url in urls), return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            messages.append(r)
    if messages:
        show_results_summary("LLM Results Summary", messages)
    clear_credentials()

def show_results_summary(title, messages):
    popup = tk.Toplevel()
    popup.title(title)
    text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, width=80, height=20)
    text_area.pack(padx=10, pady=10)
    for message in messages:
        text_area.insert(tk.END, message + "\n\n")
    text_area.config(state=tk.DISABLED)
    tk.Button(popup, text="Close", command=popup.destroy).pack(pady=5)

def refresh_dashboard_list():
    dashboards_box.delete(0, tk.END)
    for entry in session_cache["onboarded_dashboards"]:
        dashboards_box.insert(tk.END, entry["name"])

async def process_dashboard(url, start_time, end_time):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        screenshot_file = None
        try:
            await page.goto(url)
            login_input = await page.query_selector("input[name='username']")
            if login_input and session_cache["splunk_username"] and session_cache["splunk_password"]:
                await page.fill("input[name='username']", session_cache["splunk_username"])
                await page.fill("input[name='password']", session_cache["splunk_password"])
                await page.click("button[type='submit']")
                await page.wait_for_load_state("networkidle")

            await page.wait_for_load_state("networkidle")
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_name = sanitize_filename(url)
            subdir = os.path.join(SCREENSHOT_DIR_BASE, datetime.utcnow().strftime("%Y-%m-%d"))
            os.makedirs(subdir, exist_ok=True)
            screenshot_file = os.path.join(subdir, f"screenshot_{safe_name}_{timestamp}.png")
            await page.screenshot(path=screenshot_file, full_page=True)
        except Exception as e:
            return f"Failed to process {url}: {str(e)}"
        finally:
            await browser.close()

        if screenshot_file:
            return send_to_llm_mcp(screenshot_file, url, start_time, end_time)
        return None

def send_to_llm_mcp(image_path, dashboard_url, start, end):
    try:
        print(f"Sending {image_path} for analysis of {dashboard_url} between {start} and {end}...")
        return f"(Simulated) Analysis of {dashboard_url} from {start} to {end} completed. Screenshot saved at {image_path}."
    except Exception as e:
        return f"LLM analysis failed: {str(e)}"

root = tk.Tk()
root.title("Splunk Dashboard Analyzer")
root.geometry("600x400")

load_dashboards()

add_button = ttk.Button(root, text="Add Dashboard", command=add_dashboard)
add_button.pack(pady=5)

login_button = ttk.Button(root, text="Login to Splunk", command=prompt_login)
login_button.pack(pady=5)

dashboards_box = tk.Listbox(root, selectmode=tk.MULTIPLE, width=80, height=10)
dashboards_box.pack(pady=10)
refresh_dashboard_list()

analyze_button = ttk.Button(root, text="Analyze Selected Dashboards", command=analyze_selected)
analyze_button.pack(pady=10)

root.mainloop()
