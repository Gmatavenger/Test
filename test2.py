# NOTE: The following script uses Playwright, which must be installed and available.
# If you're running this in an environment without Playwright, install it using:
# pip install playwright python-dotenv tkcalendar
# And install required browsers with:
# playwright install

import requests
import asyncio
import os
from datetime import datetime
from dotenv import load_dotenv
import uuid
import time
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, scrolledtext
from tkcalendar import DateEntry
import json
import re
from playwright.sync_api import sync_playwright

# --- Load secrets from .secrets file ---
load_dotenv(".secrets")

# --- Configuration from environment variables ---
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")
BROWSER = os.getenv("CHROME_PATH")

# --- Constants ---
DASHBOARD_STORE = "dashboards.json"

# --- UI Helpers ---
def create_output_dir():
    today = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join("screenshots", today)
    os.makedirs(path, exist_ok=True)
    return path

def save_dashboards(dashboards):
    with open(DASHBOARD_STORE, "w") as f:
        json.dump(dashboards, f, indent=2)

def load_dashboards():
    if os.path.exists(DASHBOARD_STORE):
        with open(DASHBOARD_STORE, "r") as f:
            return json.load(f)
    return []

def take_screenshot_sync(dashboard_url, key="dashboard"):
    snip_save_dir = create_output_dir()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, executable_path=BROWSER)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()
        page.set_default_timeout(30000)

        print("\n" + "*" * 80)
        print(f"Capturing snip from dashboard: {key}")
        page.goto(dashboard_url)
        page.wait_for_load_state("networkidle")

        # Attempt login if login form is visible
        try:
            page.fill('input[name="username"]', USERNAME)
            page.fill('input[name="password"]', PASSWORD)
            page.click('input[value="Sign In"]')
            print("Splunk login successful")
            page.wait_for_load_state("networkidle")
        except Exception as e:
            print("Login skipped or failed:", e)

        print("Dashboard launched, waiting for panels to load...")
        time.sleep(60)

        try:
            page.wait_for_selector("div.main-section-body.dashboard-body")
            dashboard_element = page.query_selector("div.main-section-body.dashboard-body")
            page.evaluate("""
                el => {
                    let current = el;
                    while (current) {
                        current.style.height = current.scrollHeight + 'px';
                        current = current.parentElement;
                    }
                }
            """, dashboard_element)
        except:
            print("Could not adjust height automatically.")

        unique_id = uuid.uuid4().hex[:8]
        file_name = f"screenshot_{key}_{unique_id}.png"
        screenshot_path = os.path.join(snip_save_dir, file_name)
        page.screenshot(path=screenshot_path, full_page=True)
        print(f"✅ Screenshot saved to {screenshot_path}")

        browser.close()

# --- GUI ---
def run_gui():
    dashboards = load_dashboards()

    def add_dashboard():
        name = simpledialog.askstring("Dashboard Name", "Enter name/label for the dashboard:")
        url = simpledialog.askstring("Dashboard URL", "Enter Splunk dashboard URL:")
        if name and url:
            dashboards.append({"name": name.strip(), "url": url.strip()})
            save_dashboards(dashboards)
            refresh_list()

    def delete_selected():
        selected = listbox.curselection()
        if not selected:
            messagebox.showinfo("No Selection", "Select dashboards to delete.")
            return
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected dashboards?"):
            for i in reversed(selected):
                dashboards.pop(i)
            save_dashboards(dashboards)
            refresh_list()

    def analyze_selected():
        selected = listbox.curselection()
        if not selected:
            messagebox.showinfo("No Selection", "Select at least one dashboard to analyze.")
            return

        popup = tk.Toplevel()
        popup.title("Select Time Range")
        popup.geometry("300x150")

        tk.Label(popup, text="Start Date").grid(row=0, column=0, pady=5)
        start_date = DateEntry(popup)
        start_date.grid(row=0, column=1, pady=5)

        tk.Label(popup, text="Start Time (HH:MM)").grid(row=1, column=0, pady=5)
        start_time = tk.Entry(popup)
        start_time.grid(row=1, column=1, pady=5)

        tk.Label(popup, text="End Date").grid(row=2, column=0, pady=5)
        end_date = DateEntry(popup)
        end_date.grid(row=2, column=1, pady=5)

        tk.Label(popup, text="End Time (HH:MM)").grid(row=3, column=0, pady=5)
        end_time = tk.Entry(popup)
        end_time.grid(row=3, column=1, pady=5)

        def submit():
            try:
                start_ts = f"{start_date.get()} {start_time.get()}"
                end_ts = f"{end_date.get()} {end_time.get()}"
                datetime.strptime(start_ts, "%Y-%m-%d %H:%M")
                datetime.strptime(end_ts, "%Y-%m-%d %H:%M")
                popup.destroy()

                for i in selected:
                    dash = dashboards[i]
                    take_screenshot_sync(dash["url"], key=dash["name"])
            except ValueError:
                messagebox.showerror("Invalid Format", "Enter time in HH:MM format.")

        tk.Button(popup, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)
        popup.grab_set()

    def refresh_list():
        listbox.delete(0, tk.END)
        for dash in dashboards:
            listbox.insert(tk.END, dash["name"])

    root = tk.Tk()
    root.title("Splunk Dashboard Client")
    root.geometry("600x400")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    add_btn = tk.Button(frame, text="Add Dashboard", command=add_dashboard)
    add_btn.grid(row=0, column=0, padx=5)

    del_btn = tk.Button(frame, text="Delete Selected", command=delete_selected)
    del_btn.grid(row=0, column=1, padx=5)

    analyze_btn = tk.Button(frame, text="Analyze Selected", command=analyze_selected)
    analyze_btn.grid(row=0, column=2, padx=5)

    listbox = tk.Listbox(root, selectmode=tk.MULTIPLE, width=70, height=15)
    listbox.pack(padx=10, pady=10)

    refresh_list()
    root.mainloop()

# --- Entry Point ---
if __name__ == "__main__":
    run_gui()
