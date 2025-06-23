import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, scrolledtext
from tkcalendar import DateEntry
import json, os, asyncio, re, uuid, signal, sys
from urllib.parse import urlparse
from datetime import datetime, timezone
from threading import Thread
from playwright.async_api import async_playwright

# Session Cache and Paths
session_cache = {
    "splunk_username": None,
    "splunk_password": None,
    "onboarded_dashboards": [],
}

DASHBOARD_STORE = "dashboards.json"
SCREENSHOT_DIR_BASE = "screenshots"
SCREENSHOT_DIR = os.path.join(SCREENSHOT_DIR_BASE, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def graceful_shutdown(*args):
    clear_credentials()
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

def clear_credentials():
    session_cache["splunk_username"] = None
    session_cache["splunk_password"] = None

def sanitize_filename(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.replace('.', '_')
    return f"{netloc}_{uuid.uuid4().hex[:8]}"

def load_dashboards():
    if os.path.exists(DASHBOARD_STORE):
        with open(DASHBOARD_STORE, "r") as f:
            session_cache["onboarded_dashboards"] = json.load(f)

def save_dashboards():
    with open(DASHBOARD_STORE, "w") as f:
        json.dump(session_cache["onboarded_dashboards"], f, indent=2)

def refresh_dashboard_list():
    dashboards_box.delete(0, tk.END)
    for entry in session_cache["onboarded_dashboards"]:
        dashboards_box.insert(tk.END, entry["name"])

def add_dashboard():
    name = simpledialog.askstring("Dashboard Name", "Enter dashboard name:")
    url = simpledialog.askstring("Dashboard URL", "Enter dashboard URL:")
    if not name or not url or not re.match(r'^https?://', url):
        messagebox.showerror("Invalid", "Provide valid name and URL.")
        return
    if any(d["name"] == name for d in session_cache["onboarded_dashboards"]):
        messagebox.showerror("Duplicate", "Dashboard already added.")
        return
    session_cache["onboarded_dashboards"].append({"name": name, "url": url})
    save_dashboards()
    refresh_dashboard_list()

def delete_dashboard():
    selected = [dashboards_box.get(i) for i in dashboards_box.curselection()]
    if not selected:
        messagebox.showwarning("No Selection", "Please select a dashboard to delete.")
        return
    for name in selected:
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{name}'?")
        if confirm:
            session_cache["onboarded_dashboards"] = [
                d for d in session_cache["onboarded_dashboards"] if d["name"] != name
            ]
            save_dashboards()
            refresh_dashboard_list()
            messagebox.showinfo("Deleted", f"'{name}' has been deleted.")

def prompt_login():
    win = tk.Toplevel(root)
    win.title("Splunk Login")
    tk.Label(win, text="Username").grid(row=0, column=0)
    tk.Label(win, text="Password").grid(row=1, column=0)
    user = tk.Entry(win)
    pwd = tk.Entry(win, show="*")
    user.grid(row=0, column=1)
    pwd.grid(row=1, column=1)

    def submit():
        session_cache["splunk_username"] = user.get()
        session_cache["splunk_password"] = pwd.get()
        win.destroy()
        messagebox.showinfo("Success", "Credentials saved.")

    tk.Button(win, text="Submit", command=submit).grid(row=2, column=0, columnspan=2)
    win.grab_set()
    win.wait_window()

def analyze_selected():
    selected_names = [dashboards_box.get(i) for i in dashboards_box.curselection()]
    if not selected_names:
        messagebox.showwarning("Select dashboards", "Choose at least one dashboard.")
        return

    def ask_time():
        top = tk.Toplevel(root)
        top.title("Select Time Range")

        tk.Label(top, text="Start Date").grid(row=0, column=0)
        tk.Label(top, text="Start Time (HH:MM)").grid(row=1, column=0)
        tk.Label(top, text="End Date").grid(row=2, column=0)
        tk.Label(top, text="End Time (HH:MM)").grid(row=3, column=0)

        s_date = DateEntry(top, date_pattern="yyyy-mm-dd")
        s_time = tk.Entry(top)
        e_date = DateEntry(top, date_pattern="yyyy-mm-dd")
        e_time = tk.Entry(top)
        s_date.grid(row=0, column=1)
        s_time.grid(row=1, column=1)
        e_date.grid(row=2, column=1)
        e_time.grid(row=3, column=1)

        result = {}

        def validate_time(t):
            t = t.strip()
            if re.match(r"^\d{1,2}:\d{2}$", t):
                h, m = map(int, t.split(":"))
                if 0 <= h < 24 and 0 <= m < 60:
                    return f"{h:02}:{m:02}"
            raise ValueError("Time must be in HH:MM format (24-hr)")

        def submit():
            try:
                start_time = validate_time(s_time.get())
                end_time = validate_time(e_time.get())
                start_str = f"{s_date.get()} {start_time}"
                end_str = f"{e_date.get()} {end_time}"
                result['start'] = datetime.strptime(start_str, "%Y-%m-%d %H:%M")
                result['end'] = datetime.strptime(end_str, "%Y-%m-%d %H:%M")
                if result['end'] <= result['start']:
                    raise ValueError("End time must be after start time.")
                top.destroy()
            except Exception as ex:
                messagebox.showerror("Invalid Input", str(ex))

        tk.Button(top, text="Submit", command=submit).grid(row=4, columnspan=2)
        top.grab_set()
        top.wait_window()
        return result.get("start"), result.get("end")

    start, end = ask_time()
    if not start or not end:
        return

    selected_urls = [d["url"] for d in session_cache["onboarded_dashboards"] if d["name"] in selected_names]

    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_all_dashboards(selected_urls, start, end))

    Thread(target=run_async).start()

async def run_all_dashboards(urls, start, end):
    messages = []
    results = await asyncio.gather(*[process_dashboard(url, start, end) for url in urls])
    for msg in results:
        if msg:
            messages.append(msg)
    if messages:
        show_results_summary("LLM Summary", messages)

def show_results_summary(title, messages):
    win = tk.Toplevel(root)
    win.title(title)
    txt = scrolledtext.ScrolledText(win, width=80, height=25)
    txt.pack()
    for m in messages:
        txt.insert(tk.END, m + "\n\n")
    txt.config(state=tk.DISABLED)

async def process_dashboard(url, start_time, end_time):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        screenshot_file = None
        try:
            await page.goto(url, wait_until="networkidle")
            if session_cache["splunk_username"]:
                await page.fill("input[name='username']", session_cache["splunk_username"])
                await page.fill("input[name='password']", session_cache["splunk_password"])
                await page.click("button[type='submit']")
                await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(3000)
            filename = f"{sanitize_filename(url)}.png"
            screenshot_file = os.path.join(SCREENSHOT_DIR, filename)
            await page.screenshot(path=screenshot_file, full_page=True)
        except Exception as e:
            return f"❌ Error: {url} — {str(e)}"
        finally:
            await browser.close()

        return f"✅ {url} analyzed from {start_time} to {end_time}.\nScreenshot saved at: {screenshot_file}"

# GUI Setup
root = tk.Tk()
root.title("Splunk Dashboard Analyzer")
root.geometry("600x400")

load_dashboards()

btn_frame = ttk.Frame(root)
btn_frame.pack(pady=5)

ttk.Button(btn_frame, text="Add Dashboard", command=add_dashboard).grid(row=0, column=0, padx=5)
ttk.Button(btn_frame, text="Delete Dashboard", command=delete_dashboard).grid(row=0, column=1, padx=5)
ttk.Button(btn_frame, text="Login to Splunk", command=prompt_login).grid(row=0, column=2, padx=5)

dashboards_box = tk.Listbox(root, selectmode=tk.MULTIPLE, width=80, height=10)
dashboards_box.pack(pady=10)
refresh_dashboard_list()

ttk.Button(root, text="Analyze Selected Dashboards", command=analyze_selected).pack(pady=10)

root.mainloop()
