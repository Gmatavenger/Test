import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, scrolledtext
from tkcalendar import DateEntry
import json, os, asyncio, re, uuid, signal, sys
from urllib.parse import urlparse
from datetime import datetime, timezone
from threading import Thread
from playwright.async_api import async_playwright

# ========== Session Config ==========
session_cache = {
    "splunk_username": None,
    "splunk_password": None,
    "onboarded_dashboards": [],
}
DASHBOARD_STORE = "dashboards.json"
SCREENSHOT_DIR = os.path.join("screenshots", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
VALID_URL_REGEX = re.compile(r'^https?://.+')

def graceful_shutdown(*_):
    clear_credentials()
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

# ========== Utils ==========
def sanitize_filename(url):
    netloc = urlparse(url).netloc.replace('.', '_')
    uid = uuid.uuid4().hex[:6]
    return f"{netloc}_{uid}"

def clear_credentials():
    session_cache["splunk_username"] = None
    session_cache["splunk_password"] = None

def load_dashboards():
    if os.path.exists(DASHBOARD_STORE):
        with open(DASHBOARD_STORE, "r") as f:
            session_cache["onboarded_dashboards"] = json.load(f)

def save_dashboards():
    with open(DASHBOARD_STORE, "w") as f:
        json.dump(session_cache["onboarded_dashboards"], f, indent=2)

# ========== GUI Actions ==========
def add_dashboard():
    name = simpledialog.askstring("Dashboard Name", "Enter a name:")
    url = simpledialog.askstring("Dashboard URL", "Enter the URL:")
    if not name or not url:
        return
    if not VALID_URL_REGEX.match(url):
        messagebox.showerror("Invalid URL", "URL must start with http or https.")
        return
    if any(d["name"] == name for d in session_cache["onboarded_dashboards"]):
        messagebox.showerror("Duplicate", "Dashboard name already exists.")
        return
    session_cache["onboarded_dashboards"].append({"name": name.strip(), "url": url.strip()})
    save_dashboards()
    refresh_dashboard_list()

def delete_dashboard():
    selected = dashboards_box.curselection()
    if not selected:
        messagebox.showinfo("Select", "Select a dashboard to delete.")
        return
    name = dashboards_box.get(selected[0])
    if messagebox.askyesno("Confirm Delete", f"Delete dashboard '{name}'?"):
        session_cache["onboarded_dashboards"] = [
            d for d in session_cache["onboarded_dashboards"] if d["name"] != name
        ]
        save_dashboards()
        refresh_dashboard_list()

def refresh_dashboard_list():
    dashboards_box.delete(0, tk.END)
    for entry in session_cache["onboarded_dashboards"]:
        dashboards_box.insert(tk.END, entry["name"])

def analyze_selected():
    selected = [dashboards_box.get(i) for i in dashboards_box.curselection()]
    if not selected:
        messagebox.showwarning("Select Dashboard", "Select one or more dashboards.")
        return

    def get_time_range():
        popup = tk.Toplevel()
        popup.title("Select Time Range")
        result = {}

        tk.Label(popup, text="Start Date:").grid(row=0, column=0)
        start_date = DateEntry(popup)
        start_date.grid(row=0, column=1)

        tk.Label(popup, text="Start Time (HH:MM):").grid(row=1, column=0)
        start_time = tk.Entry(popup)
        start_time.grid(row=1, column=1)

        tk.Label(popup, text="End Date:").grid(row=2, column=0)
        end_date = DateEntry(popup)
        end_date.grid(row=2, column=1)

        tk.Label(popup, text="End Time (HH:MM):").grid(row=3, column=0)
        end_time = tk.Entry(popup)
        end_time.grid(row=3, column=1)

        def submit():
            try:
                start_str = f"{start_date.get_date():%Y-%m-%d} {start_time.get()}"
                end_str = f"{end_date.get_date():%Y-%m-%d} {end_time.get()}"
                datetime.strptime(start_str, "%Y-%m-%d %H:%M")
                datetime.strptime(end_str, "%Y-%m-%d %H:%M")
                result["start"] = start_str
                result["end"] = end_str
                popup.withdraw()
                popup.after(100, popup.destroy)
            except ValueError:
                messagebox.showerror("Invalid", "Time must be in HH:MM format.")

        tk.Button(popup, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)
        popup.grab_set()
        popup.wait_window()
        return result.get("start"), result.get("end")

    start, end = get_time_range()
    if not start or not end:
        return

    selected_urls = [d["url"] for d in session_cache["onboarded_dashboards"] if d["name"] in selected]

    def run():
        try:
            asyncio.run(run_all_dashboards(selected_urls, start, end))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    Thread(target=run).start()

# ========== LLM Summary ==========
def show_results_summary(messages):
    popup = tk.Toplevel()
    popup.title("LLM Summary")
    text = scrolledtext.ScrolledText(popup, wrap=tk.WORD, width=80, height=20)
    text.pack(padx=10, pady=10)
    for m in messages:
        text.insert(tk.END, m + "\n\n")
    text.config(state=tk.DISABLED)
    tk.Button(popup, text="Close", command=popup.destroy).pack(pady=5)

# ========== Async Processing ==========
async def run_all_dashboards(urls, start, end):
    messages = []
    results = await asyncio.gather(*(process_dashboard(u, start, end) for u in urls), return_exceptions=True)
    for res in results:
        messages.append(str(res))
    show_results_summary(messages)
    clear_credentials()

async def process_dashboard(url, start, end):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        screenshot_path = None

        try:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(2000)

            # Dynamic login detection
            username_selector = 'input[placeholder="Username"]'
            password_selector = 'input[placeholder="Password"]'
            login_button_selector = 'button[type="submit"], input[type="submit"], button:has-text("Sign In")'

            if await page.query_selector(username_selector) and await page.query_selector(password_selector):
                if not session_cache["splunk_username"] or not session_cache["splunk_password"]:
                    session_cache["splunk_username"] = simpledialog.askstring("Login", "Username:")
                    session_cache["splunk_password"] = simpledialog.askstring("Login", "Password:", show="*")

                await page.fill(username_selector, session_cache["splunk_username"])
                await page.fill(password_selector, session_cache["splunk_password"])
                await page.click(login_button_selector)
                await page.wait_for_load_state("networkidle")
                await page.wait_for_timeout(2000)

            # Screenshot
            safe_name = sanitize_filename(url)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe_name}_{timestamp}.png")
            await page.screenshot(path=screenshot_path, full_page=True)

        except Exception as e:
            return f"❌ Failed {url}: {str(e)}"
        finally:
            await browser.close()

        return f"✅ Analyzed {url} from {start} to {end}. Screenshot saved to {screenshot_path}"

# ========== GUI Setup ==========
root = tk.Tk()
root.title("Splunk Dashboard Analyzer")
root.geometry("650x480")

ttk.Button(root, text="Add Dashboard", command=add_dashboard).pack(pady=5)
ttk.Button(root, text="Delete Dashboard", command=delete_dashboard).pack(pady=5)

dashboards_box = tk.Listbox(root, selectmode=tk.MULTIPLE, width=80, height=10)
dashboards_box.pack(pady=10)
load_dashboards()
refresh_dashboard_list()

ttk.Button(root, text="Analyze Selected Dashboards", command=analyze_selected).pack(pady=10)

root.mainloop()
