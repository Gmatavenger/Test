import requests
import asyncio
import os
import json
from playwright.async_api import async_playwright
from datetime import datetime
from dotenv import load_dotenv

# --- Load secrets from .secrets file ---
load_dotenv(".secrets")

# --- Configuration from environment variables ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_APP = os.getenv("SPLUNK_APP", "search")
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")

# --- Dashboard Storage ---
DASHBOARD_STORE = "dashboards.json"

def load_dashboards():
    if os.path.exists(DASHBOARD_STORE):
        with open(DASHBOARD_STORE, "r") as f:
            return json.load(f)
    return []

def save_dashboards(dashboards):
    with open(DASHBOARD_STORE, "w") as f:
        json.dump(dashboards, f, indent=2)

def add_dashboard():
    name = input("Enter dashboard name: ").strip()
    url = input("Enter dashboard URL: ").strip()
    if not name or not url:
        print("❌ Both name and URL are required.")
        return
    dashboards = load_dashboards()
    if any(d["name"] == name for d in dashboards):
        print("❌ Dashboard with that name already exists.")
        return
    dashboards.append({"name": name, "url": url})
    save_dashboards(dashboards)
    print(f"✅ Added dashboard '{name}'")

def delete_dashboard():
    dashboards = load_dashboards()
    if not dashboards:
        print("No dashboards to delete.")
        return
    print("Available Dashboards:")
    for i, dash in enumerate(dashboards):
        print(f"{i + 1}. {dash['name']} - {dash['url']}")
    try:
        idx = int(input("Enter the number of the dashboard to delete: ")) - 1
        if 0 <= idx < len(dashboards):
            confirm = input(f"Are you sure you want to delete '{dashboards[idx]['name']}'? (y/n): ")
            if confirm.lower() == 'y':
                removed = dashboards.pop(idx)
                save_dashboards(dashboards)
                print(f"✅ Deleted dashboard '{removed['name']}'")
            else:
                print("Cancelled deletion.")
        else:
            print("❌ Invalid index.")
    except ValueError:
        print("❌ Invalid input.")

# --- Use Playwright to Login & Screenshot ---
async def take_screenshot(name, url, username, password, output_dir="screenshots"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"screenshot_{name}_{timestamp}.png"
    path = os.path.join(output_dir, filename)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(url, timeout=30000)
            if await page.query_selector('input[name="username"]'):
                await page.fill('input[name="username"]', username)
                await page.fill('input[name="password"]', password)
                await page.click('button[type="submit"]')
                await page.wait_for_load_state("networkidle")

            await page.wait_for_timeout(3000)
            await page.screenshot(path=path, full_page=True)
            print(f"✅ Screenshot saved to {path}")

        except Exception as e:
            print(f"❌ Error during screenshot: {e}")
        finally:
            await browser.close()

# --- Main ---
def main():
    while True:
        print("\n--- Splunk Dashboard Screenshot Tool ---")
        print("1. Add Dashboard")
        print("2. Delete Dashboard")
        print("3. Capture Dashboard Screenshot")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_dashboard()
        elif choice == "2":
            delete_dashboard()
        elif choice == "3":
            dashboards = load_dashboards()
            if not dashboards:
                print("No dashboards available.")
                continue
            print("Available Dashboards:")
            for i, dash in enumerate(dashboards):
                print(f"{i + 1}. {dash['name']}")
            try:
                idx = int(input("Select a dashboard to capture: ")) - 1
                if 0 <= idx < len(dashboards):
                    dash = dashboards[idx]
                    asyncio.run(take_screenshot(dash['name'], dash['url'], USERNAME, PASSWORD))
                else:
                    print("❌ Invalid selection.")
            except ValueError:
                print("❌ Invalid input.")
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
