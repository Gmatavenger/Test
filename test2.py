import requests
import asyncio
import os
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
DASHBOARD_NAME = os.getenv("DASHBOARD_NAME")

# Disable SSL warnings (optional for dev)
requests.packages.urllib3.disable_warnings()

# --- Get Dashboard URL from Splunk REST API ---
def get_dashboard_url(dashboard_name, username, password):
    api_url = f"{SPLUNK_HOST}/servicesNS/{username}/{SPLUNK_APP}/data/ui/views/{dashboard_name}?output_mode=json"
    try:
        response = requests.get(api_url, auth=(username, password), verify=False)
        response.raise_for_status()
        data = response.json()
        if data.get("entry"):
            return f"{SPLUNK_HOST}/en-US/app/{SPLUNK_APP}/{dashboard_name}"
        else:
            raise Exception("Dashboard not found.")
    except Exception as e:
        print(f"Error fetching dashboard URL: {e}")
        return None

# --- Use Playwright to Login & Screenshot ---
async def take_screenshot(url, username, password, output_dir="screenshots"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"screenshot_{DASHBOARD_NAME}_{timestamp}.png"
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

            await page.wait_for_timeout(3000)  # allow rendering
            await page.screenshot(path=path, full_page=True)
            print(f"✅ Screenshot saved to {path}")

        except Exception as e:
            print(f"❌ Error during screenshot: {e}")
        finally:
            await browser.close()

# --- Main ---
if __name__ == "__main__":
    dashboard_url = get_dashboard_url(DASHBOARD_NAME, USERNAME, PASSWORD)
    if dashboard_url:
        print(f"Dashboard URL: {dashboard_url}")
        asyncio.run(take_screenshot(dashboard_url, USERNAME, PASSWORD))
    else:
        print("❌ Could not get dashboard URL.")
