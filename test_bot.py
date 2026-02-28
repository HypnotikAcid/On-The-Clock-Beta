import requests
import os
import sys

BOT_PORT = os.environ.get("BOT_API_PORT", "8081")
BOT_SECRET = os.environ.get("BOT_API_SECRET", "")

urls = [
    f"http://127.0.0.1:{BOT_PORT}/health",
    f"http://127.0.0.1:{BOT_PORT}/api/guild/1419894879894507661/channels"
]

for url in urls:
    try:
        print(f"Testing {url}...")
        resp = requests.get(url, headers={"Authorization": f"Bearer {BOT_SECRET}"})
        print(f"[{resp.status_code}] {resp.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")
