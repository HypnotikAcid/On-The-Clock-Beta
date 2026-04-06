import sys
import traceback
import warnings
warnings.filterwarnings('ignore')

print("--- Testing discord_runner.py ---")
try:
    import discord_runner
    print("SUCCESS: discord_runner imported without errors.")
except Exception as e:
    print("ERROR: Failed to import discord_runner:")
    traceback.print_exc()

print("\n--- Testing app.py (Flask routes) ---")
try:
    import app
    print("SUCCESS: app.py imported without errors.")
except Exception as e:
    print("ERROR: Failed to import app.py:")
    traceback.print_exc()
