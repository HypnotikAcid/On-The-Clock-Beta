#!/usr/bin/env python3
"""
Startup script to run Discord bot and simple landing page.
Landing page only - no authentication complexity.
"""
import os
import subprocess
import threading
import time
import signal
import sys

def run_discord_bot():
    """Run the Discord bot in a separate thread."""
    print("🤖 Starting Discord Bot...")
    try:
        result = subprocess.run([sys.executable, "bot.py"], 
                              capture_output=False, 
                              text=True)
        if result.returncode != 0:
            print(f"❌ Discord bot exited with code {result.returncode}")
    except Exception as e:
        print(f"❌ Error running Discord bot: {e}")

def run_landing_page():
    """Run the Flask app with Gunicorn production server."""
    print("🌐 Starting Landing Page with Gunicorn...")
    try:
        # Run Gunicorn with proper configuration
        result = subprocess.run([
            "gunicorn", 
            "app:app",
            "--bind", "0.0.0.0:5000",
            "--workers", "2",
            "--timeout", "120",
            "--access-logfile", "-",
            "--error-logfile", "-"
        ], capture_output=False, text=True)
        
        if result.returncode != 0:
            print(f"❌ Gunicorn exited with code {result.returncode}")
    except Exception as e:
        print(f"❌ Error running Gunicorn: {e}")

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully."""
    print("\n🛑 Shutting down services...")
    os._exit(0)

def main():
    """Main startup function."""
    print("🚀 Starting On the Clock Bot & Landing Page...")
    print("=" * 60)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start Discord bot in background thread
    bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
    bot_thread.start()
    
    # Give bot a moment to start
    time.sleep(2)
    
    # Run landing page in main thread (blocks until exit)
    print("🌐 Landing page will be available on port 5000")
    print("🤖 Discord bot running in background")
    print("=" * 60)
    
    try:
        run_landing_page()
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        print("👋 Services stopped")

if __name__ == "__main__":
    main()