#!/usr/bin/env python3
"""
Startup script to run both Discord bot and Flask web app simultaneously.
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

def run_flask_app():
    """Run the Flask web application."""
    print("🌐 Starting Flask Web App...")
    try:
        # Import and run the Flask app
        from app import app
        
        # Run Flask on port 5000 (the only exposed port)
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except Exception as e:
        print(f"❌ Error running Flask app: {e}")

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully."""
    print("\n🛑 Shutting down services...")
    os._exit(0)

def main():
    """Main startup function."""
    print("🚀 Starting On the Clock Dashboard & Bot Services...")
    print("=" * 60)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start Discord bot in background thread
    bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
    bot_thread.start()
    
    # Give bot a moment to start
    time.sleep(2)
    
    # Run Flask app in main thread (blocks until exit)
    print("🌐 Flask app will handle web dashboard on port 5000")
    print("🤖 Discord bot running in background")
    print("=" * 60)
    
    try:
        run_flask_app()
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        print("👋 Services stopped")

if __name__ == "__main__":
    main()