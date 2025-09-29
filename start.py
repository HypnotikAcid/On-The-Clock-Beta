#!/usr/bin/env python3
"""
Startup script to run the Discord bot only.
Dashboard removed - bot-only mode.
"""
import os
import subprocess
import sys
import signal

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully."""
    print("\n🛑 Shutting down bot...")
    os._exit(0)

def main():
    """Main startup function for Discord bot only."""
    print("🚀 Starting On the Clock Discord Bot...")
    print("=" * 60)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("🤖 Starting Discord Bot with 24 slash commands...")
    
    try:
        # Run Discord bot directly
        result = subprocess.run([sys.executable, "bot.py"], 
                              capture_output=False, 
                              text=True)
        if result.returncode != 0:
            print(f"❌ Discord bot exited with code {result.returncode}")
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
    except Exception as e:
        print(f"❌ Error running Discord bot: {e}")
    finally:
        print("👋 Bot stopped")

if __name__ == "__main__":
    main()