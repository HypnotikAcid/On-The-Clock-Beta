import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def reset_all_onboarding():
    print("Connecting to database to reset onboarding...")
    try:
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        cur = conn.cursor()
        
        cur.execute("UPDATE guild_settings SET has_completed_onboarding = FALSE;")
        updated_rows = cur.rowcount
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"Success! Reset onboarding for {updated_rows} servers.")
    except Exception as e:
        print(f"Error resetting onboarding: {e}")

if __name__ == "__main__":
    reset_all_onboarding()
