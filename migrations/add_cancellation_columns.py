import os
import psycopg2
from contextlib import contextmanager

@contextmanager
def db_connection():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL not set, skipping cancellation columns migration locally.")
        yield None
        return

    conn = psycopg2.connect(database_url)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def run_cancellation_migration():
    """Add cancel_at_period_end and current_period_end to server_subscriptions"""
    print("Checking for cancellation columns in server_subscriptions...")
    try:
        with db_connection() as conn:
            if not conn:
                return False
                
            with conn.cursor() as cur:
                # Add cancel_at_period_end
                try:
                    cur.execute("""
                        ALTER TABLE server_subscriptions 
                        ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN DEFAULT FALSE
                    """)
                    print("Added/verified cancel_at_period_end column.")
                except Exception as e:
                    print(f"Error adding cancel_at_period_end: {e}")
                    
                # Add current_period_end
                try:
                    cur.execute("""
                        ALTER TABLE server_subscriptions 
                        ADD COLUMN IF NOT EXISTS current_period_end BIGINT
                    """)
                    print("Added/verified current_period_end column.")
                except Exception as e:
                    print(f"Error adding current_period_end: {e}")
                    
        print("Cancellation columns migration complete!")
        return True
    except Exception as e:
        print(f"Migration failed: {e}")
        return False

if __name__ == "__main__":
    run_cancellation_migration()
