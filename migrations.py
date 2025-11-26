import os
import psycopg2
from contextlib import contextmanager

# Database connection context manager (mirrors bot.py's implementation)
@contextmanager
def db_connection():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("⚠️ DATABASE_URL not set, skipping migrations")
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

def run_migrations():
    """
    Run database migrations to ensure schema is up to date.
    Safe to run on every startup (idempotent).
    """
    print("🔄 Checking database schema...")
    
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                # 1. Create time_adjustment_requests table
                print("   Checking table: time_adjustment_requests")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS time_adjustment_requests (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        user_id BIGINT NOT NULL,
                        request_type TEXT NOT NULL,
                        original_session_id INTEGER,
                        original_clock_in TIMESTAMPTZ,
                        original_clock_out TIMESTAMPTZ,
                        original_duration INTEGER,
                        requested_clock_in TIMESTAMPTZ,
                        requested_clock_out TIMESTAMPTZ,
                        reason TEXT,
                        status TEXT NOT NULL DEFAULT 'pending',
                        reviewed_by BIGINT,
                        reviewed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                
                # Add index for faster pending request lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_adjustment_requests_guild_status 
                    ON time_adjustment_requests(guild_id, status)
                """)

                # 2. Create user_preferences table
                print("   Checking table: user_preferences")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_preferences (
                        user_id BIGINT PRIMARY KEY,
                        dashboard_timezone TEXT,
                        timezone_configured BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                
                # 3. Create adjustment_audit_log table (for premium features)
                print("   Checking table: adjustment_audit_log")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS adjustment_audit_log (
                        id SERIAL PRIMARY KEY,
                        request_id INTEGER REFERENCES time_adjustment_requests(id),
                        action TEXT NOT NULL, -- 'approved', 'denied', 'cancelled'
                        actor_id BIGINT NOT NULL,
                        timestamp TIMESTAMPTZ DEFAULT NOW(),
                        details JSONB
                    )
                """)

        print("✅ Database schema is up to date")
        return True

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        # Don't crash the app, but log the error clearly
        return False

if __name__ == "__main__":
    # Allow running migrations directly for testing
    run_migrations()
