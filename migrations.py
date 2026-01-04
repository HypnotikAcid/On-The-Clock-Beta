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
                
                # 4. Create employee_profiles table (employee & admin profiles)
                print("   Checking table: employee_profiles")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS employee_profiles (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        user_id BIGINT NOT NULL,
                        role_tier VARCHAR(20) DEFAULT 'employee',
                        
                        -- Profile data
                        first_name VARCHAR(100),
                        last_name VARCHAR(100),
                        date_of_birth DATE,
                        email VARCHAR(255),
                        bio TEXT,
                        avatar_choice VARCHAR(50) DEFAULT 'random',
                        custom_avatar_url TEXT,
                        company_role VARCHAR(100),
                        
                        -- Privacy toggles (all default TRUE)
                        show_last_seen BOOLEAN DEFAULT TRUE,
                        show_discord_status BOOLEAN DEFAULT TRUE,
                        
                        -- Employee premium settings
                        email_timesheets BOOLEAN DEFAULT FALSE,
                        timesheet_email VARCHAR(255),
                        
                        -- Metadata
                        hire_date TIMESTAMPTZ DEFAULT NOW(),
                        last_seen_discord TIMESTAMPTZ,
                        profile_setup_completed BOOLEAN DEFAULT FALSE,
                        profile_sent_on_first_clockin BOOLEAN DEFAULT FALSE,
                        is_active BOOLEAN DEFAULT TRUE,
                        updated_at TIMESTAMPTZ DEFAULT NOW(),
                        
                        UNIQUE(guild_id, user_id)
                    )
                """)
                
                # Index for composite lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_employee_profiles_guild_user 
                    ON employee_profiles(guild_id, user_id)
                """)
                
                # Index for active employees
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_employee_profiles_active 
                    ON employee_profiles(guild_id, is_active)
                """)
                
                # Add missing columns to employee_profiles (for GitHub sync compatibility)
                # These are idempotent - will do nothing if columns already exist
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS full_name VARCHAR(200)
                    """)
                except Exception:
                    pass  # Column may already exist
                    
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS display_name VARCHAR(100)
                    """)
                except Exception:
                    pass  # Column may already exist
                    
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS avatar_url TEXT
                    """)
                except Exception:
                    pass  # Column may already exist
                    
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS position VARCHAR(100)
                    """)
                except Exception:
                    pass  # Column may already exist
                    
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS department VARCHAR(100)
                    """)
                except Exception:
                    pass  # Column may already exist
                    
                try:
                    cur.execute("""
                        ALTER TABLE employee_profiles 
                        ADD COLUMN IF NOT EXISTS discord_status VARCHAR(20) DEFAULT 'offline'
                    """)
                except Exception:
                    pass  # Column may already exist
                
                # 5. Create employee_profile_tokens table
                print("   Checking table: employee_profile_tokens")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS employee_profile_tokens (
                        token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        guild_id BIGINT NOT NULL,
                        user_id BIGINT NOT NULL,
                        delivery_method VARCHAR(20) DEFAULT 'ephemeral',
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),
                        used_at TIMESTAMPTZ,
                        draft_data JSONB
                    )
                """)
                
                # Index for token lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_profile_tokens_user 
                    ON employee_profile_tokens(guild_id, user_id)
                """)
                
                # 6. Create employee_archive table (PREMIUM FEATURE)
                print("   Checking table: employee_archive")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS employee_archive (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        user_id BIGINT NOT NULL,
                        profile_snapshot JSONB,
                        hire_date TIMESTAMPTZ,
                        termination_date TIMESTAMPTZ DEFAULT NOW(),
                        termination_reason VARCHAR(20),
                        admin_notes TEXT,
                        archived_by BIGINT,
                        reactivated_at TIMESTAMPTZ,
                        reactivated_by BIGINT,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                
                # Index for archive lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_employee_archive_guild_user 
                    ON employee_archive(guild_id, user_id)
                """)
                
                # 7. Create guild_transfers table (future premium feature)
                print("   Checking table: guild_transfers")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS guild_transfers (
                        id SERIAL PRIMARY KEY,
                        from_guild_id BIGINT NOT NULL,
                        to_guild_id BIGINT NOT NULL,
                        requested_by BIGINT NOT NULL,
                        fee_paid DECIMAL(10,2) DEFAULT 10.00,
                        transfer_data JSONB,
                        completed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                # Add missing columns to employee_profiles if they don't exist
                print("   Checking for missing columns in employee_profiles")
                alter_queries = [
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS full_name TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS display_name TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS position TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS department TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS discord_status TEXT"
                ]
                for query in alter_queries:
                    cur.execute(query)
                
                # 8. Add session_date column to time_adjustment_requests for calendar views
                print("   Checking for calendar enhancement columns")
                calendar_enhancements = [
                    "ALTER TABLE time_adjustment_requests ADD COLUMN IF NOT EXISTS session_date DATE",
                    "ALTER TABLE time_adjustment_requests ADD COLUMN IF NOT EXISTS admin_notes TEXT",
                    "ALTER TABLE time_adjustment_requests ADD COLUMN IF NOT EXISTS calculated_duration INTEGER"
                ]
                for query in calendar_enhancements:
                    cur.execute(query)
                
                # Add index for calendar date lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_adjustment_requests_calendar 
                    ON time_adjustment_requests(guild_id, user_id, session_date, status)
                """)
                
                # Add index for user history lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_adjustment_requests_user_history 
                    ON time_adjustment_requests(guild_id, user_id, created_at DESC)
                """)
                
                # 9. Add is_present and left_at columns to bot_guilds for tracking inactive servers
                print("   Checking for bot_guilds presence tracking columns")
                bot_guilds_enhancements = [
                    "ALTER TABLE bot_guilds ADD COLUMN IF NOT EXISTS is_present BOOLEAN DEFAULT TRUE",
                    "ALTER TABLE bot_guilds ADD COLUMN IF NOT EXISTS left_at TIMESTAMPTZ"
                ]
                for query in bot_guilds_enhancements:
                    cur.execute(query)
                
                # Update existing rows to set is_present = TRUE if null
                cur.execute("UPDATE bot_guilds SET is_present = TRUE WHERE is_present IS NULL")
                
                # 10. Add employee onboarding tracking columns
                print("   Checking for employee onboarding columns")
                onboarding_columns = [
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS welcome_dm_sent BOOLEAN DEFAULT FALSE",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS first_clock_used BOOLEAN DEFAULT FALSE",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS first_clock_at TIMESTAMPTZ"
                ]
                for query in onboarding_columns:
                    cur.execute(query)
                
                # 11. Add broadcast_channel_id to guild_settings for owner announcements
                print("   Checking for broadcast channel column")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS broadcast_channel_id BIGINT")

        print("✅ Database schema is up to date")
        return True

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        # Don't crash the app, but log the error clearly
        return False

if __name__ == "__main__":
    # Allow running migrations directly for testing
    run_migrations()
