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

_migrations_run = False

def run_migrations():
    """
    Run database migrations to ensure schema is up to date.
    Safe to run on every startup (idempotent).
    """
    global _migrations_run
    if _migrations_run:
        return True
    
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

                # 1.5 Create global_feature_flags table
                print("   Checking table: global_feature_flags")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS global_feature_flags (
                        flag_name VARCHAR(50) PRIMARY KEY,
                        is_enabled BOOLEAN DEFAULT FALSE,
                        description TEXT,
                        updated_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_by BIGINT
                    )
                """)
                
                # Insert the v2_ui flag if it doesn't exist (default to OFF)
                cur.execute("""
                    INSERT INTO global_feature_flags (flag_name, is_enabled, description)
                    VALUES ('v2_ui', FALSE, 'Enable the new V2 Neon Cyber UI globally (primarily for testing)')
                    ON CONFLICT (flag_name) DO NOTHING
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
                    
                # Dynamically add all the new profile fields to ensure existing databases are updated
                columns_to_add = {
                    'role_tier': "VARCHAR(20) DEFAULT 'employee'",
                    'first_name': "VARCHAR(100)",
                    'last_name': "VARCHAR(100)",
                    'date_of_birth': "DATE",
                    'email': "VARCHAR(255)",
                    'bio': "TEXT",
                    'avatar_choice': "VARCHAR(50) DEFAULT 'random'",
                    'custom_avatar_url': "TEXT",
                    'company_role': "VARCHAR(100)",
                    'show_last_seen': "BOOLEAN DEFAULT TRUE",
                    'show_discord_status': "BOOLEAN DEFAULT TRUE",
                    'email_timesheets': "BOOLEAN DEFAULT FALSE",
                    'timesheet_email': "VARCHAR(255)",
                    'hire_date': "TIMESTAMPTZ DEFAULT NOW()",
                    'last_seen_discord': "TIMESTAMPTZ",
                    'profile_setup_completed': "BOOLEAN DEFAULT FALSE",
                    'profile_sent_on_first_clockin': "BOOLEAN DEFAULT FALSE",
                    'is_active': "BOOLEAN DEFAULT TRUE",
                    'updated_at': "TIMESTAMPTZ DEFAULT NOW()",
                    'accent_color': "VARCHAR(20) DEFAULT '#00FFFF'",
                    'profile_background': "TEXT"
                }

                for col_name, col_type in columns_to_add.items():
                    try:
                        cur.execute(f"ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS {col_name} {col_type}")
                    except Exception as e:
                        print(f"Migration soft error adding {col_name}: {e}")
                
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
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS discord_status TEXT",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS custom_report_name VARCHAR(255)"
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
                
                # 12. Add grant_source column to server_subscriptions for tracking Stripe vs manual grants
                print("   Checking for grant_source column")
                cur.execute("ALTER TABLE server_subscriptions ADD COLUMN IF NOT EXISTS grant_source TEXT")
                
                # 13. Add source column to time_adjustment_requests for tracking origin (dashboard, kiosk, discord)
                print("   Checking for adjustment request source column")
                cur.execute("ALTER TABLE time_adjustment_requests ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'dashboard'")

                # 13.b Add kiosk_only_mode column to guild_settings to enforce Kiosk usage
                print("   Checking for kiosk_only_mode column constraint")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS kiosk_only_mode BOOLEAN DEFAULT FALSE")
                
                # 13. Create email_recipients table for storing report recipients per guild
                print("   Checking table: email_recipients")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS email_recipients (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        added_by BIGINT,
                        added_at TIMESTAMPTZ DEFAULT NOW(),
                        UNIQUE(guild_id, email)
                    )
                """)
                
                # Add index for guild-based email lookups
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_email_recipients_guild 
                    ON email_recipients(guild_id)
                """)
                
                # 14. Backfill email_settings for guilds with recipients but no settings row
                print("   Backfilling email_settings for existing recipients")
                cur.execute("""
                    INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete)
                    SELECT DISTINCT rr.guild_id, TRUE, TRUE
                    FROM report_recipients rr
                    LEFT JOIN email_settings es ON rr.guild_id = es.guild_id
                    WHERE es.guild_id IS NULL
                    ON CONFLICT (guild_id) DO NOTHING
                """)
                
                # 15. Create employee_pins table for kiosk PIN authentication
                print("   Checking table: employee_pins")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS employee_pins (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        user_id BIGINT NOT NULL,
                        pin_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW(),
                        UNIQUE(guild_id, user_id)
                    )
                """)
                
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_employee_pins_guild_user 
                    ON employee_pins(guild_id, user_id)
                """)
                
                # 16. Add kiosk_mode_only to server_subscriptions
                print("   Checking for kiosk_mode_only column")
                cur.execute("ALTER TABLE server_subscriptions ADD COLUMN IF NOT EXISTS kiosk_mode_only BOOLEAN DEFAULT FALSE")
                
                # 22. Add grandfathered column to server_subscriptions
                print("   Checking for grandfathered column in server_subscriptions")
                cur.execute("ALTER TABLE server_subscriptions ADD COLUMN IF NOT EXISTS grandfathered BOOLEAN DEFAULT FALSE")
                
                # 23. Mark existing bot_access_paid servers as grandfathered (if no active subscription)
                print("   Marking legacy bot_access_paid servers as grandfathered")
                cur.execute("""
                    UPDATE server_subscriptions 
                    SET grandfathered = TRUE 
                    WHERE bot_access_paid = TRUE 
                    AND grandfathered = FALSE
                    AND (subscription_id IS NULL OR status != 'active')
                """)
                
                # 17. Add indexes for timeclock_sessions table for performance
                print("   Checking indexes for timeclock_sessions")
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timeclock_guild_user 
                    ON timeclock_sessions(guild_id, user_id)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timeclock_clockin 
                    ON timeclock_sessions(clock_in_time)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timeclock_guild_clockin 
                    ON timeclock_sessions(guild_id, clock_in_time)
                """)
                
                # 18. Add email verification columns to report_recipients
                print("   Adding email verification columns to report_recipients")
                cur.execute("ALTER TABLE report_recipients ADD COLUMN IF NOT EXISTS verification_status VARCHAR(20) DEFAULT 'pending'")
                cur.execute("ALTER TABLE report_recipients ADD COLUMN IF NOT EXISTS verification_code_hash VARCHAR(255)")
                cur.execute("ALTER TABLE report_recipients ADD COLUMN IF NOT EXISTS verification_code_sent_at TIMESTAMPTZ")
                cur.execute("ALTER TABLE report_recipients ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ")
                cur.execute("ALTER TABLE report_recipients ADD COLUMN IF NOT EXISTS verification_attempts INTEGER DEFAULT 0")
                
                # Update existing records to be verified (grandfather them in)
                cur.execute("""
                    UPDATE report_recipients 
                    SET verification_status = 'verified', verified_at = NOW() 
                    WHERE verification_status = 'pending' AND verified_at IS NULL
                """)
                
                # 24. Report Name Formatting Option
                print("   Checking for report_name_format column in guild_settings")
                try:
                    cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS report_name_format VARCHAR(50) DEFAULT 'full_name'")
                except Exception as e:
                    print(f"   Error adding report_name_format to guild_settings: {e}")
                
                # 19. Create email_outbox table for reliable email delivery
                print("   Checking table: email_outbox")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS email_outbox (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT,
                        email_type VARCHAR(50) NOT NULL,
                        recipients TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        text_content TEXT,
                        html_content TEXT,
                        attachments_json TEXT,
                        context_json TEXT,
                        status VARCHAR(20) NOT NULL DEFAULT 'pending',
                        attempts INTEGER DEFAULT 0,
                        max_attempts INTEGER DEFAULT 3,
                        last_attempt_at TIMESTAMPTZ,
                        last_error TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        sent_at TIMESTAMPTZ,
                        next_retry_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                
                # Indexes for outbox processing
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_email_outbox_status_retry
                    ON email_outbox(status, next_retry_at)
                    WHERE status IN ('pending', 'retry')
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_email_outbox_guild
                    ON email_outbox(guild_id)
                """)
                
                # 20. Add phone column to employee_profiles
                print("   Checking for phone column in employee_profiles")
                cur.execute("ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS phone VARCHAR(50)")
                
                # 21. Create trial_usage table for tracking one-time $5 first-month trials
                print("   Checking table: trial_usage")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS trial_usage (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL UNIQUE,
                        used_at TIMESTAMPTZ DEFAULT NOW(),
                        stripe_coupon_id VARCHAR(50),
                        stripe_checkout_session_id VARCHAR(255),
                        granted_by BIGINT,
                        grant_type VARCHAR(20) DEFAULT 'checkout'
                    )
                """)
                
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_trial_usage_guild
                    ON trial_usage(guild_id)
                """)
                
                # 22. Add profile customization columns to employee_profiles
                print("   Adding profile customization columns")
                profile_customization_columns = [
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS profile_background VARCHAR(50) DEFAULT 'default'",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS accent_color VARCHAR(50) DEFAULT 'cyan'",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS catchphrase VARCHAR(50)",
                    "ALTER TABLE employee_profiles ADD COLUMN IF NOT EXISTS selected_stickers TEXT"
                ]
                for query in profile_customization_columns:
                    cur.execute(query)

                # 23. Add kiosk customization toggle to guild_settings
                print("   Checking for allow_kiosk_customization column in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS allow_kiosk_customization BOOLEAN DEFAULT TRUE")
                
                # 23. Add last_demo_reset column to guild_settings for demo server tracking
                print("   Checking for last_demo_reset column in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS last_demo_reset TIMESTAMPTZ")

                # 24. Add trial columns to guild_settings
                print("   Checking for trial columns in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS trial_start_date TIMESTAMP DEFAULT NULL")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS trial_expired BOOLEAN DEFAULT FALSE")
                
                # 24.a Add Dashboard Onboarding marker to guild_settings
                print("   Checking for has_completed_onboarding column in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS has_completed_onboarding BOOLEAN DEFAULT FALSE")

                # 24.b Add Phase 1 Reporting & Monetization columns to guild_settings
                print("   Checking for Phase 1 reporting columns in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS csv_name_format VARCHAR(255) DEFAULT 'standard'")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS discord_log_channel_id BIGINT")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS discord_report_channel_id BIGINT")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS auto_prune_logs_days INTEGER")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS auto_prune_reports_days INTEGER")

                # 24. Add original_profile_data column to employee_archive for complete profile restoration
                print("   Checking for original_profile_data column in employee_archive")
                cur.execute("ALTER TABLE employee_archive ADD COLUMN IF NOT EXISTS original_profile_data JSONB")
                
                # 24b. Add archived_at column to employee_archive for ghost pruning
                print("   Checking for archived_at column in employee_archive")
                cur.execute("ALTER TABLE employee_archive ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ DEFAULT NOW()")

                # 24c. Add unique constraint on employee_archive(guild_id, user_id) for ON CONFLICT upsert
                print("   Checking for unique constraint on employee_archive(guild_id, user_id)")
                cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_employee_archive_guild_user_unique ON employee_archive(guild_id, user_id)")
                cur.execute("DROP INDEX IF EXISTS idx_employee_archive_guild_user")

                # 25. Add Stripe cancellation columns to server_subscriptions
                print("   Checking for cancellation columns in server_subscriptions")
                cur.execute("ALTER TABLE server_subscriptions ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN DEFAULT FALSE")
                cur.execute("ALTER TABLE server_subscriptions ADD COLUMN IF NOT EXISTS current_period_end BIGINT")

                # 26. Layer 2: Role Syncing
                print("   Checking for role sync columns in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS role_id_clocked_in BIGINT")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS role_id_clocked_out BIGINT")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS enable_role_sync BOOLEAN DEFAULT FALSE")

                # 27. Layer 2: Limits - max_shift_hours
                print("   Checking for max_shift_hours in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS max_shift_hours INTEGER DEFAULT 16")

                # 28. Layer 2: Timezone Enforcement
                print("   Checking for timezone in guild_settings")
                cur.execute("ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS timezone VARCHAR(50) DEFAULT 'America/New_York'")
                cur.execute("ALTER TABLE guild_settings ALTER COLUMN timezone SET DEFAULT 'America/New_York'")

                # 29. Layer 2: Error Logs Table
                print("   Checking table: error_logs")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS error_logs (
                        id SERIAL PRIMARY KEY,
                        guild_id BIGINT,
                        user_id BIGINT,
                        component VARCHAR(50),
                        error_type VARCHAR(50),
                        error_message TEXT,
                        stack_trace TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        resolved BOOLEAN DEFAULT FALSE
                    )
                """)

                cur.execute("CREATE INDEX IF NOT EXISTS idx_error_logs_guild ON error_logs(guild_id)")
                
                print("   Checking for resolved column in error_logs")
                cur.execute("ALTER TABLE error_logs ADD COLUMN IF NOT EXISTS resolved BOOLEAN DEFAULT FALSE")

                # 30. Layer 6: Email Customization
                print("   Checking for email customization columns in email_settings")
                cur.execute("ALTER TABLE email_settings ADD COLUMN IF NOT EXISTS subject_line VARCHAR(255)")
                cur.execute("ALTER TABLE email_settings ADD COLUMN IF NOT EXISTS reply_to_address VARCHAR(255)")
                cur.execute("ALTER TABLE email_settings ADD COLUMN IF NOT EXISTS cc_addresses TEXT")

                # 31. Layer 6: Owner Settings
                print("   Checking table: owner_settings")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS owner_settings (
                        owner_id BIGINT PRIMARY KEY,
                        alert_stripe_failures BOOLEAN DEFAULT TRUE,
                        alert_db_timeouts BOOLEAN DEFAULT TRUE,
                        alert_high_errors BOOLEAN DEFAULT TRUE
                    )
                """)

        _migrations_run = True
        print("✅ Database schema is up to date")
        return True

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        # Don't crash the app, but log the error clearly
        return False

if __name__ == "__main__":
    # Allow running migrations directly for testing
    run_migrations()
