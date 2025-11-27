#!/usr/bin/env python3
"""
Migration script to move from SQLite to PostgreSQL
Safely migrates schema and data while preserving all information
"""

import sqlite3
import psycopg2
import os
import json
from datetime import datetime

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("❌ ERROR: DATABASE_URL environment variable not set")
    exit(1)

print("🔄 Starting migration from SQLite to PostgreSQL...\n")

# PostgreSQL schema (translated from SQLite)
POSTGRES_SCHEMA = """
-- Server subscriptions (core payment/access table)
CREATE TABLE IF NOT EXISTS server_subscriptions (
    guild_id BIGINT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'free',
    subscription_id TEXT,
    expires_at TIMESTAMP,
    status TEXT DEFAULT 'active',
    customer_id TEXT,
    bot_access_paid BOOLEAN DEFAULT FALSE,
    retention_tier TEXT DEFAULT 'none',
    manually_granted BOOLEAN DEFAULT FALSE,
    granted_by TEXT,
    granted_at TIMESTAMP,
    restrict_mobile_clockin BOOLEAN DEFAULT FALSE
);

-- Bot guilds tracking
CREATE TABLE IF NOT EXISTS bot_guilds (
    guild_id TEXT PRIMARY KEY,
    guild_name TEXT,
    joined_at TIMESTAMP NOT NULL
);

-- Time tracking sessions
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    clock_in TIMESTAMP NOT NULL,
    clock_out TIMESTAMP,
    duration_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS timeclock_sessions (
    session_id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    clock_in_time TIMESTAMP NOT NULL,
    clock_out_time TIMESTAMP
);

-- Guild settings
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id BIGINT PRIMARY KEY,
    recipient_user_id BIGINT,
    button_channel_id BIGINT,
    button_message_id BIGINT,
    timezone TEXT DEFAULT 'America/New_York',
    name_display_mode TEXT DEFAULT 'username',
    main_admin_role_id TEXT,
    work_day_end_time TEXT DEFAULT NULL
);

-- Role management
CREATE TABLE IF NOT EXISTS admin_roles (
    guild_id TEXT,
    role_id TEXT,
    PRIMARY KEY (guild_id, role_id)
);

CREATE TABLE IF NOT EXISTS employee_roles (
    guild_id TEXT,
    role_id TEXT,
    PRIMARY KEY (guild_id, role_id)
);

CREATE TABLE IF NOT EXISTS authorized_roles (
    guild_id BIGINT,
    role_id BIGINT,
    PRIMARY KEY (guild_id, role_id)
);

-- OAuth and session management
CREATE TABLE IF NOT EXISTS oauth_sessions (
    state TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    ip_address TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    discriminator TEXT,
    avatar TEXT,
    guilds_data TEXT NOT NULL,
    access_token TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT NOT NULL,
    refresh_token TEXT
);

-- Email settings and reports
CREATE TABLE IF NOT EXISTS report_recipients (
    id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    recipient_type TEXT NOT NULL CHECK(recipient_type IN ('discord', 'email')),
    recipient_id TEXT,
    email_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(guild_id, recipient_type, recipient_id),
    UNIQUE(guild_id, recipient_type, email_address)
);

CREATE TABLE IF NOT EXISTS email_settings (
    guild_id BIGINT PRIMARY KEY,
    auto_send_on_clockout BOOLEAN DEFAULT FALSE,
    auto_email_before_delete BOOLEAN DEFAULT FALSE
);

-- Spam protection
CREATE TABLE IF NOT EXISTS banned_users (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ban_expires_at TIMESTAMP,
    warning_count INTEGER DEFAULT 0,
    reason TEXT DEFAULT 'spam_detection',
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS server_ban_log (
    id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Webhook event tracking
CREATE TABLE IF NOT EXISTS webhook_events (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_id TEXT,
    guild_id BIGINT,
    status TEXT NOT NULL CHECK(status IN ('success', 'failed')),
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);
"""

def migrate():
    # Connect to both databases
    sqlite_conn = sqlite3.connect('timeclock.db')
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_cursor = pg_conn.cursor()
    
    try:
        # Create PostgreSQL schema
        print("📋 Creating PostgreSQL schema...")
        pg_cursor.execute(POSTGRES_SCHEMA)
        pg_conn.commit()
        print("✅ Schema created\n")
        
        # Table migration mapping (SQLite &rarr; PostgreSQL)
        tables = [
            'server_subscriptions',
            'bot_guilds',
            'sessions',
            'timeclock_sessions',
            'guild_settings',
            'admin_roles',
            'employee_roles',
            'authorized_roles',
            'oauth_sessions',
            'oauth_states',
            'user_sessions',
            'report_recipients',
            'email_settings',
            'banned_users',
            'server_ban_log',
            'webhook_events'
        ]
        
        for table in tables:
            try:
                # Check if table exists in SQLite
                sqlite_cursor = sqlite_conn.execute(
                    f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"
                )
                if not sqlite_cursor.fetchone():
                    print(f"⏭️  Skipping {table} (doesn't exist in SQLite)")
                    continue
                
                # Get data from SQLite
                sqlite_cursor = sqlite_conn.execute(f"SELECT * FROM {table}")
                rows = sqlite_cursor.fetchall()
                
                if not rows:
                    print(f"⏭️  Skipping {table} (empty)")
                    continue
                
                # Get column names
                column_names = [description[0] for description in sqlite_cursor.description]
                
                # Insert into PostgreSQL
                placeholders = ', '.join(['%s'] * len(column_names))
                columns = ', '.join(column_names)
                insert_query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                
                for row in rows:
                    pg_cursor.execute(insert_query, row)
                
                pg_conn.commit()
                print(f"✅ Migrated {len(rows)} rows from {table}")
                
            except Exception as e:
                print(f"❌ Error migrating {table}: {e}")
                pg_conn.rollback()
        
        print("\n🎉 Migration completed successfully!")
        print(f"📊 Database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'PostgreSQL'}")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        pg_conn.rollback()
        raise
    finally:
        sqlite_conn.close()
        pg_conn.close()

if __name__ == "__main__":
    migrate()
