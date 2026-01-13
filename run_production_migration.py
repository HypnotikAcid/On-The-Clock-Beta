#!/usr/bin/env python3
"""
Production Migration Script - Grandfathered Tier
=================================================
Run this script ONCE on your production database to:
1. Add the 'grandfathered' column to server_subscriptions
2. Mark all existing bot_access_paid=TRUE servers as grandfathered

HOW TO RUN:
-----------
1. Set your production DATABASE_URL environment variable
2. Run: python run_production_migration.py

This is SAFE to run multiple times - it uses IF NOT EXISTS and conditional updates.
"""

import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor

def run_migration():
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set")
        print("Please set it to your production database connection string")
        sys.exit(1)
    
    print("=" * 60)
    print("GRANDFATHERED TIER MIGRATION")
    print("=" * 60)
    print()
    
    try:
        conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
        conn.autocommit = False
        cur = conn.cursor()
        
        print("[1/4] Adding grandfathered column to server_subscriptions...")
        cur.execute("""
            ALTER TABLE server_subscriptions 
            ADD COLUMN IF NOT EXISTS grandfathered BOOLEAN DEFAULT FALSE
        """)
        print("      Done.")
        
        print("[2/4] Checking current state before migration...")
        cur.execute("""
            SELECT COUNT(*) as total,
                   COUNT(*) FILTER (WHERE bot_access_paid = TRUE) as paid_servers,
                   COUNT(*) FILTER (WHERE grandfathered = TRUE) as already_grandfathered
            FROM server_subscriptions
        """)
        stats = cur.fetchone()
        print(f"      Total servers: {stats['total']}")
        print(f"      Servers with bot_access_paid=TRUE: {stats['paid_servers']}")
        print(f"      Already grandfathered: {stats['already_grandfathered']}")
        
        print("[3/4] Marking legacy bot_access_paid servers as grandfathered...")
        cur.execute("""
            UPDATE server_subscriptions 
            SET grandfathered = TRUE 
            WHERE bot_access_paid = TRUE 
            AND grandfathered = FALSE
            AND (subscription_id IS NULL OR status != 'active')
            RETURNING guild_id
        """)
        updated = cur.fetchall()
        print(f"      Marked {len(updated)} servers as grandfathered")
        
        if updated:
            print("      Grandfathered guild IDs:")
            for row in updated:
                print(f"        - {row['guild_id']}")
        
        print("[4/4] Verifying final state...")
        cur.execute("""
            SELECT COUNT(*) FILTER (WHERE grandfathered = TRUE) as grandfathered_count
            FROM server_subscriptions
        """)
        final = cur.fetchone()
        print(f"      Total grandfathered servers: {final['grandfathered_count']}")
        
        conn.commit()
        print()
        print("=" * 60)
        print("MIGRATION COMPLETE!")
        print("=" * 60)
        print()
        print("Your legacy $5 lifetime users are now marked as 'grandfathered'")
        print("and will retain their Premium access indefinitely.")
        
    except Exception as e:
        print(f"ERROR: Migration failed - {e}")
        if 'conn' in locals():
            conn.rollback()
        sys.exit(1)
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    confirm = input("This will modify your production database. Continue? (yes/no): ")
    if confirm.lower() == 'yes':
        run_migration()
    else:
        print("Aborted.")
