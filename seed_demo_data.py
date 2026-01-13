#!/usr/bin/env python3
"""
Demo Data Seeding Script for "On The Clock" Dashboard

This script populates the demo server with sample employees, timeclock sessions,
and time adjustment requests so customers can preview the dashboard functionality.

Usage:
    python seed_demo_data.py

This script is IDEMPOTENT - safe to run multiple times without creating duplicates.
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import random

DEMO_SERVER_ID = 1419894879894507661

DEMO_EMPLOYEES = [
    {
        'user_id': 100000000000000001,
        'display_name': 'Alex Manager',
        'full_name': 'Alex Thompson',
        'first_name': 'Alex',
        'last_name': 'Thompson',
        'email': 'alex.demo@ontheclock.app',
        'position': 'Store Manager',
        'department': 'Management',
        'company_role': 'Manager',
        'bio': 'Demo manager account - 5 years with the company',
        'role_tier': 'admin'
    },
    {
        'user_id': 100000000000000002,
        'display_name': 'Jordan Sales',
        'full_name': 'Jordan Rivera',
        'first_name': 'Jordan',
        'last_name': 'Rivera',
        'email': 'jordan.demo@ontheclock.app',
        'position': 'Sales Associate',
        'department': 'Sales',
        'company_role': 'Employee',
        'bio': 'Top performer in sales department',
        'role_tier': 'employee'
    },
    {
        'user_id': 100000000000000003,
        'display_name': 'Casey Support',
        'full_name': 'Casey Williams',
        'first_name': 'Casey',
        'last_name': 'Williams',
        'email': 'casey.demo@ontheclock.app',
        'position': 'Customer Support',
        'department': 'Support',
        'company_role': 'Employee',
        'bio': 'Friendly face of customer service',
        'role_tier': 'employee'
    },
    {
        'user_id': 100000000000000004,
        'display_name': 'Sam Warehouse',
        'full_name': 'Sam Johnson',
        'first_name': 'Sam',
        'last_name': 'Johnson',
        'email': 'sam.demo@ontheclock.app',
        'position': 'Warehouse Lead',
        'department': 'Warehouse',
        'company_role': 'Employee',
        'bio': 'Keeps the warehouse running smoothly',
        'role_tier': 'employee'
    },
    {
        'user_id': 100000000000000005,
        'display_name': 'Taylor Intern',
        'full_name': 'Taylor Chen',
        'first_name': 'Taylor',
        'last_name': 'Chen',
        'email': 'taylor.demo@ontheclock.app',
        'position': 'Marketing Intern',
        'department': 'Marketing',
        'company_role': 'Intern',
        'bio': 'Learning the ropes of digital marketing',
        'role_tier': 'employee'
    }
]


def get_db_connection():
    """Get a database connection"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)


def seed_employee_profiles(conn):
    """Seed demo employee profiles (idempotent)"""
    print("\n📋 Seeding employee profiles...")
    cursor = conn.cursor()
    
    for emp in DEMO_EMPLOYEES:
        cursor.execute("""
            INSERT INTO employee_profiles (
                guild_id, user_id, display_name, full_name, first_name, last_name,
                email, position, department, company_role, bio, role_tier,
                is_active, profile_setup_completed, hire_date
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, %s
            )
            ON CONFLICT (guild_id, user_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                full_name = EXCLUDED.full_name,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name,
                email = EXCLUDED.email,
                position = EXCLUDED.position,
                department = EXCLUDED.department,
                company_role = EXCLUDED.company_role,
                bio = EXCLUDED.bio,
                role_tier = EXCLUDED.role_tier,
                is_active = TRUE,
                profile_setup_completed = TRUE
        """, (
            DEMO_SERVER_ID,
            emp['user_id'],
            emp['display_name'],
            emp['full_name'],
            emp['first_name'],
            emp['last_name'],
            emp['email'],
            emp['position'],
            emp['department'],
            emp['company_role'],
            emp['bio'],
            emp['role_tier'],
            datetime.now() - timedelta(days=random.randint(30, 365))
        ))
        print(f"   ✅ {emp['display_name']} ({emp['position']})")
    
    conn.commit()
    print(f"   Total: {len(DEMO_EMPLOYEES)} employees seeded")


def seed_timeclock_sessions(conn):
    """Seed demo timeclock sessions for the past 30 days (idempotent)"""
    print("\n⏰ Seeding timeclock sessions...")
    cursor = conn.cursor()
    
    cursor.execute("""
        DELETE FROM timeclock_sessions 
        WHERE guild_id = %s AND user_id::bigint IN (
            100000000000000001, 100000000000000002, 100000000000000003,
            100000000000000004, 100000000000000005
        )
    """, (str(DEMO_SERVER_ID),))
    
    sessions_created = 0
    now = datetime.now()
    
    for emp in DEMO_EMPLOYEES:
        work_days = random.randint(15, 25)
        
        for day_offset in range(30, 0, -1):
            if random.random() > (work_days / 30.0):
                continue
            
            work_date = now - timedelta(days=day_offset)
            
            if work_date.weekday() >= 5 and random.random() > 0.2:
                continue
            
            start_hour = random.randint(7, 10)
            start_minute = random.choice([0, 15, 30, 45])
            clock_in = work_date.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
            
            shift_length = random.uniform(4, 9)
            clock_out = clock_in + timedelta(hours=shift_length)
            
            if random.random() < 0.15:
                lunch_break = random.uniform(0.5, 1.0)
                clock_out -= timedelta(hours=lunch_break)
            
            duration_seconds = int((clock_out - clock_in).total_seconds())
            
            cursor.execute("""
                INSERT INTO timeclock_sessions (
                    guild_id, user_id, clock_in_time, clock_out_time
                ) VALUES (%s, %s, %s, %s)
            """, (
                str(DEMO_SERVER_ID),
                str(emp['user_id']),
                clock_in,
                clock_out
            ))
            sessions_created += 1
    
    if random.random() > 0.3:
        active_emp = random.choice(DEMO_EMPLOYEES[1:])
        today_start = now.replace(hour=random.randint(7, 10), minute=random.choice([0, 15, 30]), second=0, microsecond=0)
        cursor.execute("""
            INSERT INTO timeclock_sessions (
                guild_id, user_id, clock_in_time, clock_out_time
            ) VALUES (%s, %s, %s, NULL)
        """, (
            str(DEMO_SERVER_ID),
            str(active_emp['user_id']),
            today_start
        ))
        sessions_created += 1
        print(f"   🟢 {active_emp['display_name']} is currently clocked in")
    
    conn.commit()
    print(f"   Total: {sessions_created} sessions created")


def seed_adjustment_requests(conn):
    """Seed sample time adjustment requests (idempotent)"""
    print("\n📝 Seeding time adjustment requests...")
    cursor = conn.cursor()
    
    cursor.execute("""
        DELETE FROM time_adjustment_requests 
        WHERE guild_id = %s AND user_id IN (
            100000000000000001, 100000000000000002, 100000000000000003,
            100000000000000004, 100000000000000005
        )
    """, (DEMO_SERVER_ID,))
    
    now = datetime.now()
    requests_created = 0
    
    request_scenarios = [
        {
            'employee_idx': 1,
            'request_type': 'add_session',
            'reason': 'Forgot to clock in - was in morning meeting',
            'status': 'pending',
            'days_ago': 2
        },
        {
            'employee_idx': 2,
            'request_type': 'modify_clockout',
            'reason': 'System logged me out early, worked until 5pm',
            'status': 'pending',
            'days_ago': 1
        },
        {
            'employee_idx': 3,
            'request_type': 'add_session',
            'reason': 'Worked from home - forgot to use app',
            'status': 'approved',
            'days_ago': 5
        },
        {
            'employee_idx': 4,
            'request_type': 'modify_clockin',
            'reason': 'Arrived 30 min early to help with shipment',
            'status': 'denied',
            'days_ago': 7
        }
    ]
    
    for scenario in request_scenarios:
        emp = DEMO_EMPLOYEES[scenario['employee_idx']]
        request_date = now - timedelta(days=scenario['days_ago'])
        
        requested_clock_in = request_date.replace(hour=9, minute=0, second=0, microsecond=0)
        requested_clock_out = request_date.replace(hour=17, minute=0, second=0, microsecond=0)
        
        reviewed_by = DEMO_EMPLOYEES[0]['user_id'] if scenario['status'] != 'pending' else None
        reviewed_at = now - timedelta(days=scenario['days_ago'] - 1) if scenario['status'] != 'pending' else None
        
        cursor.execute("""
            INSERT INTO time_adjustment_requests (
                guild_id, user_id, request_type, reason, status,
                requested_clock_in, requested_clock_out,
                reviewed_by, reviewed_at, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            DEMO_SERVER_ID,
            emp['user_id'],
            scenario['request_type'],
            scenario['reason'],
            scenario['status'],
            requested_clock_in,
            requested_clock_out,
            reviewed_by,
            reviewed_at,
            request_date
        ))
        requests_created += 1
        status_icon = '🟡' if scenario['status'] == 'pending' else ('✅' if scenario['status'] == 'approved' else '❌')
        print(f"   {status_icon} {emp['display_name']}: {scenario['request_type']} ({scenario['status']})")
    
    conn.commit()
    print(f"   Total: {requests_created} adjustment requests created")


def main():
    """Main entry point for demo data seeding"""
    print("=" * 60)
    print("🌱 On The Clock - Demo Data Seeding Script")
    print("=" * 60)
    print(f"Target: Demo Server ID {DEMO_SERVER_ID}")
    
    try:
        conn = get_db_connection()
        print("✅ Database connection established")
        
        seed_employee_profiles(conn)
        seed_timeclock_sessions(conn)
        seed_adjustment_requests(conn)
        
        conn.close()
        
        print("\n" + "=" * 60)
        print("✅ Demo data seeding complete!")
        print("=" * 60)
        print("\nThe demo dashboard now has:")
        print(f"  • {len(DEMO_EMPLOYEES)} sample employees")
        print("  • ~30 days of timeclock history")
        print("  • Sample time adjustment requests (pending, approved, denied)")
        print("\nVisit the dashboard to see the demo data in action!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise


if __name__ == "__main__":
    main()
