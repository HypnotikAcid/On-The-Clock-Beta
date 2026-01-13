"""
Mock data generator for dashboard preview screenshots.
Creates realistic-looking employee data for 20-30 employees.
"""
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any

FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Quinn",
    "Avery", "Cameron", "Hayden", "Peyton", "Skyler", "Dakota", "Reese", "Finley",
    "Charlie", "Drew", "Logan", "Parker", "Sage", "Blake", "Emerson", "Rowan",
    "Kendall", "Ashton", "Marley", "Phoenix", "Addison", "Harley"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas", "Moore", 
    "Jackson", "Martin", "Lee", "Thompson", "White", "Harris", "Clark", "Lewis",
    "Robinson", "Walker", "Hall", "Young", "King", "Wright", "Lopez"
]

MOCK_SERVER = {
    "id": "1234567890123456789",
    "name": "Demo Company Inc.",
    "icon": None,
    "member_count": 85
}

MOCK_USER = {
    "user_id": "9876543210987654321",
    "username": "demo_admin",
    "avatar": None,
    "global_name": "Demo Admin"
}


def generate_mock_employees(count: int = 25) -> List[Dict[str, Any]]:
    """Generate realistic mock employee data"""
    employees = []
    now = datetime.utcnow()
    
    for i in range(count):
        first_name = FIRST_NAMES[i % len(FIRST_NAMES)]
        last_name = LAST_NAMES[(i * 7) % len(LAST_NAMES)]
        username = f"{first_name.lower()}.{last_name.lower()}"
        
        hire_days_ago = random.randint(30, 365 * 3)
        hire_date = now - timedelta(days=hire_days_ago)
        
        is_clocked_in = random.random() < 0.35
        
        clock_in_time = None
        current_session_hours = 0
        if is_clocked_in:
            hours_ago = random.uniform(0.5, 6)
            clock_in_time = now - timedelta(hours=hours_ago)
            current_session_hours = hours_ago
        
        weekly_hours = random.uniform(20, 45)
        total_hours = (hire_days_ago / 7) * random.uniform(30, 42)
        
        has_email = random.random() > 0.2
        has_phone = random.random() > 0.4
        has_pending_adjustment = random.random() < 0.15
        forgot_clock_out = random.random() < 0.08
        
        has_alert = not has_email or has_pending_adjustment or forgot_clock_out
        
        employees.append({
            "user_id": str(1000000000000000000 + i),
            "username": username,
            "display_name": f"{first_name} {last_name}",
            "avatar": None,
            "is_active": True,
            "is_clocked_in": is_clocked_in,
            "clock_in_time": clock_in_time.isoformat() if clock_in_time else None,
            "current_session_hours": round(current_session_hours, 2),
            "weekly_hours": round(weekly_hours, 2),
            "total_hours": round(total_hours, 2),
            "hire_date": hire_date.strftime("%Y-%m-%d"),
            "email": f"{username}@example.com" if has_email else None,
            "phone": f"555-{random.randint(100,999)}-{random.randint(1000,9999)}" if has_phone else None,
            "has_alert": has_alert,
            "pending_adjustments": 1 if has_pending_adjustment else 0,
            "forgot_clock_out": forgot_clock_out
        })
    
    employees.sort(key=lambda e: (-int(e["is_clocked_in"]), e["display_name"]))
    
    return employees


def generate_mock_time_entries(employee_id: str, days: int = 30) -> List[Dict[str, Any]]:
    """Generate mock time entries for an employee"""
    entries = []
    now = datetime.utcnow()
    
    for day_offset in range(days):
        if random.random() < 0.3:
            continue
            
        date = now - timedelta(days=day_offset)
        if date.weekday() >= 5 and random.random() < 0.7:
            continue
        
        clock_in_hour = random.randint(7, 10) + random.random()
        shift_length = random.uniform(6, 10)
        
        clock_in = date.replace(
            hour=int(clock_in_hour),
            minute=random.randint(0, 59),
            second=0
        )
        clock_out = clock_in + timedelta(hours=shift_length)
        
        entries.append({
            "session_id": len(entries) + 1,
            "user_id": employee_id,
            "clock_in_time": clock_in.isoformat(),
            "clock_out_time": clock_out.isoformat(),
            "duration_hours": round(shift_length, 2)
        })
    
    return entries


def generate_mock_adjustment_requests(employees: List[Dict], count: int = 8) -> List[Dict[str, Any]]:
    """Generate mock time adjustment requests"""
    requests = []
    now = datetime.utcnow()
    
    request_types = ["edit", "add", "delete"]
    statuses = ["pending", "pending", "pending", "approved", "denied"]
    reasons = [
        "Forgot to clock out",
        "System was down, couldn't clock in",
        "Clocked in late due to traffic",
        "Left early for doctor appointment",
        "Lunch break wasn't recorded",
        "Worked overtime, forgot to extend",
        "Wrong clock-out time recorded"
    ]
    
    sampled_employees = random.sample(employees, min(count, len(employees)))
    
    for i, emp in enumerate(sampled_employees):
        days_ago = random.randint(0, 14)
        request_date = now - timedelta(days=days_ago)
        
        requests.append({
            "id": i + 1,
            "user_id": emp["user_id"],
            "username": emp["username"],
            "display_name": emp["display_name"],
            "request_type": random.choice(request_types),
            "status": random.choice(statuses),
            "reason": random.choice(reasons),
            "created_at": request_date.isoformat(),
            "original_clock_in": (request_date.replace(hour=9)).isoformat(),
            "original_clock_out": (request_date.replace(hour=17)).isoformat(),
            "requested_clock_in": (request_date.replace(hour=8, minute=30)).isoformat(),
            "requested_clock_out": (request_date.replace(hour=17, minute=30)).isoformat()
        })
    
    return requests


def generate_mock_calendar_data(employees: List[Dict], month_offset: int = 0) -> Dict[str, List]:
    """Generate mock calendar data for admin calendar view"""
    now = datetime.utcnow()
    if month_offset:
        now = now.replace(day=1) - timedelta(days=1)
        now = now.replace(day=1)
    
    calendar_data = {}
    
    for day in range(1, 32):
        try:
            date = now.replace(day=day)
        except ValueError:
            break
            
        date_key = date.strftime("%Y-%m-%d")
        
        if date.weekday() >= 5:
            continue
        if random.random() < 0.1:
            continue
            
        working_employees = random.sample(
            employees, 
            min(random.randint(15, 22), len(employees))
        )
        
        entries = []
        for emp in working_employees:
            clock_in_hour = random.randint(7, 10)
            clock_in_min = random.randint(0, 59)
            shift_hours = random.uniform(6, 10)
            
            entries.append({
                "user_id": emp["user_id"],
                "display_name": emp["display_name"],
                "clock_in": f"{clock_in_hour:02d}:{clock_in_min:02d}",
                "clock_out": f"{(clock_in_hour + int(shift_hours)) % 24:02d}:{random.randint(0,59):02d}",
                "hours": round(shift_hours, 2)
            })
        
        calendar_data[date_key] = entries
    
    return calendar_data


def get_mock_server_settings() -> Dict[str, Any]:
    """Get mock server settings"""
    return {
        "guild_id": MOCK_SERVER["id"],
        "timezone": "America/New_York",
        "bot_access_paid": True,
        "retention_tier": "30day",
        "kiosk_mode_enabled": True,
        "broadcast_channel_id": "1234567890123456780"
    }


def get_mock_subscription() -> Dict[str, Any]:
    """Get mock subscription data"""
    return {
        "tier": "premium",
        "status": "active",
        "current_period_end": (datetime.utcnow() + timedelta(days=25)).isoformat(),
        "cancel_at_period_end": False
    }


def get_full_mock_context() -> Dict[str, Any]:
    """Get complete mock context for dashboard rendering"""
    employees = generate_mock_employees(25)
    
    clocked_in = [e for e in employees if e["is_clocked_in"]]
    pending_adj = sum(1 for e in employees if e["pending_adjustments"] > 0)
    
    return {
        "server": MOCK_SERVER,
        "user": MOCK_USER,
        "user_role": "admin",
        "is_also_employee": True,
        "employees": employees,
        "clocked_in_count": len(clocked_in),
        "pending_adjustments": pending_adj,
        "adjustment_requests": generate_mock_adjustment_requests(employees, 8),
        "settings": get_mock_server_settings(),
        "subscription": get_mock_subscription(),
        "active_page": "overview",
        "tier": "premium",
        "show_tz_reminder": False
    }
