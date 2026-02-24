# Entitlement system for On the Clock
# Provides consistent access checking across Flask and Discord bot

from enum import Enum
from typing import Optional, Dict, Any

# Retention period constants (in days)
RETENTION_FREE_DAYS = 1      # 24 hours - strictly enforced
RETENTION_PREMIUM_DAYS = 30  # Premium and Grandfathered tiers
RETENTION_PRO_DAYS = 30      # Pro tier (future-proof if tiers diverge)

class UserTier(Enum):
    FREE = "free"
    GRANDFATHERED = "grandfathered"  # Legacy $5 lifetime users - equivalent to Premium
    PREMIUM = "premium"  # $8/mo, 30-day retention
    PRO = "pro"          # $15/mo, Advanced features

class UserRole(Enum):
    EMPLOYEE = "employee"
    ADMIN = "admin"

class Entitlements:
    """Check user entitlements for features"""
    
    DEMO_SERVER_ID = 1419894879894507661

    @staticmethod
    def is_trial_active(trial_start_date) -> bool:
        """Check if 30-day trial is still active"""
        if trial_start_date is None:
            return True
        from datetime import datetime, timedelta
        return (datetime.now() - trial_start_date.replace(tzinfo=None)) < timedelta(days=30)

    @staticmethod
    def get_trial_days_remaining(trial_start_date) -> int:
        """Get days remaining in trial, 0 if expired"""
        if trial_start_date is None:
            return 30
        from datetime import datetime
        elapsed = (datetime.now() - trial_start_date.replace(tzinfo=None)).days
        return max(0, 30 - elapsed)

    @staticmethod
    def is_server_exempt(guild_id: int, grandfathered: bool = False, owner_granted: bool = False) -> bool:
        """Check if server bypasses all trial/tier restrictions"""
        return int(guild_id) == Entitlements.DEMO_SERVER_ID or grandfathered or owner_granted

    @staticmethod
    def get_guild_tier(bot_access_paid: bool, retention_tier: str, grandfathered: bool = False) -> UserTier:
        """Determine guild tier from database values"""
        if retention_tier == 'pro':
            return UserTier.PRO
        elif grandfathered:
            return UserTier.GRANDFATHERED
        elif bot_access_paid or retention_tier == '30day':
            return UserTier.PREMIUM
        return UserTier.FREE
    
    @staticmethod
    def get_retention_days(tier: UserTier) -> int:
        """Get retention days for a tier"""
        if tier == UserTier.PRO:
            return RETENTION_PRO_DAYS
        elif tier == UserTier.PREMIUM:
            return RETENTION_PREMIUM_DAYS
        elif tier == UserTier.GRANDFATHERED:
            return RETENTION_PREMIUM_DAYS  # Grandfathered users keep Premium retention
        return RETENTION_FREE_DAYS  # Free tier = 24 hours (strictly enforced)
    
    @staticmethod
    def can_access_feature(tier: UserTier, role: UserRole, feature: str, trial_active: bool = True) -> bool:
        """Check if user can access a feature"""
        # Features that require Premium
        premium_features = {
            'time_adjustments',
            'csv_reports', 
            'email_automation',
            'advanced_settings',
            'employee_profiles_extended', # Changed from employee_profiles
            'ban_management',
            'dashboard_access',
            'custom_display_names',
            'discord_channel_logistics'
        }

        # Pro-only features
        pro_only_features = {
            'kiosk',
            'payroll_formats',
            'pdf_exports',
            'advanced_reports'
        }
        
        # Admin-only features (still need premium for some)
        admin_features = {
            'csv_reports',
            'email_automation',
            'advanced_settings',
            'ban_management'
            # 'role_management' removed from here because free users can use it
        }
        
        # Everyone can always use these
        free_features = {
            'clock_in_out',
            'view_own_hours',
            'support',
            'role_management',
            'employee_profiles_basic' # Allow basic profile access
        }
        
        if feature in free_features:
            return True

        if feature in pro_only_features:
            return tier == UserTier.PRO
            
        # Check if premium required (Grandfathered users have Premium access)
        if feature in premium_features and tier == UserTier.FREE and not trial_active:
            return False
        
        # Grandfathered tier has same access as Premium
        # (Already passes above check since tier != FREE)
            
        # Check if admin required
        if feature in admin_features and role != UserRole.ADMIN:
            return False
            
        return True
    
    @staticmethod
    def get_locked_message(feature: str, trial_expired: bool = False) -> Dict[str, str]:
        """Get the message to show for a locked feature"""
        cta = 'Upgrade Now' if trial_expired else 'Start Free Trial'
        return {
            'title': 'Premium Required',
            'message': f'Upgrade to Premium to unlock {feature}.',
            'price': '$8/mo',
            'offer': 'First month FREE!',
            'cta': cta
        }

    @staticmethod
    def get_trial_expired_message() -> dict:
        return {
            'title': 'Free Trial Expired',
            'message': 'Your 30-day free trial has ended. Upgrade to Premium to continue using all features.',
            'price': '$8/mo',
            'offer': 'First month FREE!',
            'cta': 'Upgrade Now'
        }
