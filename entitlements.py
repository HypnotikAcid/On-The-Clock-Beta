# Entitlement system for On the Clock
# Provides consistent access checking across Flask and Discord bot

from enum import Enum
from typing import Optional, Dict, Any

class UserTier(Enum):
    FREE = "free"
    DASHBOARD_PREMIUM = "dashboard_premium"  # $5 one-time, 7-day retention
    PRO_RETENTION = "pro_retention"  # $5/month, 30-day retention

class UserRole(Enum):
    EMPLOYEE = "employee"
    ADMIN = "admin"

class Entitlements:
    """Check user entitlements for features"""
    
    @staticmethod
    def get_guild_tier(bot_access_paid: bool, retention_tier: str) -> UserTier:
        """Determine guild tier from database values"""
        if retention_tier == '30day':
            return UserTier.PRO_RETENTION
        elif bot_access_paid:
            return UserTier.DASHBOARD_PREMIUM
        return UserTier.FREE
    
    @staticmethod
    def get_retention_days(tier: UserTier) -> int:
        """Get retention days for a tier"""
        if tier == UserTier.PRO_RETENTION:
            return 30
        elif tier == UserTier.DASHBOARD_PREMIUM:
            return 7
        return 1  # Free tier = 24 hours (strictly enforced)
    
    @staticmethod
    def can_access_feature(tier: UserTier, role: UserRole, feature: str) -> bool:
        """Check if user can access a feature"""
        # Features that require Dashboard Premium
        premium_features = {
            'time_adjustments',
            'csv_reports', 
            'email_automation',
            'advanced_settings',
            'employee_profiles',
            'ban_management'
        }
        
        # Admin-only features (still need premium)
        admin_features = {
            'csv_reports',
            'email_automation',
            'advanced_settings',
            'ban_management',
            'role_management'
        }
        
        # Everyone can always use these
        free_features = {
            'clock_in_out',
            'view_own_hours',
            'support'
        }
        
        if feature in free_features:
            return True
            
        # Check if premium required
        if feature in premium_features and tier == UserTier.FREE:
            return False
            
        # Check if admin required
        if feature in admin_features and role != UserRole.ADMIN:
            return False
            
        return True
    
    @staticmethod
    def get_locked_message(feature: str) -> Dict[str, str]:
        """Get the message to show for a locked feature"""
        return {
            'title': 'Dashboard Premium Required',
            'message': f'Upgrade to Dashboard Premium to unlock {feature}.',
            'price': '$5 One-Time',
            'beta_price': '~~$10~~ $5 (Beta Price!)',
            'cta': 'Upgrade Now'
        }
