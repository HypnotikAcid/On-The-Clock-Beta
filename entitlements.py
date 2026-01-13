# Entitlement system for On the Clock
# Provides consistent access checking across Flask and Discord bot

from enum import Enum
from typing import Optional, Dict, Any

class UserTier(Enum):
    FREE = "free"
    PREMIUM = "premium"  # $8/mo, 30-day retention
    PRO = "pro"          # $15/mo, Advanced features

class UserRole(Enum):
    EMPLOYEE = "employee"
    ADMIN = "admin"

class Entitlements:
    """Check user entitlements for features"""
    
    @staticmethod
    def get_guild_tier(bot_access_paid: bool, retention_tier: str) -> UserTier:
        """Determine guild tier from database values"""
        if retention_tier == 'pro':
            return UserTier.PRO
        elif bot_access_paid or retention_tier == '30day':
            return UserTier.PREMIUM
        return UserTier.FREE
    
    @staticmethod
    def get_retention_days(tier: UserTier) -> int:
        """Get retention days for a tier"""
        if tier == UserTier.PRO:
            return 30 # For now, keep at 30
        elif tier == UserTier.PREMIUM:
            return 30
        return 1  # Free tier = 24 hours (strictly enforced)
    
    @staticmethod
    def can_access_feature(tier: UserTier, role: UserRole, feature: str) -> bool:
        """Check if user can access a feature"""
        # Features that require Premium
        premium_features = {
            'time_adjustments',
            'csv_reports', 
            'email_automation',
            'advanced_settings',
            'employee_profiles_extended', # Changed from employee_profiles
            'ban_management'
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
            'title': 'Premium Required',
            'message': f'Upgrade to Premium to unlock {feature}.',
            'price': '$8/mo',
            'beta_price': '~~$8~~ $5 (First Month!)',
            'cta': 'Upgrade Now'
        }
