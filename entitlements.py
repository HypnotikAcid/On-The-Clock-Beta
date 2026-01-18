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
            
        # Check if premium required (Grandfathered users have Premium access)
        if feature in premium_features and tier == UserTier.FREE:
            return False
        
        # Grandfathered tier has same access as Premium
        # (Already passes above check since tier != FREE)
            
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
