# Plan: Nitro-Style Customization & Gamification

## Concept
Employees unlock visual flair for their profiles and kiosk buttons (borders, frames, badges, stickers) based on milestones or server events.

## Features
- **Profile Borders**: Glowing animated borders for avatars.
- **Frames**: Static decorative frames for status cards.
- **Badges**: Performance-based (e.g., "Always on Time", "Week Streak").
- **Stickers**: Custom emojis attached to kiosk buttons.

## Technical
- Store unlocked items in `user_customizations` table.
- Kiosk CSS needs to dynamically apply these styles.

---

## Cross-Connections to Other Plans

### Kiosk Overhaul
- Flair (borders, stickers, badges) displays on kiosk buttons when clocked in.
- After-login pages always show profile customization.

### CSV Report Overhaul
- Consider report-based badges: "Timesheet Titan", "Perfect Week".

### Pricing Strategy
- Profile customization is a **Premium tier** feature ($8/mo).
- Advanced flair (animated borders, rare badges) could be **Pro tier**.

---

## Research Findings: Gamification Best Practices (January 2026)

### Why Gamification Works
- **TimeJam study**: Employees logged 30 more hours/month with gamification.
- **McKinsey report**: 20% productivity increase with performance tracking.
- **Gallup data**: Only 32% of employees feel engaged—badges address this gap.

### Core Gamification Elements

#### 1. Points System
| Action | Points |
|--------|--------|
| Clock in on time | +10 |
| Submit timesheet on time | +25 |
| 5-day streak | +50 |
| Zero corrections in a week | +30 |
| Help a colleague | +20 |

#### 2. Badge Ideas for Time Warden
| Badge Name | Criteria | Icon |
|------------|----------|------|
| **Early Bird** | Clock in on time for 2 weeks | 🌅 |
| **Timesheet Titan** | 4 consecutive weeks on-time submissions | 🏆 |
| **Accuracy Ace** | Zero timesheet corrections for 1 month | 🎯 |
| **Streak Champion** | 30-day on-time streak | 🔥 |
| **Consistency King** | 10 consecutive accurate submissions | 👑 |
| **Team Player** | Help 5 colleagues with time tracking | 🤝 |
| **Overtime Hero** | Log 10+ hours in a single day (voluntary) | 💪 |
| **Perfect Week** | All punches on time for a week | ⭐ |

#### 3. Leaderboards
- **Individual**: Most points, longest streak, highest accuracy.
- **Team-based**: Department vs. department competition.
- **Monthly resets**: Fresh starts to re-engage users.

#### 4. Rewards
**Virtual Rewards:**
- Exclusive badges, animated borders, rare stickers.
- Unlock new profile themes.
- Custom titles ("Time Master", "Punch Perfect").

**Tangible Rewards (admin-configured):**
- Gift card integration (future).
- Extra PTO hours (honor system).
- Recognition in team meetings.

### Implementation Approach

#### Phase 1: Basic Badges
- Award badges for streaks and milestones.
- Display on profile and kiosk button.
- Store in `employee_badges` table.

#### Phase 2: Points System
- Track points per action.
- Display running total on profile.
- Leaderboard view for admins.

#### Phase 3: Unlockable Flair
- Borders, frames, stickers unlock at point thresholds.
- Employees choose which to display.
- Sync to kiosk appearance.

### Sample Database Schema
```
employee_badges:
  - id: SERIAL PRIMARY KEY
  - guild_id: BIGINT
  - user_id: VARCHAR
  - badge_type: VARCHAR (e.g., "early_bird", "streak_champion")
  - earned_at: TIMESTAMP
  - displayed: BOOLEAN (show on profile/kiosk)

employee_points:
  - id: SERIAL PRIMARY KEY
  - guild_id: BIGINT
  - user_id: VARCHAR
  - total_points: INTEGER
  - current_streak: INTEGER
  - longest_streak: INTEGER
  - last_updated: TIMESTAMP
```

### Best Practices
✅ **Do:**
- Start small (badges only, expand later).
- Make rewards meaningful.
- Provide immediate feedback (notifications).
- Balance competition with collaboration.

❌ **Don't:**
- Overuse leaderboards (can demotivate low performers).
- Create complex rules.
- Let rewards stagnate (refresh quarterly).

### Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Gaming the system | Audit logs, admin review |
| Demotivating low performers | Focus on personal bests, not just rankings |
| Badge fatigue | Limit badge count, make them meaningful |
