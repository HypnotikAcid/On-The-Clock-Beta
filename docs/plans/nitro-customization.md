# Plan: Nitro-Style Customization

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
