# Time Warden Pricing Strategy

## Current Pricing Structure

| Tier | Price | Key Features |
|------|-------|--------------|
| **Free** | $0/mo | Basic clock in/out, 24-hour data retention, daily reports |
| **Premium** | $8/mo | 30-day retention, weekly reports, profile customization, email automation, time adjustments |
| **Pro** | $15/mo | Kiosk mode, monthly reports, advanced CSV, shift scheduling, payroll integrations |
| **Grandfathered** | Legacy | Existing Premium users keep access |

---

## Market Research (January 2026)

### Discord Bot Pricing Landscape
**Key Finding:** Most Discord time tracking bots are **completely free**.

| Bot | Pricing | Features |
|-----|---------|----------|
| TimeTracker | Free | Basic clock in/out |
| Clockin | Free | Button-based punching |
| Timekeeper | Free (mentions premium) | Slash commands, API |
| Timesheets | Free | Leaderboards, stats |
| VCStats | Free | Voice channel tracking |

**Opportunity:** There's no established paid Discord time bot market—Time Warden can define the category.

### SaaS Time Tracking Pricing
| Platform | Pricing Model | Our Position |
|----------|---------------|--------------|
| Clockify | Free + $4.99/user/mo | Cheaper at team level |
| Buddy Punch | $3.49/user + $19 base | Simpler flat rate |
| Connecteam | $35/mo (30 users) | Comparable at scale |
| QuickBooks Time | Included with payroll | Different target market |

### Discord Premium Apps (Native Monetization)
- Discord takes **10% cut** on Server Subscriptions (very favorable).
- Subscription range: **$2.99 - $199.99/month**.
- Growth tier: Only **15% fee** on first $1M earned.

---

## Pricing Analysis

### Current Structure Assessment

**Strengths:**
- Clear tier differentiation.
- Free tier for acquisition.
- Kiosk as Pro differentiator.

**Weaknesses:**
- $8 and $15 may be too close—harder to justify upgrade.
- Per-server pricing doesn't scale for multi-server customers.
- No annual discount to improve retention.

### Recommendations

#### Option A: Widen Tier Gap
| Tier | Current | Proposed |
|------|---------|----------|
| Free | $0 | $0 |
| Premium | $8 | $6 |
| Pro | $15 | $12 |

**Rationale:** Lower prices increase adoption; Discord bot market expects lower costs.

#### Option B: Add Annual Discount
| Tier | Monthly | Annual (2 months free) |
|------|---------|------------------------|
| Free | $0 | $0 |
| Premium | $8 | $80/year (save $16) |
| Pro | $15 | $150/year (save $30) |

**Rationale:** Improves retention, increases LTV, better cash flow.

#### Option C: Per-Seat Pricing (Enterprise)
For large servers (50+ employees):
- **Enterprise**: $0.50/employee/month (minimum $25/mo)
- Includes all Pro features.
- Dedicated support channel.

**Rationale:** Scales better for large organizations.

---

## Feature-to-Tier Mapping

### Current Mapping
| Feature | Free | Premium | Pro |
|---------|------|---------|-----|
| Clock in/out | ✅ | ✅ | ✅ |
| Daily reports | ✅ | ✅ | ✅ |
| 24h retention | ✅ | - | - |
| 30-day retention | - | ✅ | ✅ |
| Weekly reports | - | ✅ | ✅ |
| Monthly reports | - | - | ✅ |
| Profile customization | - | ✅ | ✅ |
| Time adjustments | - | ✅ | ✅ |
| Email automation | - | ✅ | ✅ |
| Kiosk mode | - | - | ✅ |
| Advanced CSV | - | - | ✅ |

### Proposed Additions
| New Feature | Tier | Rationale |
|-------------|------|-----------|
| PDF reports | Pro | Professional payroll submission |
| Badges/Gamification | Premium | Engagement driver |
| Kiosk-only employees | Pro | Enterprise need |
| Offline kiosk mode | Pro | Reliability |
| Multi-server management | Pro | Power users |
| White-label branding | Enterprise | Corporate customers |

---

## Monetization Channels

### Primary: Stripe Subscriptions (Current)
- Direct payment processing.
- Full control over pricing.
- Existing integration.

### Secondary: Discord Server Subscriptions (Future)
- Native Discord billing.
- Only 10% platform fee.
- Frictionless for users.
- Limited to monthly subscriptions.

### Tertiary: Premium Bot Commands (Future)
- One-time purchases for premium features.
- Discord handles payments.
- Good for add-ons.

---

## Pricing Psychology

### Anchor Pricing
- Show Pro price first, then Premium, then Free.
- Makes Premium look like a deal.

### Feature Highlighting
- Use ❌ icons for missing features on lower tiers.
- Show "Most Popular" badge on Premium.

### Social Proof
- Display customer count per tier.
- Show testimonials from paid users.

### Loss Aversion
- "You'll lose access to..." messaging for downgrades.
- Trial expiration reminders.

---

## Revenue Projections

### Assumptions
- 100 servers (50 Free, 35 Premium, 15 Pro)
- No churn (optimistic)

### Monthly Revenue
| Tier | Servers | Price | Revenue |
|------|---------|-------|---------|
| Free | 50 | $0 | $0 |
| Premium | 35 | $8 | $280 |
| Pro | 15 | $15 | $225 |
| **Total** | 100 | - | **$505/mo** |

### With Annual Pricing (50% adoption)
| Tier | Monthly | Annual | Blended Revenue |
|------|---------|--------|-----------------|
| Premium | 18 × $8 = $144 | 17 × $6.67 = $113 | $257/mo |
| Pro | 8 × $15 = $120 | 7 × $12.50 = $87.50 | $207.50/mo |
| **Total** | - | - | **$464.50/mo** (but better retention) |

---

## Competitive Positioning Matrix

| Factor | Time Warden | Clockify | Buddy Punch |
|--------|-------------|----------|-------------|
| Discord Native | ✅ | ❌ | ❌ |
| Free Tier | ✅ | ✅ | ❌ |
| Kiosk Mode | ✅ (Pro) | ❌ | ✅ |
| Per-Server Pricing | ✅ | ❌ | ❌ |
| Per-User Pricing | ❌ | ✅ | ✅ |
| Dashboard | ✅ | ✅ | ✅ |
| Profile Customization | ✅ | ❌ | ❌ |

---

## Action Items

### Short-Term
- [ ] Add annual pricing option (2 months free).
- [ ] Create comparison page on landing site.
- [ ] Implement trial expiration emails.

### Medium-Term
- [ ] Explore Discord Server Subscriptions integration.
- [ ] Add Enterprise tier for large servers.
- [ ] Build pricing page A/B tests.

### Long-Term
- [ ] Consider per-seat pricing for very large servers.
- [ ] Evaluate usage-based add-ons (extra storage, API calls).
- [ ] White-label offering for agencies.

---

## Status
**Planning Phase** - Pricing strategy documented for review.
