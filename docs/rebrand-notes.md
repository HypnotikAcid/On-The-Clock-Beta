# Time Warden Rebrand (January 2026)

## Brand Strategy
- **Umbrella Brand**: Time Warden.
- **Primary Product**: "On the Clock".
- **Domain**: `time-warden.com` (Target).
- **Subdomain**: `on-the-clock.replit.app` (Stripe/OAuth stability).

## Execution
- Visual updates to landing page and dashboard.
- Bot username remains "On the Clock".
- Update dashboard URLs in bot messages AFTER domain connection.
- Avoid conflict with `ontheclock.com`.

---

## Domain Transition To-Do

### Discord OAuth Migration
- [ ] Update Discord Developer Portal with new redirect URIs for `www.time-warden.com`
- [ ] Add both old and new domains during transition (for backwards compatibility)
- [ ] Update `DISCORD_REDIRECT_URI` environment variable
- [ ] Test OAuth login flow on new domain
- [ ] Remove old `on-the-clock.replit.app` redirect URIs after confirming new domain works

### Codebase Updates
- [ ] Search for hardcoded `on-the-clock.replit.app` references and update to `www.time-warden.com`
- [ ] Update bot messages that link to dashboard
- [ ] Update email templates with new domain
- [ ] Update Stripe webhook endpoints if needed

### DNS & SSL
- [ ] Confirm `www.time-warden.com` is properly connected in Replit
- [ ] Verify SSL certificate is active
- [ ] Test all routes on new domain

### Post-Migration Cleanup
- [ ] Monitor for OAuth errors in logs
- [ ] Update documentation with new domain
- [ ] Announce domain change to users (if applicable)
