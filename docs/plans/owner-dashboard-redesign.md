# Owner Dashboard Redesign Proposal (Master Control Panel)

## Current Status & Issues
The current `/owner` dashboard operates as a large, single-page scroll. While functional, it lacks the "Master Control Panel" layout needed for quick day-to-day business operations. 

It currently displays basic counts, a giant list of servers with expandable details, purchase histories, and manual tools.

## The Redesign Vision

To create a **Neon Cyber Master Control Panel** that provides instant insights and lightning-fast operational controls. We will ensure **100% of existing capabilities are retained**, but reorganized for maximum efficiency.

### 1. The Layout (Grid Architecture)
Instead of scrolling vertically:
- **Top Bar (The HUD):** High-level metrics (MRR/Revenue, Total Active Users, Active Servers).
- **Left Sidebar:** Quick navigation tabs to switch between views without reloading the whole page:
  - 📊 **Overview** (Metrics & Hotspots)
  - 🏰 **Server Directory** (Global list of all servers)
  - 💰 **Financials** (Purchases & Subscriptions)
  - 🛠️ **System Tools** (Broadcasts, Demo Seeding)
- **Center Main Console:** Dynamic data tables based on the selected sidebar tab.

### 2. NEW: Deep-Dive Troubleshooting (Customer Support View)
To address the need for easy support and analytics:
- **Server Command Center Modal:** When you click on *any* server in the directory, a sleek glassmorphic modal will pop up immediately.
- This modal will consolidate EVERYTHING about that customer in one place:
  - **Identities:** Server Owner ID, Guild ID, Stripe Customer IDs.
  - **Rapid Actions:** One-click buttons to Grant Pro, Revoke Access, or Reset Trial.
  - **Data Retrieval:** Direct buttons to download that specific server's CSV Time Reports instantly.
  - **Health Metrics:** Recent Webhook events (to see if their billing failed) and active worker counts.

### 3. New Analytics To Add (`app.py` modifications)
1. **Estimated MRR (Monthly Recurring Revenue):** Calculate based on active `bot_access`, `retention_30day`, and `pro` tier subscriptions. 
2. **Growth Metrics:** New servers joined in the last 7 days.
3. **Usage Hotspots:** Most active servers (based on employee count or active sessions).

### 4. UI Aesthetics (Neon Cyber)
- **Background:** Deep obsidian (`#0A0F1F`)
- **Accents:** Neon Cyan (`#00FFFF`) and Matrix Green (`#00FF41`) for positive metrics, warning Red for errors/unpaid.
- **Components:** Glassmorphism panels (translucent dark backgrounds with subtle borders) and glowing hover effects on buttons.

## Execution Steps

1. **Update `app.py`**: Modify the `owner_dashboard` route to calculate MRR and growth metrics.
2. **Rewrite `owner_dashboard.html`**: Completely strip the old layout and build the new Sidebar + Grid template with the new "Server Command Center" modals.
3. **Restyle CSS**: Apply the Neon Cyber theme with glassmorphic elements.
