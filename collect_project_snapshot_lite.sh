#!/usr/bin/env bash
set -euo pipefail
OUT="PROJECT_SNAPSHOT_LITE.md"; : > "$OUT"
p(){ printf '%s\n' "$*" >> "$OUT"; }
sec(){ printf '\n# %s\n\n' "$1" >> "$OUT"; }
sub(){ printf '\n## %s\n\n' "$1" >> "$OUT"; }

p "# Project Snapshot (Lite)"
p "Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")"

# 1) Tree (top 2 levels only)
sec "Repository Tree (depth 2)"
if command -v tree >/dev/null; then
  { echo '```text'; tree -a -L 2 -I '.git|__pycache__|node_modules|.cache|.mypy_cache|.pytest_cache'; echo '```'; } >> "$OUT"
else
  { echo '_tree not installed; using find_'; echo '```text'; find . -maxdepth 2 -path ./.git -prune -o -print | sed 's|^\./||'; echo '```'; } >> "$OUT"
fi

# 2) Key config files
sec "Key Config Files"
for f in .replit requirements.txt replit.nix pyproject.toml; do
  [[ -f "$f" ]] || continue
  sub "$f"; echo '```' >> "$OUT"; cat "$f" >> "$OUT"; echo '```' >> "$OUT"
done

# 3) Env var names
sec "Environment Variables (os.getenv names)"
if grep -RhoE "os\.getenv\(['\"][A-Z0-9_]+['\"]" . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  grep -RhoE "os\.getenv\(['\"][A-Z0-9_]+['\"]" . --exclude-dir=.git --exclude-dir=__pycache__ \
    | sed -E "s/.*\(['\"]([A-Z0-9_]+)['\"].*/\1/" | sort -u | sed 's/^/- /' >> "$OUT"
else
  p "_No os.getenv(...) calls found._"
fi

# 4) Flask routes
sec "Flask Routes (@app.route / add_url_rule)"
if grep -RInE "@app\.route\(|add_url_rule\(" . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  { echo '```text'; grep -RInE "@app\.route\(|add_url_rule\(" . --exclude-dir=.git --exclude-dir=__pycache__; echo '```'; } >> "$OUT"
else p "_No Flask routes found._"; fi

# 5) aiohttp routes
sec "aiohttp Routes (routes.get/post/...)"
if grep -RInE "routes\.(get|post|put|patch|delete)\(" . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  { echo '```text'; grep -RInE "routes\.(get|post|put|patch|delete)\(" . --exclude-dir=.git --exclude-dir=__pycache__; echo '```'; } >> "$OUT"
else p "_No aiohttp RouteTableDef routes found._"; fi

# 6) Discord slash commands
sec "Discord Slash Commands (discord.py app_commands)"
if grep -RInE "app_commands\.command\(|@app_commands\." . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  { echo '```text'; grep -RInE "app_commands\.command\(|@app_commands\." . --exclude-dir=.git --exclude-dir=__pycache__; echo '```'; } >> "$OUT"
else p "_No app_commands decorators found._"; fi

# 7) Feature tiles (look for 'TILE:' comments)
sec "Feature Tiles (lines containing 'TILE:')"
if grep -RIn "TILE:" . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  { echo '```text'; grep -RIn "TILE:" . --exclude-dir=.git --exclude-dir=__pycache__; echo '```'; } >> "$OUT"
else p "_No 'TILE:' markers found._"; fi

# 8) SQL in code (schema hints)
sec "Schema Statements in Code (CREATE/ALTER/PRAGMA)"
if grep -RInE "CREATE TABLE|ALTER TABLE|PRAGMA" . --exclude-dir=.git --exclude-dir=__pycache__ >/dev/null 2>&1; then
  { echo '```sql'; grep -RInE "CREATE TABLE|ALTER TABLE|PRAGMA" . --exclude-dir=.git --exclude-dir=__pycache__; echo '```'; } >> "$OUT"
else p "_No schema statements found in code._"; fi
