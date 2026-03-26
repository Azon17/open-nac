#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Open NAC — Deploy Extended Posture Module v2
# Run on: root@dell-test (10.10.10.173)
# ═══════════════════════════════════════════════════════════════
set -e

PROJ="/root/open-nac"
cd "$PROJ" || { echo "Project dir not found at $PROJ"; exit 1; }

echo "═══ Open NAC Posture v2 Deployment ═══"
echo ""

# ─── 1. Update database schema ───
echo "[1/5] Applying extended posture schema..."
# Use ProxySQL or direct MariaDB
MYSQL_CMD="docker exec mariadb-1 mariadb -u root -pMyStr0ng! radius"
# Try ProxySQL first, fallback to direct
$MYSQL_CMD < posture_schema_v2.sql 2>/dev/null || \
  docker exec -i mariadb-1 mariadb -u root -p'MyStr0ng!' radius < posture_schema_v2.sql
echo "  ✓ Schema updated (11 condition types, AV vendors, assessment history)"

# ─── 2. Deploy compliance engine v2 ───
echo ""
echo "[2/5] Deploying extended compliance engine..."
# Copy to posture-engine app directory
cp services/posture-engine/compliance_engine_v2.py services/posture-engine/app/compliance_engine.py
echo "  ✓ ComplianceEngineV2 deployed"

# ─── 3. Deploy extended posture admin API ───
echo ""
echo "[3/5] Deploying extended posture admin API..."
cp services/policy-engine/app/api/posture_admin_v2.py services/policy-engine/app/api/posture_admin.py
echo "  ✓ posture_admin_v2 deployed (toggle endpoints, AV vendors, extended fields)"

# ─── 4. Inject PosturePage v2 into index.html ───
echo ""
echo "[4/5] Updating Admin UI PosturePage..."

# The PosturePage function starts at 'function PosturePage(){' and ends before
# the next top-level function. We need to replace it.
# Strategy: use Python to do a precise replacement

python3 << 'PYEOF'
import re

index_path = "services/admin-ui/public/index.html"
new_posture_path = "services/admin-ui/PosturePage_v2.jsx"

with open(index_path, "r") as f:
    html = f.read()

with open(new_posture_path, "r") as f:
    new_posture = f.read()

# Remove comment lines (// ... ) from JSX — they're valid in JSX/Babel
# but we keep them since we're using Babel in-browser

# Find the old PosturePage function
# It starts at "function PosturePage(){" and ends before the next
# top-level function declaration (like "function LDAPPage")
pattern = r'function PosturePage\(\)\{.*?\n\}[\s]*\nfunction (?=LDAP|Settings|Cert|Live|Auth)'

match = re.search(pattern, html, re.DOTALL)
if match:
    # We want to keep the "function" keyword that starts the next function
    old = match.group(0)
    # Remove the trailing "function" that belongs to the next function
    old = old[:old.rfind('\nfunction ')]
    # Build replacement: new PosturePage + the ConditionsTab and EditModal helpers
    replacement = new_posture.strip()
    html = html.replace(old, replacement)
    print(f"  ✓ PosturePage replaced ({len(old)} chars → {len(replacement)} chars)")
else:
    # Fallback: try simpler pattern
    start = html.find("function PosturePage(){")
    if start == -1:
        print("  ✗ Could not find PosturePage function!")
        exit(1)
    
    # Find the end — look for next top-level "function " at column 0
    # after PosturePage
    search_from = start + 100
    next_func = -1
    for fn in ["function LDAPPage", "function SettingsPage", "function CertificatesPage"]:
        pos = html.find(fn, search_from)
        if pos != -1 and (next_func == -1 or pos < next_func):
            next_func = pos
    
    if next_func == -1:
        print("  ✗ Could not find end of PosturePage!")
        exit(1)
    
    # Go back to find the last newline before next function
    end = next_func
    while end > 0 and html[end-1] in (' ', '\t', '\n', '\r'):
        end -= 1
    end += 1  # include the newline
    
    old_code = html[start:end]
    replacement = new_posture.strip() + "\n\n"
    html = html[:start] + replacement + html[end:]
    print(f"  ✓ PosturePage replaced ({len(old_code)} chars → {len(replacement)} chars)")

with open(index_path, "w") as f:
    f.write(html)

print("  ✓ index.html updated")
PYEOF

# ─── 5. Rebuild and restart containers ───
echo ""
echo "[5/5] Rebuilding and restarting containers..."

echo "  Building policy-engine..."
docker compose build policy-engine
echo "  Starting policy-engine..."
docker compose up -d policy-engine

echo "  Building posture-engine..."
docker compose build posture-engine
echo "  Starting posture-engine..."
docker compose up -d posture-engine

echo "  Restarting admin-ui (nginx static files)..."
docker compose restart admin-ui

echo ""
echo "  Waiting 5s for containers to stabilize..."
sleep 5

# Health check
echo ""
echo "─── Health checks ───"
PE_STATUS=$(curl -s http://localhost:8000/health 2>/dev/null | grep -o '"status":"ok"' || echo "FAIL")
if [ "$PE_STATUS" = '"status":"ok"' ]; then
  echo "  ✓ Policy Engine: OK"
else
  echo "  ✗ Policy Engine: $PE_STATUS"
  echo "    Check: docker compose logs policy-engine --tail 20"
fi

UI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://localhost:443 -k 2>/dev/null || echo "000")
if [ "$UI_STATUS" = "200" ] || [ "$UI_STATUS" = "301" ] || [ "$UI_STATUS" = "302" ]; then
  echo "  ✓ Admin UI: OK (HTTP $UI_STATUS)"
else
  echo "  ✗ Admin UI: HTTP $UI_STATUS"
  echo "    Check: docker compose logs admin-ui --tail 20"
fi

echo ""
echo "═══ Deployment complete ═══"
echo ""
echo "Changes deployed:"
echo "  ✓ DB: 11 ISE condition types, AV vendor table, assessment history"
echo "  ✓ Backend: ComplianceEngineV2 with vendor-aware checks"
echo "  ✓ API: Toggle PATCH endpoints, extended condition CRUD, AV vendors"
echo "  ✓ UI: ISE-style condition wizards, working toggles, category sidebar"
echo ""
echo "New condition types:"
echo "  1.  Anti-Malware   — vendor picker (CrowdStrike, SentinelOne, etc.)"
echo "  2.  Firewall       — per-profile check (Domain/Private/Public)"
echo "  3.  Disk Encryption"
echo "  4.  OS Patches     — critical count threshold"
echo "  5.  Patch Management — specific KB numbers"
echo "  6.  OS Version     — min/max version"
echo "  7.  Application    — installed/not installed"
echo "  8.  File Check     — path, version, SHA-256 hash"
echo "  9.  Registry       — key existence, value comparison"
echo "  10. Service        — running/stopped/auto-start"
echo "  11. USB Restriction — mass storage, device class blocking"
echo "  +   Compound       — AND/OR/NOT over sub-conditions"
