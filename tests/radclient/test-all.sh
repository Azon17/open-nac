#!/bin/bash
###############################################################################
#  Open NAC — Тестовые скрипты для radclient
#
#  Быстрые тесты без supplicant (PAP/MAB/accounting/CoA)
#  Для полного 802.1X (EAP) используйте eapol_test
###############################################################################

RADIUS_SERVER="${1:-127.0.0.1}"
RADIUS_PORT="${2:-1812}"
RADIUS_SECRET="${3:-testing123}"

echo "============================================"
echo "  Open NAC RADIUS Test Suite"
echo "  Server: ${RADIUS_SERVER}:${RADIUS_PORT}"
echo "============================================"

#--- Test 1: Status-Server (health check) ---
echo ""
echo "[1/6] Status-Server (health check)..."
echo "Message-Authenticator = 0x00" | \
  radclient -t 3 "${RADIUS_SERVER}:18121" status "${RADIUS_SECRET}" 2>&1
if [ $? -eq 0 ]; then echo "  ✓ RADIUS server is alive"; else echo "  ✗ RADIUS server not responding"; fi

#--- Test 2: PAP Authentication (SQL user) ---
echo ""
echo "[2/6] PAP Authentication (local SQL user)..."
echo "User-Name = testuser
User-Password = testpass
NAS-IP-Address = 127.0.0.1
NAS-Port = 1
Service-Type = Framed-User
Framed-Protocol = PPP" | \
  radclient -t 5 "${RADIUS_SERVER}:${RADIUS_PORT}" auth "${RADIUS_SECRET}" 2>&1
echo ""

#--- Test 3: MAB (MAC Authentication Bypass) ---
echo ""
echo "[3/6] MAB Authentication (known MAC)..."
echo "User-Name = aa:bb:cc:dd:ee:ff
User-Password = aa:bb:cc:dd:ee:ff
Calling-Station-Id = AA:BB:CC:DD:EE:FF
NAS-IP-Address = 10.0.1.1
NAS-Port-Id = GigabitEthernet0/1
NAS-Port-Type = Ethernet
Service-Type = Call-Check" | \
  radclient -t 5 "${RADIUS_SERVER}:${RADIUS_PORT}" auth "${RADIUS_SECRET}" 2>&1
echo ""

#--- Test 4: MAB (unknown MAC — should get quarantine VLAN) ---
echo ""
echo "[4/6] MAB Authentication (unknown MAC → quarantine)..."
echo "User-Name = 00:11:22:33:44:55
User-Password = 00:11:22:33:44:55
Calling-Station-Id = 00:11:22:33:44:55
NAS-IP-Address = 10.0.1.1
NAS-Port-Id = GigabitEthernet0/2
NAS-Port-Type = Ethernet
Service-Type = Call-Check" | \
  radclient -t 5 "${RADIUS_SERVER}:${RADIUS_PORT}" auth "${RADIUS_SECRET}" 2>&1
echo ""

#--- Test 5: Accounting Start ---
echo ""
echo "[5/6] Accounting Start..."
echo "User-Name = testuser
Acct-Session-Id = test-session-001
Acct-Status-Type = Start
NAS-IP-Address = 10.0.1.1
NAS-Port-Id = GigabitEthernet0/1
Calling-Station-Id = AA:BB:CC:DD:EE:FF
Called-Station-Id = 10.0.1.1
Framed-IP-Address = 10.100.1.50
Service-Type = Framed-User" | \
  radclient -t 5 "${RADIUS_SERVER}:1813" acct "${RADIUS_SECRET}" 2>&1
echo ""

#--- Test 6: CoA (Change of Authorization) ---
echo ""
echo "[6/6] CoA Disconnect-Request..."
echo "User-Name = testuser
Acct-Session-Id = test-session-001
NAS-IP-Address = 10.0.1.1
Calling-Station-Id = AA:BB:CC:DD:EE:FF
Event-Timestamp = $(date +%s)" | \
  radclient -t 5 "${RADIUS_SERVER}:3799" disconnect "${RADIUS_SECRET}" 2>&1
echo ""

echo "============================================"
echo "  Tests complete"
echo "============================================"
