"""
CoA Trigger — sends RADIUS Change of Authorization when posture status changes.

Flow:
  1. Endpoint assessed → status changes (unknown → compliant)
  2. CoA Trigger looks up session (NAS-IP, MAC)
  3. Sends CoA-Reauth to switch → switch re-evaluates → new VLAN assigned
"""

import os
import asyncio
import logging
import httpx
from sqlalchemy import text

logger = logging.getLogger("nac.coa_trigger")


class CoATrigger:
    def __init__(self):
        self.policy_engine_url = os.getenv("POLICY_ENGINE_URL", "http://policy-engine:8000")
        self.enabled = os.getenv("COA_ENABLED", "true").lower() == "true"

    async def check_and_coa(self, db, mac: str, new_status: str):
        """Check if posture status changed and trigger CoA if needed."""
        if not self.enabled:
            return

        # Get current stored status
        r = await db.execute(text(
            "SELECT posture_status, nas_ip, assigned_vlan FROM nac_endpoints WHERE mac_address = :mac"
        ), {"mac": mac})
        row = r.fetchone()

        if not row:
            return

        old_status = row[0] or "unknown"
        nas_ip = row[1]

        if old_status == new_status:
            return  # No change

        logger.info(f"COA TRIGGER: mac={mac} posture {old_status} → {new_status}")

        if not nas_ip:
            logger.warning(f"COA SKIP: no NAS-IP for {mac}")
            return

        # Determine action based on transition
        if new_status == "compliant" and old_status in ("unknown", "non_compliant", "quarantined"):
            # Promote to production VLAN — send CoA-Reauth
            await self._send_coa(mac, nas_ip, "reauthenticate")
        elif new_status == "non_compliant" and old_status in ("compliant", "unknown"):
            # Demote to quarantine — send CoA-Reauth (will get quarantine VLAN)
            await self._send_coa(mac, nas_ip, "reauthenticate")
        elif new_status == "quarantined":
            # Explicit quarantine — disconnect
            await self._send_coa(mac, nas_ip, "reauthenticate")

    async def _send_coa(self, mac: str, nas_ip: str, action: str):
        """Send CoA via Policy Engine API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{self.policy_engine_url}/api/v1/coa/send",
                    json={
                        "mac_address": mac,
                        "nas_ip": nas_ip,
                        "action": action,
                    },
                )
                if r.status_code == 200:
                    data = r.json()
                    logger.info(f"COA SENT: {action} → {mac}@{nas_ip} result={data}")
                else:
                    logger.error(f"COA FAILED: {r.status_code} — {r.text}")
        except Exception as e:
            logger.error(f"COA ERROR: {e}")

    async def bulk_reassess(self, db):
        """Re-check all endpoints with stale posture data."""
        r = await db.execute(text("""
            SELECT mac_address, ip_address, hostname, posture_status
            FROM nac_endpoints
            WHERE last_posture_check < NOW() - INTERVAL 4 HOUR
               OR last_posture_check IS NULL
            LIMIT 100
        """))
        rows = r.fetchall()
        logger.info(f"BULK REASSESS: {len(rows)} stale endpoints")
        return [{"mac": row[0], "ip": row[1], "hostname": row[2], "status": row[3]} for row in rows]
