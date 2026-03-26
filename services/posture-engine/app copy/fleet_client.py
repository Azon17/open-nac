"""
Fleet Client — queries Fleet (osquery management server) for endpoint state.
Fleet API: https://fleetdm.com/docs/rest-api/rest-api

osquery tables used:
  - windows_security_products → AV status
  - windows_firewall_rules → firewall
  - disk_encryption → BitLocker/FileVault
  - patches / os_version → OS patches
  - interface_addresses → IP/MAC
"""

import os
import logging
import httpx
from typing import Optional

logger = logging.getLogger("nac.fleet")


class FleetClient:
    def __init__(self):
        self.base_url = os.getenv("FLEET_SERVER_URL", "http://fleet:8080")
        self.api_token = os.getenv("FLEET_API_TOKEN", "")
        self.client: Optional[httpx.AsyncClient] = None
        self.available = False

    async def initialize(self):
        if not self.api_token:
            logger.warning("Fleet API token not set — Fleet integration disabled")
            return

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_token}"},
            timeout=10.0,
        )
        try:
            r = await self.client.get("/api/v1/fleet/status")
            if r.status_code == 200:
                self.available = True
                logger.info(f"Fleet connected: {self.base_url}")
            else:
                logger.warning(f"Fleet returned {r.status_code}")
        except Exception as e:
            logger.warning(f"Fleet not available: {e}")

    async def get_host_by_identifier(self, identifier: str) -> Optional[dict]:
        """
        Look up host in Fleet by IP, hostname, or MAC.
        Returns normalized compliance data.
        """
        if not self.available or not self.client:
            return None

        try:
            # Search by identifier
            r = await self.client.get(
                "/api/v1/fleet/hosts",
                params={"query": identifier, "per_page": 1}
            )
            if r.status_code != 200:
                return None

            data = r.json()
            hosts = data.get("hosts", [])
            if not hosts:
                return None

            host = hosts[0]
            host_id = host.get("id")

            # Get detailed host info
            detail_r = await self.client.get(f"/api/v1/fleet/hosts/{host_id}")
            if detail_r.status_code != 200:
                return self._normalize_basic(host)

            host_detail = detail_r.json().get("host", {})

            # Run live queries for compliance data
            compliance_data = await self._query_compliance(host_id, host_detail.get("platform", ""))

            return {
                "hostname": host_detail.get("hostname", ""),
                "platform": host_detail.get("platform", ""),
                "os_version": host_detail.get("os_version", ""),
                "osquery_version": host_detail.get("osquery_version", ""),
                "last_enrolled": host_detail.get("last_enrolled_at", ""),
                "status": host_detail.get("status", ""),
                **compliance_data,
            }

        except Exception as e:
            logger.error(f"Fleet query failed for {identifier}: {e}")
            return None

    async def _query_compliance(self, host_id: int, platform: str) -> dict:
        """Run osquery queries to gather compliance data."""
        result = {
            "antivirus": [],
            "firewall": {"enabled": False},
            "disk_encryption": {"enabled": False},
            "patches": {"pending_critical": 0, "pending_total": 0},
        }

        queries = {}

        if platform in ("windows", "Windows"):
            queries = {
                "antivirus": "SELECT * FROM windows_security_products WHERE type='Antivirus'",
                "firewall": "SELECT name, enabled FROM windows_firewall_rules WHERE enabled=1 LIMIT 1",
                "encryption": "SELECT * FROM bitlocker_info",
                "patches": "SELECT count(*) as cnt FROM patches WHERE installed=0",
            }
        elif platform in ("darwin", "macOS"):
            queries = {
                "firewall": "SELECT global_state FROM alf",
                "encryption": "SELECT * FROM disk_encryption WHERE encrypted=1",
                "patches": "SELECT count(*) as cnt FROM software_updates WHERE restart_required='true'",
            }
        elif platform in ("ubuntu", "linux", "centos", "rhel"):
            queries = {
                "firewall": "SELECT count(*) as cnt FROM iptables WHERE chain='INPUT'",
                "encryption": "SELECT * FROM disk_encryption WHERE encrypted=1",
            }

        for name, query in queries.items():
            try:
                r = await self.client.post(
                    f"/api/v1/fleet/hosts/{host_id}/query",
                    json={"query": query},
                    timeout=15.0,
                )
                if r.status_code == 200:
                    rows = r.json().get("rows", [])
                    if name == "antivirus":
                        result["antivirus"] = [
                            {"name": row.get("display_name", ""), "state": row.get("state", "")}
                            for row in rows
                        ]
                    elif name == "firewall":
                        result["firewall"]["enabled"] = len(rows) > 0
                    elif name == "encryption":
                        result["disk_encryption"]["enabled"] = len(rows) > 0
                    elif name == "patches":
                        cnt = int(rows[0].get("cnt", 0)) if rows else 0
                        result["patches"]["pending_total"] = cnt
                        result["patches"]["pending_critical"] = cnt  # simplified
            except Exception as e:
                logger.debug(f"Fleet query '{name}' failed: {e}")

        return result

    def _normalize_basic(self, host: dict) -> dict:
        """Normalize basic host data without detailed queries."""
        return {
            "hostname": host.get("hostname", ""),
            "platform": host.get("platform", ""),
            "os_version": host.get("os_version", ""),
            "antivirus": [],
            "firewall": {"enabled": False},
            "disk_encryption": {"enabled": False},
            "patches": {"pending_critical": 0, "pending_total": 0},
        }

    async def list_hosts(self, page: int = 0, per_page: int = 100) -> list:
        """List all hosts in Fleet."""
        if not self.available or not self.client:
            return []
        try:
            r = await self.client.get(
                "/api/v1/fleet/hosts",
                params={"page": page, "per_page": per_page}
            )
            return r.json().get("hosts", []) if r.status_code == 200 else []
        except Exception:
            return []
