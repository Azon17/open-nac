"""
Open NAC — Posture Engine
Equivalent: Cisco ISE Posture Service + AnyConnect ISE Posture Module

Checks endpoint compliance via:
  1. osquery/Fleet — real-time host state (AV, encryption, patches, firewall)
  2. Direct agent API — lightweight REST-based compliance check
  3. Network-based heuristics — for unmanaged devices

Workflow:
  Endpoint connects → RADIUS auth → limited VLAN
  → Posture Engine checks compliance
  → Compliant: CoA → production VLAN
  → Non-compliant: stays in quarantine, portal shows remediation steps
"""

import os
import logging
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from app.compliance_engine import ComplianceEngine, CompliancePolicy
from app.fleet_client import FleetClient
from app.coa_trigger import CoATrigger
from app.db import engine, Base, get_db, AsyncSession
from app.scheduler import start_scheduler

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nac.posture")

compliance_engine = ComplianceEngine()
fleet_client = FleetClient()
coa_trigger = CoATrigger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Posture Engine...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await fleet_client.initialize()
    start_scheduler(compliance_engine, fleet_client, coa_trigger)
    logger.info("Posture Engine ready on :8000")
    yield
    await engine.dispose()


app = FastAPI(title="Open NAC Posture Engine", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ─── Models ───

class PostureCheckRequest(BaseModel):
    mac_address: str
    ip_address: str = ""
    username: str = ""
    hostname: str = ""
    os_type: str = ""  # windows, macos, linux


class PostureReportRequest(BaseModel):
    """Agent-based: endpoint self-reports compliance data."""
    mac_address: str
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    antivirus: Optional[dict] = None  # {installed: true, name: "Defender", running: true, up_to_date: true}
    firewall: Optional[dict] = None   # {enabled: true, profiles: ["domain","private","public"]}
    disk_encryption: Optional[dict] = None  # {enabled: true, type: "BitLocker", percent: 100}
    patches: Optional[dict] = None    # {last_check: "2024-01-01", pending_critical: 0, pending_total: 5}
    agent_version: str = ""


class PostureStatusResponse(BaseModel):
    mac_address: str
    status: str  # compliant, non_compliant, unknown, exempt, pending
    checks: list
    remediation: list
    last_check: str = ""


# ─── Endpoints ───

@app.get("/health")
async def health():
    return {"status": "ok", "service": "posture-engine"}


@app.post("/api/v1/posture/check")
async def check_posture(req: PostureCheckRequest, db: AsyncSession = Depends(get_db)):
    """
    Triggered after RADIUS auth — check endpoint compliance.
    Called by Policy Engine or FreeRADIUS post-auth.
    """
    mac = req.mac_address.lower().replace("-", ":")
    logger.info(f"POSTURE CHECK: mac={mac} ip={req.ip_address} user={req.username}")

    # 1. Try Fleet/osquery first (managed endpoints)
    fleet_data = await fleet_client.get_host_by_identifier(
        req.ip_address or req.hostname or mac
    )

    if fleet_data:
        result = compliance_engine.evaluate_fleet(fleet_data)
    elif req.os_type:
        # 2. No Fleet agent — use network heuristics
        result = compliance_engine.evaluate_basic(req.mac_address, req.os_type)
    else:
        result = compliance_engine.unknown_result(mac)

    # 3. Update endpoint in DB
    await _update_posture(db, mac, result)

    # 4. If status changed → trigger CoA
    await coa_trigger.check_and_coa(db, mac, result["status"])

    return result


@app.post("/api/v1/posture/report")
async def agent_report(req: PostureReportRequest, db: AsyncSession = Depends(get_db)):
    """
    Agent-based reporting: endpoint pushes compliance data directly.
    Lightweight alternative to Fleet for environments without osquery.
    """
    mac = req.mac_address.lower().replace("-", ":")
    logger.info(f"POSTURE REPORT: mac={mac} host={req.hostname} os={req.os_type}")

    result = compliance_engine.evaluate_agent_report(req)

    await _update_posture(db, mac, result)
    await coa_trigger.check_and_coa(db, mac, result["status"])

    return result


@app.get("/api/v1/posture/status/{mac_address}")
async def get_status(mac_address: str, db: AsyncSession = Depends(get_db)):
    """Get current posture status for an endpoint."""
    from sqlalchemy import text
    mac = mac_address.lower().replace("-", ":")
    r = await db.execute(text(
        "SELECT posture_status, last_posture_check FROM nac_endpoints WHERE mac_address = :mac"
    ), {"mac": mac})
    row = r.fetchone()
    if not row:
        return {"mac_address": mac, "status": "unknown", "checks": [], "remediation": []}
    return {
        "mac_address": mac,
        "status": row[0] or "unknown",
        "last_check": str(row[1]) if row[1] else "",
        "checks": [],
        "remediation": [],
    }


@app.get("/api/v1/posture/policies")
async def list_policies():
    """List active compliance policies."""
    return {"policies": [p.__dict__ for p in compliance_engine.policies]}


@app.get("/api/v1/posture/stats")
async def posture_stats(db: AsyncSession = Depends(get_db)):
    """Posture statistics across all endpoints."""
    from sqlalchemy import text
    r = await db.execute(text("""
        SELECT posture_status, COUNT(*) FROM nac_endpoints
        GROUP BY posture_status
    """))
    stats = {row[0] or "unknown": row[1] for row in r.fetchall()}
    return {
        "total": sum(stats.values()),
        "compliant": stats.get("compliant", 0),
        "non_compliant": stats.get("non_compliant", 0),
        "unknown": stats.get("unknown", 0),
        "exempt": stats.get("exempt", 0),
        "quarantined": stats.get("quarantined", 0),
    }


async def _update_posture(db, mac, result):
    from sqlalchemy import text
    try:
        await db.execute(text("""
            UPDATE nac_endpoints
            SET posture_status = :status, last_posture_check = NOW()
            WHERE mac_address = :mac
        """), {"mac": mac, "status": result["status"]})
        await db.commit()
    except Exception as e:
        logger.warning(f"Failed to update posture for {mac}: {e}")
