"""
/api/v1/authorize — called by FreeRADIUS rlm_rest on every auth request.
Returns RADIUS reply attributes (VLAN, ACL, URL-redirect) based on policies.

Flow:
  1. FreeRADIUS receives Access-Request from switch
  2. FreeRADIUS calls POST /api/v1/authorize with user/device context
  3. Policy Engine evaluates policies (AD group, device profile, posture, cert)
  4. Returns RADIUS attributes → FreeRADIUS adds to Access-Accept/Reject
"""

import logging
import time
from datetime import datetime
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.policy_evaluator import policy_evaluator, AuthContext
from app.core.redis_client import redis_pool
from app.core.policy_log import policy_log, PolicyLogEntry

logger = logging.getLogger("nac.authorize")
router = APIRouter()


class AuthorizeRequest(BaseModel):
    username: str = ""
    mac_address: str = ""
    nas_ip: str = ""
    nas_port: str = ""
    nas_port_type: str = ""
    called_station_id: str = ""
    eap_type: str = "none"
    service_type: str = ""
    framed_ip: str = ""


class ProfileRequest(BaseModel):
    mac_address: str
    ip_address: str = ""
    user_agent: str = ""
    dhcp_fingerprint: str = ""
    dhcp_vendor: str = ""


class RedirectRequest(BaseModel):
    mac_address: str
    nas_ip: str
    redirect_type: str = "guest_registration"


@router.post("/authorize")
async def authorize(req: AuthorizeRequest, db: AsyncSession = Depends(get_db)):
    """
    Main authorization endpoint — called by FreeRADIUS on every Access-Request.
    Evaluates policies and returns VLAN/ACL/redirect.
    """
    mac = req.mac_address.lower().replace("-", ":") if req.mac_address else ""

    _t0 = time.time()
    logger.info(f"AUTH REQUEST: user={req.username} mac={mac} nas={req.nas_ip} eap={req.eap_type}")

    # Check cache first
    if mac:
        cached = await redis_pool.get_cached_auth(mac)
        if cached:
            logger.info(f"AUTH CACHED: mac={mac} → {cached.get('policy_name', 'unknown')}")
            return cached

    # Look up endpoint in DB
    ep_data = {"profile": "Unknown", "category": "unknown", "posture": "unknown", "groups": ""}
    if mac:
        ep_result = await db.execute(
            text("SELECT device_profile, device_category, posture_status, ad_groups, username "
                 "FROM nac_endpoints WHERE mac_address = :mac"),
            {"mac": mac},
        )
        ep = ep_result.fetchone()
        if ep:
            ep_data = {
                "profile": ep[0] or "Unknown",
                "category": ep[1] or "unknown",
                "posture": ep[2] or "unknown",
                "groups": ep[3] or "",
            }

    # Check certificate status if EAP-TLS
    cert_valid = False
    if req.eap_type and req.eap_type.upper() in ("TLS", "EAP-TLS"):
        cert_valid = True
        # Check if cert is revoked
        if req.username:
            cert_result = await db.execute(
                text("SELECT status FROM nac_certificates WHERE username = :u AND status = 'active' LIMIT 1"),
                {"u": req.username}
            )
            cert_row = cert_result.fetchone()
            cert_valid = cert_row is not None

    # Determine auth method for policy matching
    auth_method = req.eap_type or "none"
    if req.service_type == "Call-Check":
        auth_method = "MAB"

    # Build context for policy evaluation
    groups = [g.strip() for g in ep_data["groups"].split(",") if g.strip()]
    ctx = AuthContext(
        username=req.username,
        mac_address=mac,
        nas_ip=req.nas_ip,
        nas_port=req.nas_port,
        eap_type=auth_method,
        service_type=req.service_type,
        framed_ip=req.framed_ip,
        ldap_groups=groups,
        ad_department="",
        device_profile=ep_data["profile"],
        device_category=ep_data["category"],
        posture_status=ep_data["posture"],
        certificate=cert_valid,
    )

    # Evaluate policies
    result = await policy_evaluator.evaluate(ctx, db)

    logger.info(
        f"AUTH DECISION: user={req.username} mac={mac} "
        f"→ policy='{result.policy_name}' vlan={result.tunnel_private_group_id} "
        f"acl={result.filter_id} decision={result.decision}"
    )

    # Build response
    response = result.to_radius_dict()

    # Update endpoint record
    if mac:
        await _update_endpoint(db, mac, req, result)

    # Cache the result (TTL 5 min)
    if mac:
        await redis_pool.cache_auth_result(mac, response, ttl=300)

    return response


@router.post("/profile")
async def profile_endpoint(req: ProfileRequest, db: AsyncSession = Depends(get_db)):
    """Called by FreeRADIUS post-auth to trigger profiling."""
    mac = req.mac_address.lower().replace("-", ":")
    await db.execute(
        text("""
            INSERT INTO nac_endpoints (mac_address, ip_address, user_agent, dhcp_fingerprint, dhcp_vendor, last_seen)
            VALUES (:mac, :ip, :ua, :dhcp_fp, :dhcp_v, NOW())
            ON DUPLICATE KEY UPDATE
                ip_address = COALESCE(:ip, ip_address),
                user_agent = COALESCE(:ua, user_agent),
                dhcp_fingerprint = COALESCE(:dhcp_fp, dhcp_fingerprint),
                dhcp_vendor = COALESCE(:dhcp_v, dhcp_vendor),
                last_seen = NOW()
        """),
        {"mac": mac, "ip": req.ip_address or None, "ua": req.user_agent or None,
         "dhcp_fp": req.dhcp_fingerprint or None, "dhcp_v": req.dhcp_vendor or None},
    )
    await db.commit()
    return {"status": "profiled", "mac": mac}


@router.post("/redirect-url")
async def redirect_url(req: RedirectRequest):
    """Build captive portal redirect URL."""
    portal_base = "https://portal.nac.local:8443"
    urls = {
        "guest_registration": f"{portal_base}/guest/register?mac={req.mac_address}",
        "byod_onboarding": f"{portal_base}/byod/enroll?mac={req.mac_address}",
        "posture_remediation": f"{portal_base}/remediation?mac={req.mac_address}",
    }
    return {
        "url-redirect": urls.get(req.redirect_type, urls["guest_registration"]),
        "url-redirect-acl": "ACL-WEBAUTH-REDIRECT",
    }


async def _update_endpoint(db: AsyncSession, mac: str, req, result):
    """Update endpoint record with auth result."""
    try:
        await db.execute(
            text("""
                INSERT INTO nac_endpoints (mac_address, ip_address, username, nas_ip, nas_port,
                    auth_method, auth_status, assigned_vlan, last_seen, last_auth)
                VALUES (:mac, :ip, :user, :nas, :port, :method, :status, :vlan, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    ip_address = COALESCE(:ip, ip_address),
                    username = COALESCE(:user, username),
                    nas_ip = :nas,
                    nas_port = :port,
                    auth_method = :method,
                    auth_status = :status,
                    assigned_vlan = :vlan,
                    last_seen = NOW(),
                    last_auth = NOW()
            """),
            {
                "mac": mac,
                "ip": req.framed_ip or None,
                "user": req.username or None,
                "nas": req.nas_ip,
                "port": req.nas_port,
                "method": req.eap_type or "PAP",
                "status": "authenticated" if result.decision == "permit" else "rejected",
                "vlan": result.tunnel_private_group_id,
            },
        )
        await db.commit()
    except Exception as e:
        logger.warning(f"Failed to update endpoint {mac}: {e}")
