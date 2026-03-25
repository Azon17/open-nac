"""
/api/v1/live-log — real-time policy decision log with SSE streaming.

Endpoints:
  GET /live-log              — recent decisions (polling)
  GET /live-log/stream       — SSE stream (real-time push)
  GET /live-log/stats        — aggregated stats
  POST /live-log/test        — simulate a policy evaluation
"""

import asyncio
import json
import time
from fastapi import APIRouter, Query, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.policy_log import policy_log, PolicyLogEntry
from app.core.policy_evaluator import policy_evaluator, AuthContext

router = APIRouter()


@router.get("/live-log")
async def get_live_log(
    limit: int = Query(100, le=500),
    username: str = Query(""),
    mac: str = Query(""),
    decision: str = Query(""),
    policy_name: str = Query(""),
):
    """Get recent policy decisions from memory buffer."""
    items = policy_log.get_recent(
        limit=limit, username=username, mac=mac,
        decision=decision, policy_name=policy_name,
    )
    return {"total": len(items), "items": items}


@router.get("/live-log/stats")
async def get_live_log_stats():
    """Aggregated policy decision statistics."""
    return policy_log.get_stats()


@router.get("/live-log/stream")
async def stream_live_log():
    """Server-Sent Events stream of policy decisions in real-time."""
    queue = policy_log.subscribe()

    async def event_generator():
        try:
            # Send initial keepalive
            yield f"data: {json.dumps({'type': 'connected', 'message': 'Policy log stream connected'})}\n\n"

            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(entry, default=str)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive every 15s
                    yield f": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            policy_log.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class TestAuthRequest(BaseModel):
    username: str = "testuser"
    mac_address: str = "aa:bb:cc:dd:ee:ff"
    nas_ip: str = "10.0.1.1"
    eap_type: str = "PEAP"
    device_profile: str = "Windows Workstation"
    posture_status: str = "compliant"
    ad_groups: str = "Domain Users"


@router.post("/live-log/test")
async def test_policy_eval(req: TestAuthRequest, db: AsyncSession = Depends(get_db)):
    """Simulate a policy evaluation without actual RADIUS — for testing policies."""
    t0 = time.time()

    groups = [g.strip() for g in req.ad_groups.split(",") if g.strip()]
    ctx = AuthContext(
        username=req.username,
        mac_address=req.mac_address.lower(),
        nas_ip=req.nas_ip,
        eap_type=req.eap_type,
        ldap_groups=groups,
        device_profile=req.device_profile,
        device_category="workstation",
        posture_status=req.posture_status,
        certificate=req.eap_type.upper() in ("TLS", "EAP-TLS"),
    )

    result = await policy_evaluator.evaluate(ctx, db)
    eval_ms = (time.time() - t0) * 1000

    # Log the test evaluation
    entry = PolicyLogEntry(
        username=req.username,
        mac_address=req.mac_address,
        nas_ip=req.nas_ip,
        eap_type=req.eap_type,
        auth_method=req.eap_type,
        device_profile=req.device_profile,
        posture_status=req.posture_status,
        ad_groups=req.ad_groups,
        policy_name=result.policy_name,
        policy_id=result.policy_id,
        decision=result.decision,
        vlan=result.tunnel_private_group_id,
        acl=result.filter_id,
        url_redirect=result.url_redirect,
        eval_time_ms=round(eval_ms, 2),
        cached=False,
        radius_result="Test",
        detail="Simulated evaluation from UI",
    )
    policy_log.log(entry)

    return {
        "decision": result.decision,
        "policy_name": result.policy_name,
        "vlan": result.tunnel_private_group_id,
        "acl": result.filter_id,
        "url_redirect": result.url_redirect,
        "eval_time_ms": round(eval_ms, 2),
        "context": {
            "username": req.username,
            "mac": req.mac_address,
            "profile": req.device_profile,
            "posture": req.posture_status,
            "groups": groups,
        },
    }
