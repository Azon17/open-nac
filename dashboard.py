"""
/api/v1/dashboard — агрегированная статистика для Overview.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.redis_client import redis_pool

router = APIRouter()


@router.get("/dashboard/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    # Endpoints
    total = (await db.execute(text("SELECT COUNT(*) FROM nac_endpoints"))).scalar() or 0
    compliant = (await db.execute(text("SELECT COUNT(*) FROM nac_endpoints WHERE posture_status='compliant'"))).scalar() or 0
    non_compliant = (await db.execute(text("SELECT COUNT(*) FROM nac_endpoints WHERE posture_status='non_compliant'"))).scalar() or 0
    unknown_profile = (await db.execute(text("SELECT COUNT(*) FROM nac_endpoints WHERE device_profile='Unknown' OR device_profile IS NULL"))).scalar() or 0

    # Sites
    sites = (await db.execute(text("SELECT COUNT(DISTINCT site_id) FROM nac_endpoints WHERE site_id IS NOT NULL"))).scalar() or 0

    # Auth counters from Redis
    auth_accept = await redis_pool.get_counter("auth:access-accept")
    auth_reject = await redis_pool.get_counter("auth:access-reject")

    # Categories
    cats_result = await db.execute(text(
        "SELECT COALESCE(device_category, 'unknown') as cat, COUNT(*) as cnt "
        "FROM nac_endpoints GROUP BY device_category ORDER BY cnt DESC"
    ))
    categories = [{"category": r[0], "count": r[1]} for r in cats_result.fetchall()]

    # Recent auth (last 10)
    recent_result = await db.execute(text(
        "SELECT username, pass, reply, authdate, callingstationid, nasipaddress "
        "FROM radpostauth ORDER BY id DESC LIMIT 10"
    ))
    recent = [
        {"username": r[0], "result": r[2], "time": str(r[3]), "mac": r[4], "nas": r[5]}
        for r in recent_result.fetchall()
    ]

    return {
        "endpoints": {"total": total, "compliant": compliant, "non_compliant": non_compliant, "unknown_profile": unknown_profile},
        "sites": sites,
        "auth": {"accept": auth_accept, "reject": auth_reject, "reject_rate": round(auth_reject / max(auth_accept + auth_reject, 1) * 100, 1)},
        "categories": categories,
        "recent_auth": recent,
    }
