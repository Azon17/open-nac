"""
/api/v1/endpoints — управление эндпоинтами (Admin UI).
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db

router = APIRouter()


class EndpointOut(BaseModel):
    id: int
    mac_address: str
    ip_address: Optional[str]
    hostname: Optional[str]
    username: Optional[str]
    device_profile: Optional[str]
    device_category: Optional[str]
    profile_confidence: float = 0
    posture_status: str = "unknown"
    auth_status: str = "unknown"
    auth_method: Optional[str]
    assigned_vlan: Optional[str]
    nas_ip: Optional[str]
    nas_port: Optional[str]
    site_id: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@router.get("/endpoints")
async def list_endpoints(
    search: str = Query("", description="Search MAC, IP, username, profile"),
    posture: str = Query("", description="Filter: compliant, non_compliant, unknown, exempt"),
    site: str = Query(""),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    where_clauses = ["1=1"]
    params = {}

    if search:
        where_clauses.append(
            "(mac_address LIKE :search OR ip_address LIKE :search "
            "OR username LIKE :search OR device_profile LIKE :search)"
        )
        params["search"] = f"%{search}%"
    if posture:
        where_clauses.append("posture_status = :posture")
        params["posture"] = posture
    if site:
        where_clauses.append("site_id = :site")
        params["site"] = site

    where = " AND ".join(where_clauses)
    params["limit"] = limit
    params["offset"] = offset

    count_result = await db.execute(text(f"SELECT COUNT(*) FROM nac_endpoints WHERE {where}"), params)
    total = count_result.scalar()

    result = await db.execute(
        text(f"SELECT * FROM nac_endpoints WHERE {where} ORDER BY last_seen DESC LIMIT :limit OFFSET :offset"),
        params,
    )
    rows = result.mappings().all()

    return {"total": total, "items": [dict(r) for r in rows]}


@router.get("/endpoints/{mac}")
async def get_endpoint(mac: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        text("SELECT * FROM nac_endpoints WHERE mac_address = :mac"),
        {"mac": mac.lower()},
    )
    row = result.mappings().fetchone()
    if not row:
        return {"error": "not_found"}
    return dict(row)


@router.put("/endpoints/{mac}")
async def update_endpoint(mac: str, data: dict, db: AsyncSession = Depends(get_db)):
    allowed = {"device_profile", "device_category", "posture_status", "assigned_vlan", "site_id", "notes"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return {"error": "no_valid_fields"}

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates["mac"] = mac.lower()
    await db.execute(text(f"UPDATE nac_endpoints SET {set_clause} WHERE mac_address = :mac"), updates)
    await db.commit()
    return {"status": "updated", "mac": mac}


@router.delete("/endpoints/{mac}")
async def delete_endpoint(mac: str, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_endpoints WHERE mac_address = :mac"), {"mac": mac.lower()})
    await db.commit()
    return {"status": "deleted", "mac": mac}
