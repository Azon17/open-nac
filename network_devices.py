"""
/api/v1/network-devices — управление NAS (коммутаторы, WLC, VPN).
Заменяет ручное редактирование clients.conf.
FreeRADIUS читает NAS из SQL (read_clients = yes).
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db

router = APIRouter()


class NASCreate(BaseModel):
    nasname: str  # IP или subnet
    shortname: str
    type: str = "cisco"
    secret: str
    ports: Optional[int] = None
    server: Optional[str] = None
    community: Optional[str] = None
    description: str = ""


class NASUpdate(BaseModel):
    shortname: Optional[str] = None
    type: Optional[str] = None
    secret: Optional[str] = None
    description: Optional[str] = None


@router.get("/network-devices")
async def list_nas(
    search: str = Query(""),
    limit: int = Query(100),
    db: AsyncSession = Depends(get_db),
):
    if search:
        result = await db.execute(
            text("SELECT * FROM nas WHERE nasname LIKE :s OR shortname LIKE :s OR description LIKE :s ORDER BY id"),
            {"s": f"%{search}%"},
        )
    else:
        result = await db.execute(text("SELECT * FROM nas ORDER BY id LIMIT :limit"), {"limit": limit})

    rows = result.mappings().all()
    # Маскируем secret
    items = []
    for r in rows:
        d = dict(r)
        d["secret"] = "••••••••••"
        items.append(d)

    return {"total": len(items), "items": items}


@router.post("/network-devices")
async def create_nas(nas: NASCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(
        text("""
            INSERT INTO nas (nasname, shortname, type, secret, ports, server, community, description)
            VALUES (:nasname, :shortname, :type, :secret, :ports, :server, :community, :desc)
        """),
        {
            "nasname": nas.nasname, "shortname": nas.shortname, "type": nas.type,
            "secret": nas.secret, "ports": nas.ports, "server": nas.server,
            "community": nas.community, "desc": nas.description,
        },
    )
    await db.commit()
    return {"status": "created", "nasname": nas.nasname}


@router.put("/network-devices/{nas_id}")
async def update_nas(nas_id: int, nas: NASUpdate, db: AsyncSession = Depends(get_db)):
    updates = {k: v for k, v in nas.model_dump().items() if v is not None}
    if not updates:
        return {"error": "no_changes"}

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates["id"] = nas_id
    await db.execute(text(f"UPDATE nas SET {set_clause} WHERE id = :id"), updates)
    await db.commit()
    return {"status": "updated", "id": nas_id}


@router.delete("/network-devices/{nas_id}")
async def delete_nas(nas_id: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nas WHERE id = :id"), {"id": nas_id})
    await db.commit()
    return {"status": "deleted", "id": nas_id}
