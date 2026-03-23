"""
/api/v1/guest-accounts — управление гостевыми аккаунтами.
"""

import secrets
import hashlib
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db

router = APIRouter()


class GuestCreate(BaseModel):
    email: str = ""
    phone: str = ""
    sponsor: str = ""
    company: str = ""
    duration_hours: int = 24
    max_devices: int = 3


class GuestOut(BaseModel):
    username: str
    password: str  # plaintext, только при создании
    valid_until: str


@router.get("/guest-accounts")
async def list_guests(
    status: str = Query("", description="active, expired, disabled, pending"),
    limit: int = Query(100),
    db: AsyncSession = Depends(get_db),
):
    if status:
        result = await db.execute(
            text("SELECT id, username, email, phone, sponsor, company, valid_from, valid_until, max_devices, status, created_at FROM nac_guest_accounts WHERE status = :s ORDER BY created_at DESC LIMIT :limit"),
            {"s": status, "limit": limit},
        )
    else:
        result = await db.execute(
            text("SELECT id, username, email, phone, sponsor, company, valid_from, valid_until, max_devices, status, created_at FROM nac_guest_accounts ORDER BY created_at DESC LIMIT :limit"),
            {"limit": limit},
        )
    rows = result.mappings().all()
    return {"total": len(rows), "items": [dict(r) for r in rows]}


@router.post("/guest-accounts")
async def create_guest(guest: GuestCreate, db: AsyncSession = Depends(get_db)):
    username = f"guest_{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(8)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    valid_until = datetime.utcnow() + timedelta(hours=guest.duration_hours)

    await db.execute(
        text("""
            INSERT INTO nac_guest_accounts (username, password_hash, email, phone, sponsor, company, valid_until, max_devices, status)
            VALUES (:u, :p, :email, :phone, :sponsor, :company, :valid, :max, 'active')
        """),
        {"u": username, "p": password_hash, "email": guest.email, "phone": guest.phone,
         "sponsor": guest.sponsor, "company": guest.company, "valid": valid_until, "max": guest.max_devices},
    )

    # Также создаём RADIUS-учётку для аутентификации
    await db.execute(
        text("INSERT INTO radcheck (username, attribute, op, value) VALUES (:u, 'Cleartext-Password', ':=', :p)"),
        {"u": username, "p": password},
    )
    await db.execute(
        text("INSERT INTO radusergroup (username, groupname, priority) VALUES (:u, 'guests', 1)"),
        {"u": username},
    )
    await db.commit()

    return {"username": username, "password": password, "valid_until": str(valid_until)}


@router.delete("/guest-accounts/{guest_id}")
async def delete_guest(guest_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("SELECT username FROM nac_guest_accounts WHERE id = :id"), {"id": guest_id})
    row = result.fetchone()
    if row:
        username = row[0]
        await db.execute(text("DELETE FROM radcheck WHERE username = :u"), {"u": username})
        await db.execute(text("DELETE FROM radusergroup WHERE username = :u"), {"u": username})
        await db.execute(text("DELETE FROM nac_guest_accounts WHERE id = :id"), {"id": guest_id})
        await db.commit()
    return {"status": "deleted"}
