"""
/api/v1/coa — отправка CoA на NAD (Admin UI + automation).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.coa_client import coa_client
from app.core.redis_client import redis_pool
from app.core.kafka_producer import kafka_producer

router = APIRouter()


class CoAAction(BaseModel):
    mac_address: str
    action: str  # reauthenticate | disconnect | bounce-port
    nas_ip: str = ""  # если пусто — ищем в Redis session directory


@router.post("/coa/send")
async def send_coa(req: CoAAction, db: AsyncSession = Depends(get_db)):
    mac = req.mac_address.lower()

    # Определяем NAS IP
    nas_ip = req.nas_ip
    session_id = ""

    if not nas_ip:
        session = await redis_pool.get_session(mac)
        if session:
            nas_ip = session.get("nas_ip", "")
            session_id = session.get("session_id", "")
        else:
            ep = await db.execute(
                text("SELECT nas_ip FROM nac_endpoints WHERE mac_address = :mac"),
                {"mac": mac},
            )
            row = ep.fetchone()
            nas_ip = row[0] if row else ""

    if not nas_ip:
        return {"success": False, "error": "Cannot determine NAS IP for this endpoint"}

    # Отправляем CoA
    if req.action == "reauthenticate":
        result = await coa_client.send_reauth(nas_ip, mac, session_id)
    elif req.action == "disconnect":
        result = await coa_client.send_disconnect(nas_ip, mac, session_id)
    elif req.action == "bounce-port":
        result = await coa_client.send_bounce(nas_ip, mac)
    else:
        return {"success": False, "error": f"Unknown action: {req.action}"}

    # Публикуем в Kafka
    await kafka_producer.coa_event(mac, {
        "mac_address": mac, "nas_ip": nas_ip, "action": req.action,
        "success": result.get("success", False),
    })

    return {"success": result.get("success", False), "nas_ip": nas_ip, "action": req.action, "detail": result}


@router.post("/coa/bulk")
async def bulk_coa(macs: list[str], action: str = "reauthenticate", db: AsyncSession = Depends(get_db)):
    """Mass CoA — например, после обновления политики."""
    results = []
    for mac in macs[:100]:  # лимит 100 за раз
        r = await send_coa(CoAAction(mac_address=mac, action=action), db)
        results.append({"mac": mac, **r})
    return {"total": len(results), "results": results}
