"""
/api/v1/profile — вызывается FreeRADIUS для профилирования устройства.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.kafka_producer import kafka_producer

router = APIRouter()


class ProfileRequest(BaseModel):
    mac_address: str
    ip_address: str = ""
    nas_ip: str = ""
    nas_port: str = ""
    called_station_id: str = ""
    username: str = ""
    dhcp_vendor_class: str = ""
    dhcp_hostname: str = ""
    user_agent: str = ""
    eap_type: str = "none"


@router.post("/profile")
async def profile_endpoint(req: ProfileRequest, db: AsyncSession = Depends(get_db)):
    """Принимает profiling-данные от FreeRADIUS, обновляет БД, публикует в Kafka."""
    mac = req.mac_address.lower()

    # Обновляем DHCP/UA данные в nac_endpoints
    await db.execute(
        text("""
            UPDATE nac_endpoints SET
                dhcp_vendor = COALESCE(NULLIF(:dhcp_vendor, ''), dhcp_vendor),
                dhcp_fingerprint = COALESCE(NULLIF(:dhcp_hostname, ''), dhcp_fingerprint),
                user_agent = COALESCE(NULLIF(:ua, ''), user_agent),
                last_profiled = NOW()
            WHERE mac_address = :mac
        """),
        {"mac": mac, "dhcp_vendor": req.dhcp_vendor_class, "dhcp_hostname": req.dhcp_hostname, "ua": req.user_agent},
    )
    await db.commit()

    # Публикуем в Kafka для async-обработки profiler'ом
    await kafka_producer.profile_event(mac, {
        "mac_address": mac,
        "ip_address": req.ip_address,
        "dhcp_vendor_class": req.dhcp_vendor_class,
        "dhcp_hostname": req.dhcp_hostname,
        "user_agent": req.user_agent,
        "eap_type": req.eap_type,
    })

    return {"status": "queued", "mac": mac}
