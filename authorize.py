"""
/api/v1/authorize — вызывается FreeRADIUS в post-auth.
Возвращает VLAN, ACL, URL-redirect на основе политик.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.policy_evaluator import policy_evaluator, AuthContext
from app.core.redis_client import redis_pool

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
    ldap_groups: str = ""
    ad_department: str = ""
    radius_node: str = ""


class RedirectRequest(BaseModel):
    mac_address: str
    nas_ip: str
    redirect_type: str = "guest_registration"


@router.post("/authorize")
async def authorize(req: AuthorizeRequest, db: AsyncSession = Depends(get_db)):
    """Принимает решение об авторизации для FreeRADIUS."""

    # Проверяем кэш
    cached = await redis_pool.get_cached_auth(req.mac_address)
    if cached:
        return cached

    # Получаем профиль устройства из БД
    ep_result = await db.execute(
        text("SELECT device_profile, device_category, posture_status FROM nac_endpoints WHERE mac_address = :mac"),
        {"mac": req.mac_address.lower()},
    )
    ep = ep_result.fetchone()

    # Строим контекст
    groups = [g.strip() for g in req.ldap_groups.split(",") if g.strip()]
    ctx = AuthContext(
        username=req.username,
        mac_address=req.mac_address.lower(),
        nas_ip=req.nas_ip,
        nas_port=req.nas_port,
        eap_type=req.eap_type,
        service_type=req.service_type,
        framed_ip=req.framed_ip,
        ldap_groups=groups,
        ad_department=req.ad_department,
        device_profile=ep[0] if ep else "Unknown",
        device_category=ep[1] if ep else "unknown",
        posture_status=ep[2] if ep else "unknown",
        certificate=req.eap_type in ("TLS", "EAP-TLS"),
    )

    # Оцениваем политики
    result = await policy_evaluator.evaluate(ctx, db)
    response = result.to_radius_dict()

    # Кэшируем результат
    await redis_pool.cache_auth_result(req.mac_address, response)

    return response


@router.post("/redirect-url")
async def redirect_url(req: RedirectRequest):
    """Формирует URL для captive portal redirect."""
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
