"""
/api/v1/events — приём событий от FreeRADIUS → Kafka.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.kafka_producer import kafka_producer
from app.core.redis_client import redis_pool

router = APIRouter()


class AuthEvent(BaseModel):
    event_type: str = "authentication"
    timestamp: str = ""
    username: str = ""
    mac_address: str = ""
    ip_address: str = ""
    nas_ip: str = ""
    nas_port: str = ""
    auth_result: str = ""
    eap_type: str = ""
    vlan: str = ""
    radius_node: str = ""


class SessionEvent(BaseModel):
    event_type: str = "accounting"
    acct_status: str = ""
    timestamp: str = ""
    username: str = ""
    mac_address: str = ""
    ip_address: str = ""
    nas_ip: str = ""
    session_id: str = ""
    session_time: str = "0"
    input_octets: str = "0"
    output_octets: str = "0"
    terminate_cause: str = ""


@router.post("/events/auth")
async def receive_auth_event(event: AuthEvent):
    mac = event.mac_address.lower()
    await kafka_producer.auth_event(mac, event.model_dump())
    await redis_pool.incr_counter(f"auth:{event.auth_result.lower()}")
    return {"status": "published"}


@router.post("/events/session")
async def receive_session_event(event: SessionEvent):
    mac = event.mac_address.lower()

    if event.acct_status == "Start":
        await redis_pool.set_session(mac, {
            "nas_ip": event.nas_ip, "session_id": event.session_id,
            "username": event.username, "ip_address": event.ip_address,
        })
    elif event.acct_status == "Stop":
        await redis_pool.delete_session(mac)

    await kafka_producer.session_event(mac, event.model_dump())
    return {"status": "published"}
