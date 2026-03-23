"""
Kafka producer: публикация NAC-событий (auth, session, profile, posture, CoA).
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from aiokafka import AIOKafkaProducer

logger = logging.getLogger("nac.kafka")

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")


class KafkaEventProducer:
    def __init__(self):
        self.producer: Optional[AIOKafkaProducer] = None

    async def start(self):
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                compression_type="gzip",
            )
            await self.producer.start()
            logger.info(f"Kafka producer connected to {BOOTSTRAP}")
        except Exception as e:
            logger.warning(f"Kafka unavailable ({e}), events will be dropped")
            self.producer = None

    async def stop(self):
        if self.producer:
            await self.producer.stop()

    async def publish(self, topic: str, key: str, data: dict):
        if not self.producer:
            return
        data["_ts"] = datetime.now(timezone.utc).isoformat()
        try:
            await self.producer.send_and_wait(topic, key=key, value=data)
        except Exception as e:
            logger.error(f"Kafka publish failed: {e}")

    # ── Convenience methods ──

    async def auth_event(self, mac: str, data: dict):
        await self.publish("nac.auth.events", mac, data)

    async def session_event(self, mac: str, data: dict):
        await self.publish("nac.session.state", mac, data)

    async def profile_event(self, mac: str, data: dict):
        await self.publish("nac.endpoint.profiles", mac, data)

    async def posture_event(self, mac: str, data: dict):
        await self.publish("nac.posture.status", mac, data)

    async def coa_event(self, mac: str, data: dict):
        await self.publish("nac.coa.requests", mac, data)


kafka_producer = KafkaEventProducer()
