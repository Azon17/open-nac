"""
Kafka consumer — читает profiling-события и вызывает scoring engine.
"""

import os
import json
import logging
from typing import Optional

import aiomysql
from aiokafka import AIOKafkaConsumer

from app.engines.scoring import ScoringEngine, ProfileData, ProfileResult

logger = logging.getLogger("nac.profiler.consumer")

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPICS = ["nac.endpoint.profiles", "nac.profiler.raw"]
GROUP_ID = "nac-profiler-group"

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "proxysql"),
    "port": int(os.getenv("MYSQL_PORT", "6033")),
    "user": os.getenv("MYSQL_USER", "radius"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme_radius_pwd"),
    "db": os.getenv("MYSQL_DATABASE", "radius"),
    "charset": "utf8mb4",
}

POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "http://policy-engine:8000")


class ProfileConsumer:
    def __init__(self, scoring_engine: ScoringEngine):
        self.scoring = scoring_engine
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.db_pool: Optional[aiomysql.Pool] = None

    async def start(self):
        # DB pool
        self.db_pool = await aiomysql.create_pool(**DB_CONFIG, minsize=2, maxsize=10)

        # Kafka consumer
        self.consumer = AIOKafkaConsumer(
            *TOPICS,
            bootstrap_servers=BOOTSTRAP,
            group_id=GROUP_ID,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
            auto_commit_interval_ms=5000,
        )
        await self.consumer.start()
        logger.info(f"Consuming from {TOPICS}")

        # Запускаем обработку
        import asyncio
        asyncio.create_task(self._consume_loop())

    async def stop(self):
        if self.consumer:
            await self.consumer.stop()
        if self.db_pool:
            self.db_pool.close()
            await self.db_pool.wait_closed()

    async def _consume_loop(self):
        async for msg in self.consumer:
            try:
                await self._process_message(msg.value)
            except Exception as e:
                logger.error(f"Error processing message: {e}", exc_info=True)

    async def _process_message(self, data: dict):
        mac = data.get("mac_address", "").lower()
        if not mac:
            return

        # Собираем данные для профилирования
        profile_data = ProfileData(
            mac_address=mac,
            dhcp_fingerprint=data.get("dhcp_vendor_class", ""),
            dhcp_hostname=data.get("dhcp_hostname", ""),
            user_agent=data.get("user_agent", ""),
            ip_address=data.get("ip_address", ""),
            eap_type=data.get("eap_type", ""),
        )

        # Получаем текущий профиль из БД
        current_profile = await self._get_current_profile(mac)

        # Запускаем scoring
        result = await self.scoring.evaluate(profile_data)

        if not result or not result.device_name:
            return

        # Проверяем: изменился ли профиль?
        profile_changed = (
            current_profile is None
            or current_profile.get("device_profile") != result.device_name
        )

        # Обновляем БД
        await self._update_endpoint(mac, result)

        if profile_changed and current_profile:
            old_profile = current_profile.get("device_profile", "Unknown")
            logger.info(
                f"Profile changed: {mac} [{old_profile}] → [{result.device_name}] "
                f"(confidence: {result.confidence:.0%})"
            )

            # Если профиль изменился — можем инициировать CoA
            # чтобы устройство получило новый VLAN на основе нового профиля
            if result.confidence >= 0.7:
                await self._trigger_coa(mac)

    async def _get_current_profile(self, mac: str) -> Optional[dict]:
        async with self.db_pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(
                    "SELECT device_profile, device_category, profile_confidence "
                    "FROM nac_endpoints WHERE mac_address = %s",
                    (mac,),
                )
                return await cur.fetchone()

    async def _update_endpoint(self, mac: str, result: "ProfileResult"):
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO nac_endpoints
                        (mac_address, device_profile, device_category, device_vendor,
                         profile_confidence, fingerbank_device_id, last_profiled)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                        device_profile = VALUES(device_profile),
                        device_category = VALUES(device_category),
                        device_vendor = VALUES(device_vendor),
                        profile_confidence = VALUES(profile_confidence),
                        fingerbank_device_id = VALUES(fingerbank_device_id),
                        last_profiled = NOW()
                    """,
                    (
                        mac, result.device_name, result.category,
                        result.vendor, result.confidence,
                        result.fingerbank_id,
                    ),
                )
            await conn.commit()

    async def _trigger_coa(self, mac: str):
        """Вызываем Policy Engine API для отправки CoA."""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{POLICY_ENGINE_URL}/api/v1/coa/send",
                    json={"mac_address": mac, "action": "reauthenticate"},
                )
                if resp.status_code == 200:
                    logger.info(f"CoA triggered for {mac} after profile change")
                else:
                    logger.warning(f"CoA failed for {mac}: {resp.text}")
        except Exception as e:
            logger.error(f"CoA request failed: {e}")
