"""
Open NAC — Profiler Service
Эквивалент: Cisco ISE Profiler + Fingerbank

Kafka consumer, который:
  1. Читает события из nac.profiler.raw и nac.endpoint.profiles
  2. Анализирует DHCP fingerprint, User-Agent, MAC OUI через Fingerbank API
  3. Опционально запускает p0f (passive OS fingerprint) и nmap (active scan)
  4. Вычисляет composite confidence score
  5. Обновляет device_profile в MariaDB
  6. При смене профиля → отправляет CoA через Policy Engine API

Запуск: python -m app.main
"""

import os
import asyncio
import logging
import signal

from app.consumers.kafka_consumer import ProfileConsumer
from app.engines.scoring import ScoringEngine
from app.engines.fingerbank_engine import FingerbankEngine
from app.engines.mac_oui_engine import MACOUIEngine
from app.engines.useragent_engine import UserAgentEngine

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nac.profiler")


async def main():
    logger.info("Starting Open NAC Profiler Service...")

    # Инициализируем движки профилирования
    fingerbank = FingerbankEngine(api_key=os.getenv("FINGERBANK_API_KEY", ""))
    mac_oui = MACOUIEngine()
    useragent = UserAgentEngine()

    scoring = ScoringEngine(
        engines={
            "fingerbank": (fingerbank, 0.40),   # вес 40%
            "mac_oui": (mac_oui, 0.15),         # вес 15%
            "useragent": (useragent, 0.20),      # вес 20%
            # p0f и nmap добавляются опционально
        }
    )

    # Запускаем Kafka consumer
    consumer = ProfileConsumer(scoring_engine=scoring)

    # Graceful shutdown
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def shutdown():
        logger.info("Shutting down profiler...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    try:
        await consumer.start()
        logger.info("Profiler ready — consuming from Kafka")
        await stop_event.wait()
    finally:
        await consumer.stop()
        logger.info("Profiler stopped")


if __name__ == "__main__":
    asyncio.run(main())
