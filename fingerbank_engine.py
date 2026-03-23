"""
Fingerbank Engine — идентификация устройств через Fingerbank API.
Эквивалент: Cisco ISE Profiler с Device Sensor.

Fingerbank анализирует:
  - DHCP Option 55 (Parameter Request List) — основной сигнал
  - DHCP Option 60 (Vendor Class)
  - MAC OUI prefix
  - User-Agent
  - mDNS/UPnP (если доступно)

API: https://api.fingerbank.org/api/v2/combinations/interrogate
Бесплатно: 300 запросов/час. С ключом: 5000/час.
"""

import os
import logging
from typing import Optional

import httpx

from app.engines.scoring import ProfileData, EngineResult

logger = logging.getLogger("nac.profiler.fingerbank")

API_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"


class FingerbankEngine:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("FINGERBANK_API_KEY", "")
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.warning("Fingerbank API key not set — engine disabled. Get one at https://fingerbank.org")

    async def identify(self, data: ProfileData) -> Optional[EngineResult]:
        if not self.enabled:
            return None

        # Формируем запрос
        # Fingerbank принимает DHCP fingerprint как comma-separated option numbers
        # Но мы получаем vendor class — используем что есть
        params = {}

        if data.dhcp_fingerprint:
            params["dhcp_fingerprint"] = data.dhcp_fingerprint

        if data.user_agent:
            params["user_agents"] = [data.user_agent]

        if data.mac_address:
            # Первые 3 октета = OUI
            params["mac"] = data.mac_address

        if data.dhcp_hostname:
            params["hostname"] = data.dhcp_hostname

        if not params:
            return None

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    API_URL,
                    params={"key": self.api_key, **self._flatten_params(params)},
                    headers={"Accept": "application/json"},
                )

                if resp.status_code == 404:
                    logger.debug(f"Fingerbank: no match for {data.mac_address}")
                    return None

                if resp.status_code == 429:
                    logger.warning("Fingerbank: rate limit exceeded")
                    return None

                if resp.status_code != 200:
                    logger.warning(f"Fingerbank API error: {resp.status_code}")
                    return None

                result = resp.json()
                return self._parse_response(result, data.mac_address)

        except httpx.TimeoutException:
            logger.warning("Fingerbank API timeout")
            return None
        except Exception as e:
            logger.error(f"Fingerbank error: {e}")
            return None

    def _parse_response(self, data: dict, mac: str) -> Optional[EngineResult]:
        """Парсим ответ Fingerbank API."""
        device = data.get("device", {})
        if not device:
            return None

        device_name = device.get("name", "")
        device_id = device.get("id", 0)

        # Извлекаем категорию из иерархии
        parents = device.get("parents", [])
        category = "unknown"
        vendor = ""

        if parents:
            # Верхний уровень = категория (Computer, Phone, Printer, IoT, etc.)
            top_parent = parents[-1] if parents else {}
            category = self._map_category(top_parent.get("name", ""))

        # Vendor из имени или parents
        if "Apple" in device_name:
            vendor = "Apple"
        elif "Samsung" in device_name:
            vendor = "Samsung"
        elif "Cisco" in device_name:
            vendor = "Cisco"
        elif "HP" in device_name or "Hewlett" in device_name:
            vendor = "HP"
        else:
            # Пытаемся извлечь из parent
            for p in parents:
                pname = p.get("name", "")
                if pname and pname not in ("Device", "Computer", "Phone", "Printer"):
                    vendor = pname
                    break

        # Confidence: Fingerbank возвращает score 0-100
        score = data.get("score", 50)
        confidence = min(score / 100.0, 1.0)

        logger.info(
            f"Fingerbank identified {mac}: {device_name} "
            f"(id={device_id}, category={category}, confidence={confidence:.0%})"
        )

        return EngineResult(
            device_name=device_name,
            category=category,
            vendor=vendor,
            confidence=confidence,
            fingerbank_id=device_id,
            source="fingerbank",
        )

    def _map_category(self, fb_category: str) -> str:
        """Маппим Fingerbank-категории на наши."""
        mapping = {
            "Computer": "workstation",
            "Windows": "workstation",
            "Mac OS X": "workstation",
            "Linux": "workstation",
            "Phone": "mobile",
            "Tablet": "mobile",
            "VoIP Device": "voip",
            "IP Phone": "voip",
            "Printer": "peripheral",
            "Scanner": "peripheral",
            "Gaming Console": "iot",
            "Camera": "iot",
            "IoT": "iot",
            "Smart TV": "iot",
            "Network Device": "infrastructure",
            "Switch": "infrastructure",
            "Router": "infrastructure",
            "Access Point": "infrastructure",
        }
        for key, value in mapping.items():
            if key.lower() in fb_category.lower():
                return value
        return "unknown"

    def _flatten_params(self, params: dict) -> dict:
        """Flatten nested params for HTTP query string."""
        flat = {}
        for k, v in params.items():
            if isinstance(v, list):
                flat[f"{k}[]"] = v[0] if v else ""
            else:
                flat[k] = v
        return flat
