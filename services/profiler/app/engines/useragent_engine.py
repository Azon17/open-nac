"""
User-Agent Engine — идентификация устройства по HTTP User-Agent.
Работает offline — regex-based парсинг.

Полезно для:
  - Определение ОС (Windows 10/11, macOS, iOS, Android, Linux)
  - Определение типа (Desktop vs Mobile vs Tablet)
  - Определение конкретной модели (iPhone 15, Galaxy S24)
"""

import re
import logging
from typing import Optional

from app.engines.scoring import ProfileData, EngineResult

logger = logging.getLogger("nac.profiler.useragent")

# Паттерны User-Agent → (device_name, category, vendor, confidence)
UA_PATTERNS = [
    # iOS
    (r"iPhone\s*(?:OS\s*)?([\d_]+)", "iPhone", "mobile", "Apple", 0.85),
    (r"iPad.*?OS\s*([\d_]+)", "iPad", "mobile", "Apple", 0.85),
    # macOS
    (r"Macintosh.*Mac OS X\s*([\d_.]+)", "macOS Workstation", "workstation", "Apple", 0.80),
    # Android
    (r"Android\s*([\d.]+).*?(SM-[A-Z]\d+)", "Samsung Galaxy", "mobile", "Samsung", 0.80),
    (r"Android\s*([\d.]+).*?(Pixel\s*\d+)", "Google Pixel", "mobile", "Google", 0.80),
    (r"Android\s*([\d.]+)", "Android Device", "mobile", "", 0.60),
    # Windows
    (r"Windows NT 10\.0.*Win64", "Windows 10/11 Workstation", "workstation", "Microsoft", 0.70),
    (r"Windows NT 10\.0", "Windows 10/11 Workstation", "workstation", "Microsoft", 0.70),
    (r"Windows NT 6\.3", "Windows 8.1 Workstation", "workstation", "Microsoft", 0.70),
    (r"Windows NT 6\.1", "Windows 7 Workstation", "workstation", "Microsoft", 0.70),
    # Linux
    (r"Ubuntu", "Ubuntu Workstation", "workstation", "Canonical", 0.65),
    (r"Fedora", "Fedora Workstation", "workstation", "Red Hat", 0.65),
    (r"Linux x86_64", "Linux Workstation", "workstation", "", 0.55),
    (r"Linux", "Linux Device", "workstation", "", 0.45),
    # ChromeOS
    (r"CrOS", "Chromebook", "workstation", "Google", 0.75),
    # Smart TV
    (r"SmartTV|SMART-TV|Tizen|webOS", "Smart TV", "iot", "", 0.70),
    # Printer (некоторые HP/Brother шлют UA при web-конфигурации)
    (r"HP\s*(LaserJet|OfficeJet|DeskJet)", "HP Printer", "peripheral", "HP", 0.80),
    (r"Brother\s*(HL-|MFC-|DCP-)", "Brother Printer", "peripheral", "Brother", 0.80),
    # IoT / Bots (не устройства, но полезно для фильтрации)
    (r"curl/|wget/|python-requests/|Go-http-client", "Automated Client", "iot", "", 0.50),
]


class UserAgentEngine:
    async def identify(self, data: ProfileData) -> Optional[EngineResult]:
        if not data.user_agent:
            return None

        ua = data.user_agent

        for pattern, device_name, category, vendor, confidence in UA_PATTERNS:
            match = re.search(pattern, ua, re.IGNORECASE)
            if match:
                # Детализируем если есть группы
                version = ""
                if match.groups():
                    version = match.group(1).replace("_", ".")

                full_name = device_name
                if version and "Workstation" in device_name:
                    full_name = f"{device_name} ({version})"

                return EngineResult(
                    device_name=full_name,
                    category=category,
                    vendor=vendor,
                    confidence=confidence,
                    source="user_agent",
                )

        # Fallback: хотя бы определяем browser
        if "Mozilla" in ua or "Chrome" in ua or "Safari" in ua:
            return EngineResult(
                device_name="Web Browser Device",
                category="workstation",
                vendor="",
                confidence=0.25,
                source="user_agent",
            )

        return None
