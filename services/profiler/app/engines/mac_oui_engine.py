"""
MAC OUI Engine — определение vendor по первым 3 октетам MAC-адреса.
Работает полностью offline — не требует API.

OUI база: IEEE MA-L (загружается при старте).
Это самый быстрый и надёжный источник — vendor identification.
"""

import logging
from typing import Optional, Dict

from app.engines.scoring import ProfileData, EngineResult

logger = logging.getLogger("nac.profiler.oui")

# Компактная встроенная таблица топ-200 OUI
# В production: загружайте полный файл из https://standards-oui.ieee.org/oui/oui.txt
OUI_DB: Dict[str, tuple] = {
    # Apple
    "00:03:93": ("Apple", "workstation"), "00:0a:27": ("Apple", "mobile"),
    "00:0a:95": ("Apple", "mobile"), "00:0d:93": ("Apple", "workstation"),
    "00:1e:c2": ("Apple", "workstation"), "00:25:bc": ("Apple", "workstation"),
    "28:cf:e9": ("Apple", "mobile"), "3c:15:c2": ("Apple", "mobile"),
    "40:33:1a": ("Apple", "mobile"), "48:d7:05": ("Apple", "mobile"),
    "54:26:96": ("Apple", "mobile"), "68:5b:35": ("Apple", "workstation"),
    "70:56:81": ("Apple", "mobile"), "78:7e:61": ("Apple", "mobile"),
    "8c:85:90": ("Apple", "workstation"), "a4:83:e7": ("Apple", "mobile"),
    "ac:bc:32": ("Apple", "mobile"), "bc:52:b7": ("Apple", "mobile"),
    "dc:2b:2a": ("Apple", "mobile"), "f0:18:98": ("Apple", "mobile"),
    # Samsung
    "00:07:ab": ("Samsung", "mobile"), "00:12:fb": ("Samsung", "mobile"),
    "00:21:19": ("Samsung", "mobile"), "08:d4:2b": ("Samsung", "mobile"),
    "18:3a:2d": ("Samsung", "mobile"), "34:23:ba": ("Samsung", "mobile"),
    "50:01:d9": ("Samsung", "mobile"), "78:52:1a": ("Samsung", "mobile"),
    "84:25:db": ("Samsung", "mobile"), "a8:f2:74": ("Samsung", "mobile"),
    "c4:73:1e": ("Samsung", "mobile"), "e8:50:8b": ("Samsung", "mobile"),
    # Cisco
    "00:00:0c": ("Cisco", "infrastructure"), "00:01:42": ("Cisco", "voip"),
    "00:01:64": ("Cisco", "infrastructure"), "00:07:0e": ("Cisco", "voip"),
    "00:0b:be": ("Cisco", "infrastructure"), "00:0d:bc": ("Cisco", "voip"),
    "00:13:1a": ("Cisco", "infrastructure"), "00:1b:0d": ("Cisco", "infrastructure"),
    "00:22:bd": ("Cisco", "infrastructure"), "00:26:0b": ("Cisco", "infrastructure"),
    "2c:36:f8": ("Cisco", "infrastructure"), "58:ac:78": ("Cisco", "infrastructure"),
    "b0:aa:77": ("Cisco", "infrastructure"), "f4:cf:e2": ("Cisco", "infrastructure"),
    # HP / HPE
    "00:01:e6": ("HP", "peripheral"), "00:08:02": ("HP", "workstation"),
    "00:0d:9d": ("HP", "workstation"), "00:14:38": ("HP", "workstation"),
    "00:17:a4": ("HP", "workstation"), "00:1a:4b": ("HP", "workstation"),
    "00:1e:0b": ("HP", "workstation"), "00:21:5a": ("HP", "workstation"),
    "00:25:b3": ("HP", "workstation"), "00:30:c1": ("HP", "workstation"),
    "18:a9:05": ("HP", "peripheral"), "2c:44:fd": ("HP", "peripheral"),
    "3c:d9:2b": ("HP", "peripheral"), "64:51:06": ("HP", "peripheral"),
    "9c:b6:54": ("HP", "workstation"), "d4:85:64": ("HP", "peripheral"),
    # Dell
    "00:06:5b": ("Dell", "workstation"), "00:08:74": ("Dell", "workstation"),
    "00:0b:db": ("Dell", "workstation"), "00:12:3f": ("Dell", "workstation"),
    "00:14:22": ("Dell", "workstation"), "00:18:8b": ("Dell", "workstation"),
    "00:1e:4f": ("Dell", "workstation"), "00:24:e8": ("Dell", "workstation"),
    "14:fe:b5": ("Dell", "workstation"), "34:17:eb": ("Dell", "workstation"),
    "b0:83:fe": ("Dell", "workstation"), "f8:bc:12": ("Dell", "workstation"),
    # Lenovo
    "00:06:1b": ("Lenovo", "workstation"), "00:09:2d": ("Lenovo", "workstation"),
    "00:1a:6b": ("Lenovo", "workstation"), "00:21:cc": ("Lenovo", "workstation"),
    "28:d2:44": ("Lenovo", "workstation"), "54:ee:75": ("Lenovo", "workstation"),
    "98:fa:9b": ("Lenovo", "workstation"), "e8:2a:44": ("Lenovo", "workstation"),
    # Intel (часто = workstation)
    "00:02:b3": ("Intel", "workstation"), "00:03:47": ("Intel", "workstation"),
    "00:07:e9": ("Intel", "workstation"), "00:13:02": ("Intel", "workstation"),
    "00:13:20": ("Intel", "workstation"), "00:15:00": ("Intel", "workstation"),
    "00:1b:21": ("Intel", "workstation"), "00:1e:64": ("Intel", "workstation"),
    "3c:97:0e": ("Intel", "workstation"), "48:51:b7": ("Intel", "workstation"),
    # Microsoft (Surface, Xbox)
    "28:18:78": ("Microsoft", "workstation"), "60:45:bd": ("Microsoft", "workstation"),
    "7c:1e:52": ("Microsoft", "workstation"), "c8:3f:26": ("Microsoft", "iot"),
    # Aruba / HPE Aruba
    "00:0b:86": ("Aruba", "infrastructure"), "00:1a:1e": ("Aruba", "infrastructure"),
    "24:de:c6": ("Aruba", "infrastructure"), "6c:f3:7f": ("Aruba", "infrastructure"),
    # Axis (IP cameras)
    "00:40:8c": ("Axis", "iot"), "ac:cc:8e": ("Axis", "iot"), "b8:a4:4f": ("Axis", "iot"),
    # Hikvision (cameras)
    "18:68:cb": ("Hikvision", "iot"), "54:c4:15": ("Hikvision", "iot"),
    "c0:56:e3": ("Hikvision", "iot"), "ec:8e:b5": ("Hikvision", "iot"),
    # Polycom / Poly (VoIP)
    "00:04:f2": ("Polycom", "voip"), "00:e0:db": ("Polycom", "voip"),
    "64:16:7f": ("Polycom", "voip"),
    # Yealink (VoIP)
    "00:15:65": ("Yealink", "voip"), "80:5e:c0": ("Yealink", "voip"),
    # Zebra / Symbol (scanners)
    "00:15:70": ("Zebra", "peripheral"), "00:a0:f8": ("Zebra", "peripheral"),
    # Raspberry Pi
    "b8:27:eb": ("Raspberry Pi", "iot"), "dc:a6:32": ("Raspberry Pi", "iot"),
    "e4:5f:01": ("Raspberry Pi", "iot"),
    # Amazon (Echo, Ring)
    "00:fc:8b": ("Amazon", "iot"), "18:74:2e": ("Amazon", "iot"),
    "40:b4:cd": ("Amazon", "iot"), "68:54:fd": ("Amazon", "iot"),
    # Google (Nest, Chromecast)
    "54:60:09": ("Google", "iot"), "f4:f5:d8": ("Google", "iot"),
    # Sonos
    "00:0e:58": ("Sonos", "iot"), "5c:aa:fd": ("Sonos", "iot"),
}


class MACOUIEngine:
    def __init__(self):
        self.db = OUI_DB
        logger.info(f"OUI database loaded: {len(self.db)} entries")

    async def identify(self, data: ProfileData) -> Optional[EngineResult]:
        if not data.mac_address:
            return None

        mac = data.mac_address.lower()
        oui = mac[:8]  # "aa:bb:cc"

        entry = self.db.get(oui)
        if not entry:
            return None

        vendor, category = entry

        # Confidence для OUI: знаем vendor, но не конкретную модель
        # Для Cisco → высокая уверенность что infrastructure/voip
        # Для Intel → может быть любой workstation
        confidence = 0.6 if category != "workstation" else 0.4

        return EngineResult(
            device_name=f"{vendor} Device",
            category=category,
            vendor=vendor,
            confidence=confidence,
            source="mac_oui",
        )
