"""
Scoring Engine — объединяет результаты всех движков профилирования.
Эквивалент: Cisco ISE Certainty Factor (CF) scoring.

Каждый движок возвращает (device_name, category, confidence).
Scoring engine вычисляет composite score по весам.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Protocol

logger = logging.getLogger("nac.profiler.scoring")


@dataclass
class ProfileData:
    """Входные данные для профилирования."""
    mac_address: str = ""
    dhcp_fingerprint: str = ""
    dhcp_hostname: str = ""
    user_agent: str = ""
    ip_address: str = ""
    eap_type: str = ""
    tcp_fingerprint: str = ""  # от p0f
    open_ports: list = field(default_factory=list)  # от nmap


@dataclass
class EngineResult:
    """Результат одного движка."""
    device_name: str = ""
    category: str = ""
    vendor: str = ""
    confidence: float = 0.0
    fingerbank_id: int = 0
    source: str = ""


@dataclass
class ProfileResult:
    """Финальный результат после scoring."""
    device_name: str = ""
    category: str = ""
    vendor: str = ""
    confidence: float = 0.0
    fingerbank_id: int = 0
    sources: Dict[str, EngineResult] = field(default_factory=dict)


class ProfilingEngine(Protocol):
    """Интерфейс для движков профилирования."""
    async def identify(self, data: ProfileData) -> Optional[EngineResult]:
        ...


class ScoringEngine:
    """
    Composite scoring: каждый движок имеет вес.
    Финальный confidence = sum(engine_confidence × engine_weight) / sum(active_weights)
    При конфликте — побеждает движок с наибольшим (confidence × weight).
    """

    def __init__(self, engines: Dict[str, Tuple[ProfilingEngine, float]]):
        self.engines = engines  # {"name": (engine_instance, weight)}

    async def evaluate(self, data: ProfileData) -> Optional[ProfileResult]:
        results: Dict[str, EngineResult] = {}
        active_weights = 0.0

        # Запускаем все движки
        for name, (engine, weight) in self.engines.items():
            try:
                result = await engine.identify(data)
                if result and result.device_name and result.confidence > 0:
                    results[name] = result
                    active_weights += weight
            except Exception as e:
                logger.warning(f"Engine '{name}' failed: {e}")

        if not results:
            return None

        # Выбираем лучший результат
        best_name = ""
        best_score = 0.0
        best_result: Optional[EngineResult] = None

        for name, result in results.items():
            _, weight = self.engines[name]
            score = result.confidence * weight
            if score > best_score:
                best_score = score
                best_name = name
                best_result = result

        if not best_result:
            return None

        # Вычисляем composite confidence
        # Если несколько движков согласны — confidence выше
        agreeing_weight = 0.0
        for name, result in results.items():
            _, weight = self.engines[name]
            if result.device_name == best_result.device_name:
                agreeing_weight += weight
            elif result.category == best_result.category:
                agreeing_weight += weight * 0.5  # частичное согласие

        # Нормализуем: если все активные движки согласны → 1.0
        total_possible = sum(w for _, (_, w) in self.engines.items())
        agreement_bonus = (agreeing_weight / total_possible) * 0.2 if total_possible > 0 else 0

        composite_confidence = min(best_result.confidence + agreement_bonus, 1.0)

        logger.debug(
            f"Scoring for {data.mac_address}: best='{best_name}' "
            f"device='{best_result.device_name}' "
            f"confidence={composite_confidence:.2%} "
            f"(base={best_result.confidence:.2%} + agreement={agreement_bonus:.2%})"
        )

        return ProfileResult(
            device_name=best_result.device_name,
            category=best_result.category,
            vendor=best_result.vendor,
            confidence=composite_confidence,
            fingerbank_id=best_result.fingerbank_id,
            sources=results,
        )
