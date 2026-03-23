"""
Policy Evaluator — ядро авторизации.
Эквивалент: Cisco ISE Authorization Policy Engine.

Получает контекст (username, MAC, groups, device profile, posture)
и возвращает решение (VLAN, ACL, URL-redirect, CoA-action).

Политики загружаются из MariaDB (таблица nac_policies) и кэшируются в Redis.
"""

import json
import re
import logging
from typing import Optional
from dataclasses import dataclass, field

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_client import redis_pool

logger = logging.getLogger("nac.policy")

POLICY_CACHE_KEY = "nac:policies:all"
POLICY_CACHE_TTL = 60  # секунд


@dataclass
class AuthContext:
    """Контекст аутентификации — все данные для принятия решения."""
    username: str = ""
    mac_address: str = ""
    nas_ip: str = ""
    nas_port: str = ""
    eap_type: str = "none"
    service_type: str = ""
    framed_ip: str = ""
    ldap_groups: list = field(default_factory=list)
    ad_department: str = ""
    device_profile: str = ""
    device_category: str = ""
    posture_status: str = "unknown"
    auth_source: str = ""
    site: str = ""
    certificate: bool = False


@dataclass
class AuthResult:
    """Результат авторизации — что вернуть в FreeRADIUS."""
    decision: str = "permit"  # permit | deny | continue
    tunnel_type: str = "13"  # VLAN
    tunnel_medium_type: str = "6"  # IEEE-802
    tunnel_private_group_id: str = "999"  # VLAN ID
    filter_id: str = ""  # ACL name
    url_redirect: str = ""  # Captive portal URL
    url_redirect_acl: str = ""  # Redirect ACL
    session_timeout: int = 0
    policy_name: str = ""  # Какое правило сработало
    policy_id: int = 0

    def to_radius_dict(self) -> dict:
        d = {
            "decision": self.decision,
            "Tunnel-Type": self.tunnel_type,
            "Tunnel-Medium-Type": self.tunnel_medium_type,
            "Tunnel-Private-Group-Id": self.tunnel_private_group_id,
            "Filter-Id": self.filter_id,
            "url-redirect": self.url_redirect,
            "url-redirect-acl": self.url_redirect_acl,
            "policy_name": self.policy_name,
        }
        if self.session_timeout:
            d["Session-Timeout"] = str(self.session_timeout)
        return d


class PolicyEvaluator:
    """
    Загружает политики из БД, кэширует в Redis, оценивает по приоритету.
    Формат условий — упрощённый DSL:
        "AD-Group = Domain Users AND Posture = Compliant"
        "Device-Profile = IP Phone*"
        "Auth-Source = Guest Portal"
    """

    async def evaluate(self, ctx: AuthContext, db: AsyncSession) -> AuthResult:
        policies = await self._load_policies(db)

        for policy in policies:
            if not policy.get("enabled", True):
                continue
            if self._match_conditions(ctx, policy.get("conditions", {})):
                logger.info(
                    f"Policy matched: '{policy['name']}' for {ctx.mac_address} ({ctx.username})"
                )
                result = self._build_result(policy)

                # Инкремент hit counter (async, не блокируем ответ)
                await self._increment_hit(db, policy["id"])
                return result

        # Default: quarantine
        logger.warning(f"No policy matched for {ctx.mac_address}, applying default quarantine")
        return AuthResult(
            tunnel_private_group_id="999",
            policy_name="default-quarantine",
        )

    def _match_conditions(self, ctx: AuthContext, conditions: dict) -> bool:
        """Проверяет все условия политики."""
        for key, expected in conditions.items():
            actual = self._get_context_value(ctx, key)
            if not self._match_single(actual, expected):
                return False
        return True

    def _get_context_value(self, ctx: AuthContext, key: str) -> str:
        mapping = {
            "AD-Group": ",".join(ctx.ldap_groups),
            "Posture": ctx.posture_status,
            "Device-Profile": ctx.device_profile,
            "Device-Category": ctx.device_category,
            "Auth-Method": ctx.eap_type,
            "EAP-Type": ctx.eap_type,
            "Auth-Source": ctx.auth_source,
            "NAS-IP": ctx.nas_ip,
            "Site": ctx.site,
            "Certificate": "true" if ctx.certificate else "false",
            "Department": ctx.ad_department,
            "Username": ctx.username,
        }
        return mapping.get(key, "")

    def _match_single(self, actual: str, expected: str) -> bool:
        if not expected:
            return True

        # Negation: "≠ Compliant" or "!= Compliant"
        if expected.startswith("≠ ") or expected.startswith("!= "):
            val = expected.split(" ", 1)[1]
            return val.lower() not in actual.lower()

        # Wildcard: "IP Phone*"
        if "*" in expected:
            pattern = expected.replace("*", ".*")
            return bool(re.search(pattern, actual, re.IGNORECASE))

        # Contains (for comma-separated groups)
        if "," in actual:
            return expected.lower() in actual.lower()

        return actual.lower() == expected.lower()

    def _build_result(self, policy: dict) -> AuthResult:
        actions = policy.get("actions", {})
        result = AuthResult(
            policy_name=policy["name"],
            policy_id=policy["id"],
        )
        if "vlan" in actions:
            result.tunnel_private_group_id = str(actions["vlan"])
        if "acl" in actions:
            result.filter_id = actions["acl"]
        if "url_redirect" in actions:
            result.url_redirect = actions["url_redirect"]
            result.url_redirect_acl = actions.get("url_redirect_acl", "ACL-WEBAUTH-REDIRECT")
        if "session_timeout" in actions:
            result.session_timeout = int(actions["session_timeout"])
        if actions.get("deny"):
            result.decision = "deny"
        return result

    async def _load_policies(self, db: AsyncSession) -> list:
        # Проверяем кэш
        cached = await redis_pool.pool.get(POLICY_CACHE_KEY) if redis_pool.pool else None
        if cached:
            return json.loads(cached)

        # Загружаем из БД
        result = await db.execute(
            text("""
                SELECT id, name, priority, enabled, conditions_json, actions_json
                FROM nac_policies
                WHERE enabled = 1
                ORDER BY priority ASC, id ASC
            """)
        )
        rows = result.fetchall()
        policies = []
        for row in rows:
            policies.append({
                "id": row[0],
                "name": row[1],
                "priority": row[2],
                "enabled": bool(row[3]),
                "conditions": json.loads(row[4]) if row[4] else {},
                "actions": json.loads(row[5]) if row[5] else {},
            })

        # Кэшируем
        if redis_pool.pool and policies:
            await redis_pool.pool.setex(POLICY_CACHE_KEY, POLICY_CACHE_TTL, json.dumps(policies))

        return policies

    async def _increment_hit(self, db: AsyncSession, policy_id: int):
        try:
            await db.execute(
                text("UPDATE nac_policies SET hit_count = hit_count + 1 WHERE id = :id"),
                {"id": policy_id},
            )
            await db.commit()
        except Exception:
            pass  # Non-critical


policy_evaluator = PolicyEvaluator()
