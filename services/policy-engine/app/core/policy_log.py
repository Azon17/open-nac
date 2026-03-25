"""
Policy Decision Log — stores every authorization decision for live monitoring.
Ring buffer in memory (last 1000) + async write to DB.
Supports SSE streaming for real-time UI.
"""

import asyncio
import json
import logging
from datetime import datetime
from collections import deque
from typing import Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("nac.policy_log")


@dataclass
class PolicyLogEntry:
    id: int = 0
    timestamp: str = ""
    username: str = ""
    mac_address: str = ""
    nas_ip: str = ""
    nas_port: str = ""
    eap_type: str = ""
    auth_method: str = ""
    device_profile: str = ""
    device_category: str = ""
    posture_status: str = ""
    ad_groups: str = ""
    certificate: bool = False
    # Decision
    policy_name: str = ""
    policy_id: int = 0
    decision: str = ""  # permit | deny
    vlan: str = ""
    acl: str = ""
    url_redirect: str = ""
    # Timing
    eval_time_ms: float = 0
    cached: bool = False
    # Result
    radius_result: str = ""  # Access-Accept | Access-Reject
    detail: str = ""


class PolicyLog:
    def __init__(self, max_entries: int = 2000):
        self._buffer: deque[PolicyLogEntry] = deque(maxlen=max_entries)
        self._counter = 0
        self._subscribers: list[asyncio.Queue] = []
        self._db_queue: deque[PolicyLogEntry] = deque(maxlen=5000)

    def log(self, entry: PolicyLogEntry):
        self._counter += 1
        entry.id = self._counter
        if not entry.timestamp:
            entry.timestamp = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
        self._buffer.append(entry)
        self._db_queue.append(entry)

        # Notify SSE subscribers
        data = asdict(entry)
        for q in self._subscribers[:]:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                pass  # Drop if subscriber is slow

        logger.debug(f"POLICY LOG #{entry.id}: {entry.username}@{entry.mac_address} → {entry.policy_name} ({entry.decision})")

    def get_recent(self, limit: int = 100, username: str = "", mac: str = "",
                   decision: str = "", policy_name: str = "") -> list[dict]:
        items = list(self._buffer)
        items.reverse()  # newest first

        # Filter
        if username:
            items = [e for e in items if username.lower() in e.username.lower()]
        if mac:
            items = [e for e in items if mac.lower() in e.mac_address.lower()]
        if decision:
            items = [e for e in items if e.decision == decision]
        if policy_name:
            items = [e for e in items if policy_name.lower() in e.policy_name.lower()]

        return [asdict(e) for e in items[:limit]]

    def get_stats(self) -> dict:
        entries = list(self._buffer)
        total = len(entries)
        if total == 0:
            return {"total": 0, "permits": 0, "denies": 0, "cached": 0,
                    "avg_eval_ms": 0, "policies_hit": {}, "top_vlans": {}}

        permits = sum(1 for e in entries if e.decision == "permit")
        denies = sum(1 for e in entries if e.decision == "deny")
        cached = sum(1 for e in entries if e.cached)
        eval_times = [e.eval_time_ms for e in entries if e.eval_time_ms > 0]
        avg_eval = sum(eval_times) / len(eval_times) if eval_times else 0

        # Top policies
        policy_counts = {}
        for e in entries:
            if e.policy_name:
                policy_counts[e.policy_name] = policy_counts.get(e.policy_name, 0) + 1

        # Top VLANs
        vlan_counts = {}
        for e in entries:
            if e.vlan:
                vlan_counts[e.vlan] = vlan_counts.get(e.vlan, 0) + 1

        return {
            "total": total,
            "permits": permits,
            "denies": denies,
            "cached": cached,
            "avg_eval_ms": round(avg_eval, 2),
            "policies_hit": dict(sorted(policy_counts.items(), key=lambda x: -x[1])[:10]),
            "top_vlans": dict(sorted(vlan_counts.items(), key=lambda x: -x[1])[:10]),
        }

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    def drain_db_queue(self, limit: int = 100) -> list[PolicyLogEntry]:
        items = []
        while self._db_queue and len(items) < limit:
            items.append(self._db_queue.popleft())
        return items


policy_log = PolicyLog()
