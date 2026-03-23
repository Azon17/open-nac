"""
/api/v1/policies — CRUD для авторизационных политик.
"""

import json
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.core.redis_client import redis_pool

router = APIRouter()

POLICY_CACHE_KEY = "nac:policies:all"


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    priority: int = 100
    policy_set: str = "default"
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    enabled: bool = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    policy_set: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


@router.get("/policies")
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text(
        "SELECT id, name, description, priority, enabled, policy_set, "
        "conditions_json, actions_json, hit_count, created_at, updated_at "
        "FROM nac_policies ORDER BY priority ASC, id ASC"
    ))
    rows = result.fetchall()
    policies = []
    for r in rows:
        policies.append({
            "id": r[0], "name": r[1], "description": r[2], "priority": r[3],
            "enabled": bool(r[4]), "policy_set": r[5],
            "conditions": json.loads(r[6]) if r[6] else {},
            "actions": json.loads(r[7]) if r[7] else {},
            "hit_count": r[8], "created_at": str(r[9]), "updated_at": str(r[10]),
        })
    return {"total": len(policies), "items": policies}


@router.post("/policies")
async def create_policy(policy: PolicyCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(
        text("""
            INSERT INTO nac_policies (name, description, priority, policy_set, conditions_json, actions_json, enabled)
            VALUES (:name, :desc, :pri, :pset, :cond, :act, :en)
        """),
        {
            "name": policy.name, "desc": policy.description, "pri": policy.priority,
            "pset": policy.policy_set, "cond": json.dumps(policy.conditions),
            "act": json.dumps(policy.actions), "en": policy.enabled,
        },
    )
    await db.commit()
    await _invalidate_cache()
    return {"status": "created", "name": policy.name}


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: int, policy: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    updates = {}
    if policy.name is not None:
        updates["name"] = policy.name
    if policy.description is not None:
        updates["description"] = policy.description
    if policy.priority is not None:
        updates["priority"] = policy.priority
    if policy.policy_set is not None:
        updates["policy_set"] = policy.policy_set
    if policy.conditions is not None:
        updates["conditions_json"] = json.dumps(policy.conditions)
    if policy.actions is not None:
        updates["actions_json"] = json.dumps(policy.actions)
    if policy.enabled is not None:
        updates["enabled"] = policy.enabled

    if not updates:
        return {"error": "no_changes"}

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    updates["id"] = policy_id
    await db.execute(text(f"UPDATE nac_policies SET {set_clause} WHERE id = :id"), updates)
    await db.commit()
    await _invalidate_cache()
    return {"status": "updated", "id": policy_id}


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_policies WHERE id = :id"), {"id": policy_id})
    await db.commit()
    await _invalidate_cache()
    return {"status": "deleted", "id": policy_id}


async def _invalidate_cache():
    if redis_pool.pool:
        await redis_pool.pool.delete(POLICY_CACHE_KEY)
