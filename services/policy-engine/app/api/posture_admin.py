"""
/api/v1/posture — Posture administration API.
ISE equivalent: Work Centers → Posture → Policy Elements

Three levels:
  1. Conditions — individual checks (AV installed, FW enabled, patches applied)
  2. Requirements — groups of conditions mapped to OS types + remediation
  3. Policies — map requirements to identity groups with compliant/non-compliant actions
"""

import json
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.database import get_db

router = APIRouter()


# ─── Models ───

class ConditionCreate(BaseModel):
    name: str
    description: str = ""
    category: str = "antivirus"
    os_types: list = ["windows", "macos", "linux"]
    operator: str = "enabled"
    expected_value: str = "true"
    severity: str = "critical"
    enabled: bool = True

class RequirementCreate(BaseModel):
    name: str
    description: str = ""
    os_types: list = ["windows", "macos", "linux"]
    conditions: list = []
    remediation: dict = {}
    enabled: bool = True

class PosturePolicyCreate(BaseModel):
    name: str
    description: str = ""
    priority: int = 100
    identity_match: dict = {}
    requirements: list = []
    action_compliant: str = "permit"
    action_non_compliant: str = "quarantine"
    reassessment_minutes: int = 240
    grace_minutes: int = 0
    enabled: bool = True


# ─── Conditions CRUD ───

@router.get("/posture/conditions")
async def list_conditions(db: AsyncSession = Depends(get_db)):
    r = await db.execute(text(
        "SELECT id, name, description, category, os_types, operator, expected_value, severity, enabled, created_at "
        "FROM nac_posture_conditions ORDER BY category, name"
    ))
    items = []
    for row in r.fetchall():
        items.append({
            "id": row[0], "name": row[1], "description": row[2], "category": row[3],
            "os_types": json.loads(row[4]) if row[4] else [], "operator": row[5],
            "expected_value": row[6], "severity": row[7], "enabled": bool(row[8]),
            "created_at": str(row[9]),
        })
    return {"total": len(items), "items": items}

@router.post("/posture/conditions")
async def create_condition(c: ConditionCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        INSERT INTO nac_posture_conditions (name, description, category, os_types, operator, expected_value, severity, enabled)
        VALUES (:name, :desc, :cat, :os, :op, :val, :sev, :en)
    """), {"name": c.name, "desc": c.description, "cat": c.category,
           "os": json.dumps(c.os_types), "op": c.operator, "val": c.expected_value,
           "sev": c.severity, "en": c.enabled})
    await db.commit()
    return {"status": "created", "name": c.name}

@router.put("/posture/conditions/{cid}")
async def update_condition(cid: int, c: ConditionCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        UPDATE nac_posture_conditions SET name=:name, description=:desc, category=:cat,
        os_types=:os, operator=:op, expected_value=:val, severity=:sev, enabled=:en WHERE id=:id
    """), {"id": cid, "name": c.name, "desc": c.description, "cat": c.category,
           "os": json.dumps(c.os_types), "op": c.operator, "val": c.expected_value,
           "sev": c.severity, "en": c.enabled})
    await db.commit()
    return {"status": "updated", "id": cid}

@router.delete("/posture/conditions/{cid}")
async def delete_condition(cid: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_posture_conditions WHERE id=:id"), {"id": cid})
    await db.commit()
    return {"status": "deleted", "id": cid}


# ─── Requirements CRUD ───

@router.get("/posture/requirements")
async def list_requirements(db: AsyncSession = Depends(get_db)):
    r = await db.execute(text(
        "SELECT id, name, description, os_types, conditions, remediation, enabled, created_at "
        "FROM nac_posture_requirements ORDER BY name"
    ))
    items = []
    for row in r.fetchall():
        items.append({
            "id": row[0], "name": row[1], "description": row[2],
            "os_types": json.loads(row[3]) if row[3] else [],
            "conditions": json.loads(row[4]) if row[4] else [],
            "remediation": json.loads(row[5]) if row[5] else {},
            "enabled": bool(row[6]), "created_at": str(row[7]),
        })
    return {"total": len(items), "items": items}

@router.post("/posture/requirements")
async def create_requirement(r: RequirementCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        INSERT INTO nac_posture_requirements (name, description, os_types, conditions, remediation, enabled)
        VALUES (:name, :desc, :os, :cond, :rem, :en)
    """), {"name": r.name, "desc": r.description, "os": json.dumps(r.os_types),
           "cond": json.dumps(r.conditions), "rem": json.dumps(r.remediation), "en": r.enabled})
    await db.commit()
    return {"status": "created", "name": r.name}

@router.put("/posture/requirements/{rid}")
async def update_requirement(rid: int, r: RequirementCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        UPDATE nac_posture_requirements SET name=:name, description=:desc, os_types=:os,
        conditions=:cond, remediation=:rem, enabled=:en WHERE id=:id
    """), {"id": rid, "name": r.name, "desc": r.description, "os": json.dumps(r.os_types),
           "cond": json.dumps(r.conditions), "rem": json.dumps(r.remediation), "en": r.enabled})
    await db.commit()
    return {"status": "updated", "id": rid}

@router.delete("/posture/requirements/{rid}")
async def delete_requirement(rid: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_posture_requirements WHERE id=:id"), {"id": rid})
    await db.commit()
    return {"status": "deleted", "id": rid}


# ─── Posture Policies CRUD ───

@router.get("/posture/policies")
async def list_posture_policies(db: AsyncSession = Depends(get_db)):
    r = await db.execute(text(
        "SELECT id, name, description, priority, identity_match, requirements, "
        "action_compliant, action_non_compliant, reassessment_minutes, grace_minutes, enabled, created_at "
        "FROM nac_posture_policies ORDER BY priority, name"
    ))
    items = []
    for row in r.fetchall():
        items.append({
            "id": row[0], "name": row[1], "description": row[2], "priority": row[3],
            "identity_match": json.loads(row[4]) if row[4] else {},
            "requirements": json.loads(row[5]) if row[5] else [],
            "action_compliant": row[6], "action_non_compliant": row[7],
            "reassessment_minutes": row[8], "grace_minutes": row[9],
            "enabled": bool(row[10]), "created_at": str(row[11]),
        })
    return {"total": len(items), "items": items}

@router.post("/posture/policies")
async def create_posture_policy(p: PosturePolicyCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        INSERT INTO nac_posture_policies (name, description, priority, identity_match, requirements,
        action_compliant, action_non_compliant, reassessment_minutes, grace_minutes, enabled)
        VALUES (:name, :desc, :pri, :im, :req, :ac, :anc, :rm, :gm, :en)
    """), {"name": p.name, "desc": p.description, "pri": p.priority,
           "im": json.dumps(p.identity_match), "req": json.dumps(p.requirements),
           "ac": p.action_compliant, "anc": p.action_non_compliant,
           "rm": p.reassessment_minutes, "gm": p.grace_minutes, "en": p.enabled})
    await db.commit()
    return {"status": "created", "name": p.name}

@router.put("/posture/policies/{pid}")
async def update_posture_policy(pid: int, p: PosturePolicyCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        UPDATE nac_posture_policies SET name=:name, description=:desc, priority=:pri,
        identity_match=:im, requirements=:req, action_compliant=:ac, action_non_compliant=:anc,
        reassessment_minutes=:rm, grace_minutes=:gm, enabled=:en WHERE id=:id
    """), {"id": pid, "name": p.name, "desc": p.description, "pri": p.priority,
           "im": json.dumps(p.identity_match), "req": json.dumps(p.requirements),
           "ac": p.action_compliant, "anc": p.action_non_compliant,
           "rm": p.reassessment_minutes, "gm": p.grace_minutes, "en": p.enabled})
    await db.commit()
    return {"status": "updated", "id": pid}

@router.delete("/posture/policies/{pid}")
async def delete_posture_policy(pid: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_posture_policies WHERE id=:id"), {"id": pid})
    await db.commit()
    return {"status": "deleted", "id": pid}
