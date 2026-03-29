"""
/api/v1/posture — Extended Posture Administration API v2
ISE equivalent: Work Centers → Posture → Policy Elements

Additions over v1:
  - PATCH toggle endpoint (fixes broken toggle buttons)
  - Extended condition fields (vendor, file_path, registry, service, KB, USB, compound)
  - AV vendor reference CRUD
  - Posture assessment history
  - Stats endpoint with posture overview
"""

import json
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.database import get_db

router = APIRouter()


# ─── Extended Models ───

class ConditionCreate(BaseModel):
    name: str
    description: str = ""
    category: str = "antivirus"
    os_types: list = ["windows", "macos", "linux"]
    operator: str = "enabled"
    expected_value: str = "true"
    severity: str = "critical"
    enabled: bool = True
    # Extended ISE-style fields
    vendor: Optional[str] = None
    product_name: Optional[str] = None
    min_version: Optional[str] = None
    file_path: Optional[str] = None
    registry_path: Optional[str] = None
    registry_key: Optional[str] = None
    service_name: Optional[str] = None
    kb_numbers: Optional[list] = None
    usb_classes: Optional[list] = None
    firewall_profiles: Optional[list] = None
    sub_conditions: Optional[list] = None
    compound_operator: Optional[str] = None


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


class ToggleRequest(BaseModel):
    enabled: bool


# ─── Helper ───

def _json_dumps(val):
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val)


def _json_loads(val):
    if val is None:
        return None
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return None


# ════════════════════════════════════════════
# CONDITIONS CRUD (extended)
# ════════════════════════════════════════════

@router.get("/posture/conditions")
async def list_conditions(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = """
        SELECT id, name, description, category, os_types, operator, expected_value,
               severity, enabled, created_at, updated_at,
               vendor, product_name, min_version, file_path, registry_path,
               registry_key, service_name, kb_numbers, usb_classes,
               firewall_profiles, sub_conditions, compound_operator
        FROM nac_posture_conditions
    """
    params = {}
    if category:
        q += " WHERE category = :cat"
        params["cat"] = category
    q += " ORDER BY category, name"

    r = await db.execute(text(q), params)
    items = []
    for row in r.fetchall():
        items.append({
            "id": row[0], "name": row[1], "description": row[2], "category": row[3],
            "os_types": _json_loads(row[4]) or [],
            "operator": row[5], "expected_value": row[6],
            "severity": row[7], "enabled": bool(row[8]),
            "created_at": str(row[9]), "updated_at": str(row[10]) if row[10] else None,
            # Extended
            "vendor": row[11], "product_name": row[12], "min_version": row[13],
            "file_path": row[14], "registry_path": row[15], "registry_key": row[16],
            "service_name": row[17],
            "kb_numbers": _json_loads(row[18]),
            "usb_classes": _json_loads(row[19]),
            "firewall_profiles": _json_loads(row[20]),
            "sub_conditions": _json_loads(row[21]),
            "compound_operator": row[22],
        })
    return {"total": len(items), "items": items}


@router.post("/posture/conditions")
async def create_condition(c: ConditionCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        INSERT INTO nac_posture_conditions
        (name, description, category, os_types, operator, expected_value, severity, enabled,
         vendor, product_name, min_version, file_path, registry_path, registry_key,
         service_name, kb_numbers, usb_classes, firewall_profiles, sub_conditions, compound_operator)
        VALUES (:name, :desc, :cat, :os, :op, :val, :sev, :en,
                :vendor, :product, :minver, :fpath, :rpath, :rkey,
                :svcname, :kbs, :usbc, :fwprof, :subcond, :compop)
    """), {
        "name": c.name, "desc": c.description, "cat": c.category,
        "os": json.dumps(c.os_types), "op": c.operator, "val": c.expected_value,
        "sev": c.severity, "en": c.enabled,
        "vendor": c.vendor, "product": c.product_name, "minver": c.min_version,
        "fpath": c.file_path, "rpath": c.registry_path, "rkey": c.registry_key,
        "svcname": c.service_name,
        "kbs": _json_dumps(c.kb_numbers), "usbc": _json_dumps(c.usb_classes),
        "fwprof": _json_dumps(c.firewall_profiles),
        "subcond": _json_dumps(c.sub_conditions), "compop": c.compound_operator,
    })
    await db.commit()
    return {"status": "created", "name": c.name}


@router.put("/posture/conditions/{cid}")
async def update_condition(cid: int, c: ConditionCreate, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        UPDATE nac_posture_conditions SET
        name=:name, description=:desc, category=:cat, os_types=:os,
        operator=:op, expected_value=:val, severity=:sev, enabled=:en,
        vendor=:vendor, product_name=:product, min_version=:minver,
        file_path=:fpath, registry_path=:rpath, registry_key=:rkey,
        service_name=:svcname, kb_numbers=:kbs, usb_classes=:usbc,
        firewall_profiles=:fwprof, sub_conditions=:subcond, compound_operator=:compop
        WHERE id=:id
    """), {
        "id": cid, "name": c.name, "desc": c.description, "cat": c.category,
        "os": json.dumps(c.os_types), "op": c.operator, "val": c.expected_value,
        "sev": c.severity, "en": c.enabled,
        "vendor": c.vendor, "product": c.product_name, "minver": c.min_version,
        "fpath": c.file_path, "rpath": c.registry_path, "rkey": c.registry_key,
        "svcname": c.service_name,
        "kbs": _json_dumps(c.kb_numbers), "usbc": _json_dumps(c.usb_classes),
        "fwprof": _json_dumps(c.firewall_profiles),
        "subcond": _json_dumps(c.sub_conditions), "compop": c.compound_operator,
    })
    await db.commit()
    return {"status": "updated", "id": cid}


@router.delete("/posture/conditions/{cid}")
async def delete_condition(cid: int, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM nac_posture_conditions WHERE id=:id"), {"id": cid})
    await db.commit()
    return {"status": "deleted", "id": cid}


# ── Toggle endpoint (fixes broken UI toggles) ──

@router.patch("/posture/conditions/{cid}/toggle")
async def toggle_condition(cid: int, body: ToggleRequest, db: AsyncSession = Depends(get_db)):
    await db.execute(text(
        "UPDATE nac_posture_conditions SET enabled=:en WHERE id=:id"
    ), {"id": cid, "en": body.enabled})
    await db.commit()
    return {"status": "toggled", "id": cid, "enabled": body.enabled}


# ════════════════════════════════════════════
# REQUIREMENTS CRUD
# ════════════════════════════════════════════

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
            "os_types": _json_loads(row[3]) or [],
            "conditions": _json_loads(row[4]) or [],
            "remediation": _json_loads(row[5]) or {},
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


@router.patch("/posture/requirements/{rid}/toggle")
async def toggle_requirement(rid: int, body: ToggleRequest, db: AsyncSession = Depends(get_db)):
    await db.execute(text(
        "UPDATE nac_posture_requirements SET enabled=:en WHERE id=:id"
    ), {"id": rid, "en": body.enabled})
    await db.commit()
    return {"status": "toggled", "id": rid, "enabled": body.enabled}


# ════════════════════════════════════════════
# POSTURE POLICIES CRUD
# ════════════════════════════════════════════

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
            "identity_match": _json_loads(row[4]) or {},
            "requirements": _json_loads(row[5]) or [],
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


@router.patch("/posture/policies/{pid}/toggle")
async def toggle_posture_policy(pid: int, body: ToggleRequest, db: AsyncSession = Depends(get_db)):
    await db.execute(text(
        "UPDATE nac_posture_policies SET enabled=:en WHERE id=:id"
    ), {"id": pid, "en": body.enabled})
    await db.commit()
    return {"status": "toggled", "id": pid, "enabled": body.enabled}


# ════════════════════════════════════════════
# AV VENDORS reference
# ════════════════════════════════════════════

@router.get("/posture/av-vendors")
async def list_av_vendors(
    os_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    q = "SELECT id, vendor_name, product_name, os_type, process_name, service_name FROM nac_av_vendors"
    params = {}
    if os_type:
        q += " WHERE os_type = :os"
        params["os"] = os_type
    q += " ORDER BY vendor_name, product_name"
    r = await db.execute(text(q), params)
    items = [
        {"id": row[0], "vendor_name": row[1], "product_name": row[2],
         "os_type": row[3], "process_name": row[4], "service_name": row[5]}
        for row in r.fetchall()
    ]
    return {"total": len(items), "items": items}


# ════════════════════════════════════════════
# POSTURE STATS
# ════════════════════════════════════════════

@router.get("/posture/stats")
async def posture_stats(db: AsyncSession = Depends(get_db)):
    # Endpoint status distribution
    r = await db.execute(text("""
        SELECT posture_status, COUNT(*) FROM nac_endpoints GROUP BY posture_status
    """))
    status_counts = {(row[0] or "unknown"): row[1] for row in r.fetchall()}

    # Condition counts by category
    r2 = await db.execute(text("""
        SELECT category, COUNT(*), SUM(enabled) FROM nac_posture_conditions GROUP BY category
    """))
    categories = [
        {"category": row[0], "total": row[1], "enabled": int(row[2] or 0)}
        for row in r2.fetchall()
    ]

    # Recent assessment stats
    r3 = await db.execute(text("""
        SELECT status, COUNT(*) FROM nac_posture_assessments
        WHERE assessed_at > NOW() - INTERVAL 24 HOUR
        GROUP BY status
    """))
    recent_assessments = {row[0]: row[1] for row in r3.fetchall()}

    return {
        "total": sum(status_counts.values()),
        "compliant": status_counts.get("compliant", 0),
        "non_compliant": status_counts.get("non_compliant", 0),
        "unknown": status_counts.get("unknown", 0),
        "exempt": status_counts.get("exempt", 0),
        "quarantined": status_counts.get("quarantined", 0),
        "condition_categories": categories,
        "recent_assessments_24h": recent_assessments,
    }


# ════════════════════════════════════════════
# ASSESSMENT HISTORY
# ════════════════════════════════════════════

@router.get("/posture/assessments/{mac_address}")
async def get_assessments(
    mac_address: str,
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db)
):
    mac = mac_address.lower().replace("-", ":")
    r = await db.execute(text("""
        SELECT id, mac_address, policy_id, status, checks_json, source, assessed_at
        FROM nac_posture_assessments
        WHERE mac_address = :mac
        ORDER BY assessed_at DESC
        LIMIT :lim
    """), {"mac": mac, "lim": limit})
    items = [
        {
            "id": row[0], "mac_address": row[1], "policy_id": row[2],
            "status": row[3], "checks": _json_loads(row[4]) or [],
            "source": row[5], "assessed_at": str(row[6]),
        }
        for row in r.fetchall()
    ]
    return {"mac_address": mac, "total": len(items), "items": items}
