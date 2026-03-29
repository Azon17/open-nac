"""
Open NAC — ISE-Style Policy API Routes
Full CRUD for: Policy Sets, Auth Policies, Authz Policies,
Condition Library, Authorization Profiles, Allowed Protocols, Identity Sources
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core import crud
from app.core.policy_evaluator import PolicyEvaluator
from app.models.policy_models import (
    # Identity Sources
    IdentitySourceCreate, IdentitySourceUpdate, IdentitySourceOut,
    # Allowed Protocols
    AllowedProtocolsCreate, AllowedProtocolsUpdate, AllowedProtocolsOut,
    # Authorization Profiles
    AuthzProfileCreate, AuthzProfileUpdate, AuthzProfileOut,
    # Conditions
    ConditionCreate, ConditionUpdate, ConditionOut,
    # Policy Sets
    PolicySetCreate, PolicySetUpdate, PolicySetOut, PolicySetDetail,
    # Auth Policies
    AuthenticationPolicyCreate, AuthenticationPolicyUpdate, AuthenticationPolicyOut,
    # Authz Policies
    AuthorizationPolicyCreate, AuthorizationPolicyUpdate, AuthorizationPolicyOut,
    # Evaluation
    EvaluateRequest, EvaluateResponse,
)

logger = logging.getLogger("policy_api")

router = APIRouter(prefix="/api/v2/policy", tags=["ISE Policy Module"])


# ─────────────────────────────────────────────
# Dependencies (injected by main app)
# ─────────────────────────────────────────────

_db_pool = None
_redis_client = None
_evaluator: Optional[PolicyEvaluator] = None


def init_dependencies(db_pool, redis_client):
    global _db_pool, _redis_client, _evaluator
    _db_pool = db_pool
    _redis_client = redis_client
    _evaluator = PolicyEvaluator(db_pool, redis_client)


def get_pool():
    if _db_pool is None:
        raise HTTPException(503, "Database not initialized")
    return _db_pool


def get_evaluator():
    if _evaluator is None:
        raise HTTPException(503, "Policy evaluator not initialized")
    return _evaluator


# ─────────────────────────────────────────────
# IDENTITY SOURCES
# ─────────────────────────────────────────────

@router.get("/identity-sources", response_model=list[IdentitySourceOut])
async def list_identity_sources():
    return await crud.get_all(get_pool(), "identity_sources", order_by="priority ASC")


@router.get("/identity-sources/{source_id}", response_model=IdentitySourceOut)
async def get_identity_source(source_id: int):
    row = await crud.get_by_id(get_pool(), "identity_sources", source_id)
    if not row:
        raise HTTPException(404, "Identity source not found")
    return row


@router.post("/identity-sources", response_model=IdentitySourceOut, status_code=201)
async def create_identity_source(body: IdentitySourceCreate):
    return await crud.create(get_pool(), "identity_sources", body.model_dump())


@router.patch("/identity-sources/{source_id}", response_model=IdentitySourceOut)
async def update_identity_source(source_id: int, body: IdentitySourceUpdate):
    row = await crud.update(get_pool(), "identity_sources", source_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Identity source not found")
    await _invalidate()
    return row


@router.delete("/identity-sources/{source_id}")
async def delete_identity_source(source_id: int):
    ok = await crud.delete(get_pool(), "identity_sources", source_id)
    if not ok:
        raise HTTPException(404, "Identity source not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# ALLOWED PROTOCOLS
# ─────────────────────────────────────────────

@router.get("/allowed-protocols", response_model=list[AllowedProtocolsOut])
async def list_allowed_protocols():
    return await crud.get_all(get_pool(), "allowed_protocols")


@router.get("/allowed-protocols/{proto_id}", response_model=AllowedProtocolsOut)
async def get_allowed_protocols(proto_id: int):
    row = await crud.get_by_id(get_pool(), "allowed_protocols", proto_id)
    if not row:
        raise HTTPException(404, "Allowed protocols not found")
    return row


@router.post("/allowed-protocols", response_model=AllowedProtocolsOut, status_code=201)
async def create_allowed_protocols(body: AllowedProtocolsCreate):
    return await crud.create(get_pool(), "allowed_protocols", body.model_dump())


@router.patch("/allowed-protocols/{proto_id}", response_model=AllowedProtocolsOut)
async def update_allowed_protocols(proto_id: int, body: AllowedProtocolsUpdate):
    row = await crud.update(get_pool(), "allowed_protocols", proto_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Allowed protocols not found")
    await _invalidate()
    return row


@router.delete("/allowed-protocols/{proto_id}")
async def delete_allowed_protocols(proto_id: int):
    ok = await crud.delete(get_pool(), "allowed_protocols", proto_id)
    if not ok:
        raise HTTPException(404, "Allowed protocols not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# AUTHORIZATION PROFILES
# ─────────────────────────────────────────────

@router.get("/authorization-profiles", response_model=list[AuthzProfileOut])
async def list_authz_profiles():
    return await crud.get_all(get_pool(), "authorization_profiles")


@router.get("/authorization-profiles/{profile_id}", response_model=AuthzProfileOut)
async def get_authz_profile(profile_id: int):
    row = await crud.get_by_id(get_pool(), "authorization_profiles", profile_id)
    if not row:
        raise HTTPException(404, "Authorization profile not found")
    return row


@router.post("/authorization-profiles", response_model=AuthzProfileOut, status_code=201)
async def create_authz_profile(body: AuthzProfileCreate):
    return await crud.create(get_pool(), "authorization_profiles", body.model_dump())


@router.patch("/authorization-profiles/{profile_id}", response_model=AuthzProfileOut)
async def update_authz_profile(profile_id: int, body: AuthzProfileUpdate):
    row = await crud.update(get_pool(), "authorization_profiles", profile_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Authorization profile not found")
    await _invalidate()
    return row


@router.delete("/authorization-profiles/{profile_id}")
async def delete_authz_profile(profile_id: int):
    ok = await crud.delete(get_pool(), "authorization_profiles", profile_id)
    if not ok:
        raise HTTPException(404, "Authorization profile not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# CONDITION LIBRARY
# ─────────────────────────────────────────────

@router.get("/conditions", response_model=list[ConditionOut])
async def list_conditions(
    category: Optional[str] = Query(None),
    condition_type: Optional[str] = Query(None),
):
    filters = {}
    if category:
        filters["category"] = category
    if condition_type:
        filters["condition_type"] = condition_type
    return await crud.get_all(get_pool(), "condition_library", filters=filters,
                              order_by="category ASC, name ASC")


@router.get("/conditions/{cond_id}", response_model=ConditionOut)
async def get_condition(cond_id: int):
    row = await crud.get_by_id(get_pool(), "condition_library", cond_id)
    if not row:
        raise HTTPException(404, "Condition not found")
    return row


@router.post("/conditions", response_model=ConditionOut, status_code=201)
async def create_condition(body: ConditionCreate):
    return await crud.create(get_pool(), "condition_library", body.model_dump())


@router.patch("/conditions/{cond_id}", response_model=ConditionOut)
async def update_condition(cond_id: int, body: ConditionUpdate):
    row = await crud.update(get_pool(), "condition_library", cond_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Condition not found")
    await _invalidate()
    return row


@router.delete("/conditions/{cond_id}")
async def delete_condition(cond_id: int):
    ok = await crud.delete(get_pool(), "condition_library", cond_id)
    if not ok:
        raise HTTPException(404, "Condition not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# POLICY SETS
# ─────────────────────────────────────────────

@router.get("/policy-sets", response_model=list[PolicySetOut])
async def list_policy_sets():
    pool = get_pool()
    sets = await crud.get_all(pool, "policy_sets", order_by="priority ASC")
    # Enrich with nested counts
    for ps in sets:
        ps["auth_policy_count"] = await crud.count(
            pool, "authentication_policies", {"policy_set_id": ps["id"]})
        ps["authz_policy_count"] = await crud.count(
            pool, "authorization_policies", {"policy_set_id": ps["id"]})
    return sets


@router.get("/policy-sets/{ps_id}", response_model=PolicySetDetail)
async def get_policy_set_detail(ps_id: int):
    pool = get_pool()
    ps = await crud.get_by_id(pool, "policy_sets", ps_id)
    if not ps:
        raise HTTPException(404, "Policy set not found")

    # Enrich
    ps["auth_policy_count"] = await crud.count(
        pool, "authentication_policies", {"policy_set_id": ps_id})
    ps["authz_policy_count"] = await crud.count(
        pool, "authorization_policies", {"policy_set_id": ps_id})

    # Condition
    if ps.get("condition_id"):
        ps["condition"] = await crud.get_by_id(pool, "condition_library", ps["condition_id"])

    # Allowed protocols
    if ps.get("allowed_protocols_id"):
        ps["allowed_protocols"] = await crud.get_by_id(
            pool, "allowed_protocols", ps["allowed_protocols_id"])

    # Auth policies
    auth_rules = await crud.get_all(
        pool, "authentication_policies",
        filters={"policy_set_id": ps_id}, order_by="priority ASC")
    for r in auth_rules:
        if r.get("condition_id"):
            r["condition"] = await crud.get_by_id(pool, "condition_library", r["condition_id"])
        if r.get("identity_source_id"):
            r["identity_source"] = await crud.get_by_id(
                pool, "identity_sources", r["identity_source_id"])
    ps["authentication_policies"] = auth_rules

    # Authz policies
    authz_rules = await crud.get_all(
        pool, "authorization_policies",
        filters={"policy_set_id": ps_id}, order_by="priority ASC")
    for r in authz_rules:
        if r.get("condition_id"):
            r["condition"] = await crud.get_by_id(pool, "condition_library", r["condition_id"])
        if r.get("authorization_profile_id"):
            r["authorization_profile"] = await crud.get_by_id(
                pool, "authorization_profiles", r["authorization_profile_id"])
    ps["authorization_policies"] = authz_rules

    return ps


@router.post("/policy-sets", response_model=PolicySetOut, status_code=201)
async def create_policy_set(body: PolicySetCreate):
    row = await crud.create(get_pool(), "policy_sets", body.model_dump())
    row["auth_policy_count"] = 0
    row["authz_policy_count"] = 0
    await _invalidate()
    return row


@router.patch("/policy-sets/{ps_id}", response_model=PolicySetOut)
async def update_policy_set(ps_id: int, body: PolicySetUpdate):
    pool = get_pool()
    row = await crud.update(pool, "policy_sets", ps_id, body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Policy set not found")
    row["auth_policy_count"] = await crud.count(
        pool, "authentication_policies", {"policy_set_id": ps_id})
    row["authz_policy_count"] = await crud.count(
        pool, "authorization_policies", {"policy_set_id": ps_id})
    await _invalidate()
    return row


@router.delete("/policy-sets/{ps_id}")
async def delete_policy_set(ps_id: int):
    ok = await crud.delete(get_pool(), "policy_sets", ps_id)
    if not ok:
        raise HTTPException(404, "Policy set not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# AUTHENTICATION POLICIES
# ─────────────────────────────────────────────

@router.get("/policy-sets/{ps_id}/authentication", response_model=list[AuthenticationPolicyOut])
async def list_auth_policies(ps_id: int):
    pool = get_pool()
    rules = await crud.get_all(
        pool, "authentication_policies",
        filters={"policy_set_id": ps_id}, order_by="priority ASC")
    for r in rules:
        if r.get("condition_id"):
            r["condition"] = await crud.get_by_id(pool, "condition_library", r["condition_id"])
        if r.get("identity_source_id"):
            r["identity_source"] = await crud.get_by_id(
                pool, "identity_sources", r["identity_source_id"])
    return rules


@router.post("/policy-sets/{ps_id}/authentication",
             response_model=AuthenticationPolicyOut, status_code=201)
async def create_auth_policy(ps_id: int, body: AuthenticationPolicyCreate):
    body.policy_set_id = ps_id
    row = await crud.create(get_pool(), "authentication_policies", body.model_dump())
    await _invalidate()
    return row


@router.patch("/authentication-policies/{rule_id}", response_model=AuthenticationPolicyOut)
async def update_auth_policy(rule_id: int, body: AuthenticationPolicyUpdate):
    row = await crud.update(get_pool(), "authentication_policies", rule_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Authentication policy not found")
    await _invalidate()
    return row


@router.delete("/authentication-policies/{rule_id}")
async def delete_auth_policy(rule_id: int):
    ok = await crud.delete(get_pool(), "authentication_policies", rule_id)
    if not ok:
        raise HTTPException(404, "Authentication policy not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# AUTHORIZATION POLICIES
# ─────────────────────────────────────────────

@router.get("/policy-sets/{ps_id}/authorization", response_model=list[AuthorizationPolicyOut])
async def list_authz_policies(ps_id: int):
    pool = get_pool()
    rules = await crud.get_all(
        pool, "authorization_policies",
        filters={"policy_set_id": ps_id}, order_by="priority ASC")
    for r in rules:
        if r.get("condition_id"):
            r["condition"] = await crud.get_by_id(pool, "condition_library", r["condition_id"])
        if r.get("authorization_profile_id"):
            r["authorization_profile"] = await crud.get_by_id(
                pool, "authorization_profiles", r["authorization_profile_id"])
    return rules


@router.post("/policy-sets/{ps_id}/authorization",
             response_model=AuthorizationPolicyOut, status_code=201)
async def create_authz_policy(ps_id: int, body: AuthorizationPolicyCreate):
    body.policy_set_id = ps_id
    row = await crud.create(get_pool(), "authorization_policies", body.model_dump())
    await _invalidate()
    return row


@router.patch("/authorization-policies/{rule_id}", response_model=AuthorizationPolicyOut)
async def update_authz_policy(rule_id: int, body: AuthorizationPolicyUpdate):
    row = await crud.update(get_pool(), "authorization_policies", rule_id,
                            body.model_dump(exclude_unset=True))
    if not row:
        raise HTTPException(404, "Authorization policy not found")
    await _invalidate()
    return row


@router.delete("/authorization-policies/{rule_id}")
async def delete_authz_policy(rule_id: int):
    ok = await crud.delete(get_pool(), "authorization_policies", rule_id)
    if not ok:
        raise HTTPException(404, "Authorization policy not found")
    await _invalidate()
    return {"deleted": True}


# ─────────────────────────────────────────────
# EVALUATION ENDPOINT (used by FreeRADIUS)
# ─────────────────────────────────────────────

@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_policy(body: EvaluateRequest):
    evaluator = get_evaluator()
    result = await evaluator.evaluate(body.attributes)
    return result


# ─────────────────────────────────────────────
# STATS & CACHE CONTROL
# ─────────────────────────────────────────────

@router.get("/stats")
async def policy_stats():
    evaluator = get_evaluator()
    await evaluator.load()
    return evaluator.get_stats()


@router.post("/cache/invalidate")
async def invalidate_cache():
    await _invalidate()
    return {"status": "cache invalidated"}


async def _invalidate():
    if _evaluator:
        await _evaluator.invalidate_cache()
