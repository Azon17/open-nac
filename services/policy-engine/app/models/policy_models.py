"""
Open NAC — Pydantic Models for ISE-Style Policy Module
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class SourceType(str, Enum):
    internal = "internal"
    active_directory = "active_directory"
    ldap = "ldap"
    certificate = "certificate"
    mab = "mab"

class AccessType(str, Enum):
    access_accept = "access_accept"
    access_reject = "access_reject"

class ConditionType(str, Enum):
    simple = "simple"
    compound = "compound"

class ConditionOperator(str, Enum):
    equals = "equals"
    not_equals = "not_equals"
    contains = "contains"
    not_contains = "not_contains"
    starts_with = "starts_with"
    ends_with = "ends_with"
    matches_regex = "matches_regex"
    in_ = "in"
    not_in = "not_in"
    greater_than = "greater_than"
    less_than = "less_than"
    exists = "exists"
    not_exists = "not_exists"

class CompoundOperator(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"

class OnFailureAction(str, Enum):
    reject = "reject"
    continue_ = "continue"
    drop = "drop"

class ReauthType(str, Enum):
    default = "default"
    last = "last"
    reauth = "reauth"

class ConditionCategory(str, Enum):
    Network = "Network"
    Device = "Device"
    User = "User"
    Posture = "Posture"
    General = "General"


# ─────────────────────────────────────────────
# Identity Sources
# ─────────────────────────────────────────────

class IdentitySourceBase(BaseModel):
    name: str = Field(..., max_length=128)
    source_type: SourceType
    description: str = ""
    config_json: Optional[Dict[str, Any]] = None
    priority: int = 0
    enabled: bool = True

class IdentitySourceCreate(IdentitySourceBase):
    pass

class IdentitySourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[SourceType] = None
    description: Optional[str] = None
    config_json: Optional[Dict[str, Any]] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None

class IdentitySourceOut(IdentitySourceBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Allowed Protocols
# ─────────────────────────────────────────────

class AllowedProtocolsBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    allow_pap: bool = True
    allow_chap: bool = False
    allow_mschap_v2: bool = True
    allow_peap: bool = True
    allow_eap_tls: bool = True
    allow_eap_fast: bool = False
    allow_eap_ttls: bool = False
    allow_eap_md5: bool = False
    peap_inner_mschap_v2: bool = True
    peap_inner_eap_gtc: bool = False
    ttls_inner_pap: bool = True
    ttls_inner_mschap_v2: bool = False
    enabled: bool = True

class AllowedProtocolsCreate(AllowedProtocolsBase):
    pass

class AllowedProtocolsUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    allow_pap: Optional[bool] = None
    allow_chap: Optional[bool] = None
    allow_mschap_v2: Optional[bool] = None
    allow_peap: Optional[bool] = None
    allow_eap_tls: Optional[bool] = None
    allow_eap_fast: Optional[bool] = None
    allow_eap_ttls: Optional[bool] = None
    allow_eap_md5: Optional[bool] = None
    peap_inner_mschap_v2: Optional[bool] = None
    peap_inner_eap_gtc: Optional[bool] = None
    ttls_inner_pap: Optional[bool] = None
    ttls_inner_mschap_v2: Optional[bool] = None
    enabled: Optional[bool] = None

class AllowedProtocolsOut(AllowedProtocolsBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Authorization Profiles
# ─────────────────────────────────────────────

class AuthzProfileBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    access_type: AccessType = AccessType.access_accept
    vlan_id: Optional[int] = None
    vlan_name: Optional[str] = None
    acl_name: Optional[str] = None
    dacl_name: Optional[str] = None
    sgt: Optional[int] = None
    url_redirect: Optional[str] = None
    url_redirect_acl: Optional[str] = None
    session_timeout: Optional[int] = None
    idle_timeout: Optional[int] = None
    reauth_timer: Optional[int] = None
    reauth_type: ReauthType = ReauthType.default
    voice_vlan: Optional[int] = None
    extra_attributes_json: Optional[List[Dict[str, Any]]] = None
    enabled: bool = True

class AuthzProfileCreate(AuthzProfileBase):
    pass

class AuthzProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    access_type: Optional[AccessType] = None
    vlan_id: Optional[int] = None
    vlan_name: Optional[str] = None
    acl_name: Optional[str] = None
    dacl_name: Optional[str] = None
    sgt: Optional[int] = None
    url_redirect: Optional[str] = None
    url_redirect_acl: Optional[str] = None
    session_timeout: Optional[int] = None
    idle_timeout: Optional[int] = None
    reauth_timer: Optional[int] = None
    reauth_type: Optional[ReauthType] = None
    voice_vlan: Optional[int] = None
    extra_attributes_json: Optional[List[Dict[str, Any]]] = None
    enabled: Optional[bool] = None

class AuthzProfileOut(AuthzProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Condition Library
# ─────────────────────────────────────────────

class CompoundConditionDef(BaseModel):
    operator: CompoundOperator
    children: List[Union[int, "CompoundConditionDef"]]

class ConditionBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    condition_type: ConditionType = ConditionType.simple
    attribute: Optional[str] = None
    operator: Optional[ConditionOperator] = None
    value: Optional[str] = None
    compound_json: Optional[CompoundConditionDef] = None
    category: ConditionCategory = ConditionCategory.General
    reusable: bool = True
    enabled: bool = True

class ConditionCreate(ConditionBase):
    pass

class ConditionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_type: Optional[ConditionType] = None
    attribute: Optional[str] = None
    operator: Optional[ConditionOperator] = None
    value: Optional[str] = None
    compound_json: Optional[CompoundConditionDef] = None
    category: Optional[ConditionCategory] = None
    reusable: Optional[bool] = None
    enabled: Optional[bool] = None

class ConditionOut(ConditionBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Policy Sets
# ─────────────────────────────────────────────

class PolicySetBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    allowed_protocols_id: Optional[int] = None
    priority: int = 100
    is_default: bool = False
    enabled: bool = True

class PolicySetCreate(PolicySetBase):
    pass

class PolicySetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    allowed_protocols_id: Optional[int] = None
    priority: Optional[int] = None
    is_default: Optional[bool] = None
    enabled: Optional[bool] = None

class PolicySetOut(PolicySetBase):
    id: int
    hit_count: int = 0
    created_at: datetime
    updated_at: datetime
    # Nested counts
    auth_policy_count: int = 0
    authz_policy_count: int = 0
    class Config:
        from_attributes = True

class PolicySetDetail(PolicySetOut):
    """Full policy set with nested auth/authz policies."""
    condition: Optional[ConditionOut] = None
    allowed_protocols: Optional[AllowedProtocolsOut] = None
    authentication_policies: List["AuthenticationPolicyOut"] = []
    authorization_policies: List["AuthorizationPolicyOut"] = []


# ─────────────────────────────────────────────
# Authentication Policies
# ─────────────────────────────────────────────

class AuthenticationPolicyBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    policy_set_id: int
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    identity_source_id: Optional[int] = None
    on_failure: OnFailureAction = OnFailureAction.reject
    priority: int = 100
    enabled: bool = True

class AuthenticationPolicyCreate(AuthenticationPolicyBase):
    pass

class AuthenticationPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    identity_source_id: Optional[int] = None
    on_failure: Optional[OnFailureAction] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None

class AuthenticationPolicyOut(AuthenticationPolicyBase):
    id: int
    hit_count: int = 0
    created_at: datetime
    updated_at: datetime
    condition: Optional[ConditionOut] = None
    identity_source: Optional[IdentitySourceOut] = None
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Authorization Policies
# ─────────────────────────────────────────────

class AuthorizationPolicyBase(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    policy_set_id: int
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    authorization_profile_id: Optional[int] = None
    priority: int = 100
    is_default: bool = False
    enabled: bool = True

class AuthorizationPolicyCreate(AuthorizationPolicyBase):
    pass

class AuthorizationPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_id: Optional[int] = None
    condition_json: Optional[Dict[str, Any]] = None
    authorization_profile_id: Optional[int] = None
    priority: Optional[int] = None
    is_default: Optional[bool] = None
    enabled: Optional[bool] = None

class AuthorizationPolicyOut(AuthorizationPolicyBase):
    id: int
    hit_count: int = 0
    created_at: datetime
    updated_at: datetime
    condition: Optional[ConditionOut] = None
    authorization_profile: Optional[AuthzProfileOut] = None
    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Evaluation request/response
# ─────────────────────────────────────────────

class EvaluateRequest(BaseModel):
    """RADIUS request context for policy evaluation."""
    attributes: Dict[str, Any] = Field(
        ...,
        description="RADIUS and enrichment attributes, e.g. {'RADIUS:User-Name': 'john', 'AD:memberOf': '...'}"
    )

class EvaluateResponse(BaseModel):
    decision: str
    policy_set: Optional[str] = None
    auth_rule: Optional[str] = None
    authz_rule: Optional[str] = None
    identity_source: Optional[Dict[str, Any]] = None
    authorization_profile: Optional[Dict[str, Any]] = None
    radius_attributes: Dict[str, Any] = {}
    evaluation_time_ms: float = 0


# Resolve forward references
PolicySetDetail.model_rebuild()
