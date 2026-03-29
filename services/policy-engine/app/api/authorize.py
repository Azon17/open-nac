"""
Open NAC — FreeRADIUS Authorization Endpoint
Called by rlm_rest when FreeRADIUS receives Access-Request.
Translates RADIUS attributes → ISE-style evaluation → RADIUS reply.
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.api.policy_routes import get_evaluator

logger = logging.getLogger("authorize")
router = APIRouter(tags=["FreeRADIUS Integration"])


# Mapping of common RADIUS attribute names to our namespaced format
RADIUS_ATTR_MAP = {
    "User-Name":            "RADIUS:User-Name",
    "NAS-IP-Address":       "RADIUS:NAS-IP-Address",
    "NAS-Port-Type":        "RADIUS:NAS-Port-Type",
    "NAS-Port":             "RADIUS:NAS-Port",
    "NAS-Identifier":       "RADIUS:NAS-Identifier",
    "Calling-Station-Id":   "RADIUS:Calling-Station-Id",
    "Called-Station-Id":     "RADIUS:Called-Station-Id",
    "Service-Type":         "RADIUS:Service-Type",
    "Framed-MTU":           "RADIUS:Framed-MTU",
    "EAP-Type":             "RADIUS:EAP-Type",
    "NAS-Port-Id":          "RADIUS:NAS-Port-Id",
    "Connect-Info":         "RADIUS:Connect-Info",
    "Acct-Session-Id":      "RADIUS:Acct-Session-Id",
}


def normalize_radius_request(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw FreeRADIUS rlm_rest POST body to namespaced context."""
    context = {}
    for key, value in raw.items():
        # Skip internal FreeRADIUS keys
        if key.startswith("__"):
            continue
        # Map known attributes
        mapped = RADIUS_ATTR_MAP.get(key)
        if mapped:
            context[mapped] = value
        else:
            # Keep as-is but add RADIUS: prefix if not already namespaced
            if ":" not in key:
                context[f"RADIUS:{key}"] = value
            else:
                context[key] = value

    # Normalize Calling-Station-Id (MAC) format: uppercase, colon-separated
    mac = context.get("RADIUS:Calling-Station-Id", "")
    if mac:
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        # Handle Cisco format (aabb.ccdd.eeff → AA:BB:CC:DD:EE:FF)
        if len(mac_clean) == 14 and ":" not in mac_clean:
            mac_clean = ":".join(
                mac_clean.replace(".", "")[i:i+2] for i in range(0, 12, 2)
            )
        context["RADIUS:Calling-Station-Id"] = mac_clean

    return context


@router.post("/api/v2/authorize")
async def authorize(request: Request):
    """
    Called by FreeRADIUS rlm_rest.
    
    Input: RADIUS Access-Request attributes (form or JSON)
    Output: RADIUS reply attributes (JSON) for Access-Accept/Reject
    
    FreeRADIUS rlm_rest config:
        authorize {
            uri = "http://policy-engine:8000/api/v2/authorize"
            method = 'post'
            body = 'json'
            ...
        }
    """
    # Parse request body (support both form and JSON)
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        raw = await request.json()
    else:
        form = await request.form()
        raw = dict(form)

    logger.info(f"RADIUS request: User-Name={raw.get('User-Name', 'unknown')}, "
                f"NAS-IP={raw.get('NAS-IP-Address', '?')}, "
                f"MAC={raw.get('Calling-Station-Id', '?')}")

    # Normalize to namespaced context
    context = normalize_radius_request(raw)

    # Run ISE-style evaluation
    evaluator = get_evaluator()
    result = await evaluator.evaluate(context)

    logger.info(f"Policy decision: {result['decision']} "
                f"(set={result['policy_set']}, authz={result['authz_rule']}, "
                f"time={result['evaluation_time_ms']}ms)")

    # Format response for FreeRADIUS rlm_rest
    if result["decision"] == "accept":
        reply = {
            "control:Auth-Type": "Accept",
        }
        # Add RADIUS reply attributes from authorization profile
        for attr_name, attr_value in result.get("radius_attributes", {}).items():
            if isinstance(attr_value, list):
                # Multi-valued attributes (e.g., Cisco-AVPair)
                for i, v in enumerate(attr_value):
                    reply[f"reply:{attr_name}"] = v  # rlm_rest handles += for multi
            else:
                reply[f"reply:{attr_name}"] = str(attr_value)

        return JSONResponse(content=reply, status_code=200)

    elif result["decision"] == "drop":
        return JSONResponse(content={}, status_code=204)

    else:  # reject
        return JSONResponse(
            content={"control:Auth-Type": "Reject"},
            status_code=200
        )


@router.post("/api/v2/post-auth")
async def post_auth(request: Request):
    """Post-authentication hook — logging and accounting."""
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        raw = await request.json()
    else:
        form = await request.form()
        raw = dict(form)

    logger.info(f"Post-auth: User={raw.get('User-Name', '?')}, "
                f"Reply={raw.get('Reply-Message', '?')}, "
                f"MAC={raw.get('Calling-Station-Id', '?')}")
    return JSONResponse(content={}, status_code=200)
