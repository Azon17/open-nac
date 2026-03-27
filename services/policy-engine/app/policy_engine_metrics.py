"""
Open NAC — Policy Engine Prometheus Metrics
============================================
Add this to the FastAPI Policy Engine app to expose /metrics.

Install: pip install prometheus-client prometheus-fastapi-instrumentator

Usage in main.py:
    from policy_engine_metrics import setup_metrics
    app = FastAPI()
    setup_metrics(app)
"""

from prometheus_client import Counter, Gauge, Histogram, Info
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi import FastAPI


# ---------------------------------------------------------------------------
# Custom metrics (business-level)
# ---------------------------------------------------------------------------

# Auth decisions
REQUESTS_TOTAL = Counter(
    "policy_engine_requests_total",
    "Total policy evaluation requests",
    ["status", "policy_set", "auth_method"],
)

REQUEST_DURATION = Histogram(
    "policy_engine_request_duration_seconds",
    "Policy evaluation latency",
    ["policy_set"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Endpoint inventory
CONNECTED_ENDPOINTS = Gauge(
    "policy_engine_connected_endpoints",
    "Currently connected and authenticated endpoints",
)

ENDPOINTS_BY_STATUS = Gauge(
    "policy_engine_endpoints_by_status",
    "Endpoints grouped by auth status",
    ["status"],  # authenticated, pending, rejected, quarantined
)

NEW_ENDPOINTS_TOTAL = Counter(
    "policy_engine_new_endpoints_total",
    "Newly seen endpoints",
)

AUTH_BY_VLAN = Gauge(
    "policy_engine_auth_by_vlan",
    "Authenticated endpoints by VLAN assignment",
    ["vlan"],
)

# CoA
COA_TOTAL = Counter(
    "policy_engine_coa_total",
    "Change of Authorization events",
    ["action"],  # reauthenticate, bounce, disable
)

# App info
APP_INFO = Info(
    "policy_engine",
    "Policy Engine build info",
)


def setup_metrics(app: FastAPI) -> None:
    """Attach Prometheus metrics to a FastAPI application."""

    # Automatic HTTP metrics (request count, latency, in-progress)
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/health", "/ready"],
    ).instrument(app).expose(app, endpoint="/metrics")

    # Set build info
    APP_INFO.info({
        "version": "1.0.0",
        "component": "policy-engine",
    })


# ---------------------------------------------------------------------------
# Helper functions for the Policy Engine to call
# ---------------------------------------------------------------------------

def record_policy_decision(
    status_code: int,
    policy_set: str,
    auth_method: str,
    duration_seconds: float,
) -> None:
    """Call after each policy evaluation."""
    status_bucket = f"{status_code // 100}xx"
    REQUESTS_TOTAL.labels(
        status=status_bucket,
        policy_set=policy_set,
        auth_method=auth_method,
    ).inc()
    REQUEST_DURATION.labels(policy_set=policy_set).observe(duration_seconds)


def update_endpoint_counts(
    connected: int,
    by_status: dict[str, int],
    by_vlan: dict[str, int],
) -> None:
    """Call periodically (e.g., every 15s) to update gauge metrics."""
    CONNECTED_ENDPOINTS.set(connected)
    for status, count in by_status.items():
        ENDPOINTS_BY_STATUS.labels(status=status).set(count)
    for vlan, count in by_vlan.items():
        AUTH_BY_VLAN.labels(vlan=vlan).set(count)


def record_new_endpoint() -> None:
    NEW_ENDPOINTS_TOTAL.inc()


def record_coa(action: str) -> None:
    COA_TOTAL.labels(action=action).inc()
