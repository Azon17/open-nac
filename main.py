"""
Open NAC — Policy Engine (FastAPI)
Центральный сервис: авторизация, профилирование, события, Admin API.
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import engine, Base
from app.core.redis_client import redis_pool
from app.core.kafka_producer import kafka_producer
from app.api import (
    authorize,
    endpoints,
    policies,
    profiling,
    events,
    network_devices,
    guest_accounts,
    dashboard,
    coa,
    auth_log,
)

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nac.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Open NAC Policy Engine...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await kafka_producer.start()
    await redis_pool.initialize()
    logger.info("Policy Engine ready on :8000")
    yield
    await kafka_producer.stop()
    await redis_pool.close()
    await engine.dispose()


app = FastAPI(
    title="Open NAC Policy Engine",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# RADIUS-facing (FreeRADIUS rlm_rest вызывает эти endpoints)
app.include_router(authorize.router, prefix="/api/v1", tags=["RADIUS"])
app.include_router(profiling.router, prefix="/api/v1", tags=["RADIUS"])
app.include_router(events.router, prefix="/api/v1", tags=["RADIUS"])

# Admin UI
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])
app.include_router(endpoints.router, prefix="/api/v1", tags=["Endpoints"])
app.include_router(policies.router, prefix="/api/v1", tags=["Policies"])
app.include_router(network_devices.router, prefix="/api/v1", tags=["NAS"])
app.include_router(guest_accounts.router, prefix="/api/v1", tags=["Guest"])
app.include_router(coa.router, prefix="/api/v1", tags=["CoA"])
app.include_router(auth_log.router, prefix="/api/v1", tags=["Logs"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "policy-engine"}
