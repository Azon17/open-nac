"""
Open NAC — Policy Engine (FastAPI)
ISE-Style Policy Module — Main Application
"""

import logging
import os

import aiomysql
import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.policy_routes import router as policy_router, init_dependencies
from app.api.authorize import router as authorize_router

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("main")

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "mariadb-node1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "nac_user")
DB_PASS = os.getenv("DB_PASS", "MyStr0ng!")
DB_NAME = os.getenv("DB_NAME", "open_nac")

REDIS_HOST = os.getenv("REDIS_HOST", "redis-node1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS = os.getenv("REDIS_PASS", "MyStr0ng!")

# ─────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────
app = FastAPI(
    title="Open NAC — Policy Engine",
    description="ISE-Style 3-Level Policy Evaluation Engine",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(policy_router)
app.include_router(authorize_router)


@app.on_event("startup")
async def startup():
    logger.info("Starting Policy Engine v2.0 (ISE-style)...")

    # MariaDB pool
    pool = await aiomysql.create_pool(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASS,
        db=DB_NAME, charset="utf8mb4",
        minsize=2, maxsize=10,
        autocommit=True,
    )
    logger.info(f"MariaDB pool created: {DB_HOST}:{DB_PORT}/{DB_NAME}")

    # Redis
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        password=REDIS_PASS, decode_responses=True,
    )
    await redis_client.ping()
    logger.info(f"Redis connected: {REDIS_HOST}:{REDIS_PORT}")

    # Initialize dependencies
    init_dependencies(pool, redis_client)

    # Pre-load policy cache
    from app.api.policy_routes import get_evaluator
    evaluator = get_evaluator()
    await evaluator.load(force=True)
    stats = evaluator.get_stats()
    logger.info(f"Policy engine ready: {stats}")

    # Store for cleanup
    app.state.db_pool = pool
    app.state.redis = redis_client


@app.on_event("shutdown")
async def shutdown():
    logger.info("Shutting down Policy Engine...")
    if hasattr(app.state, "db_pool"):
        app.state.db_pool.close()
        await app.state.db_pool.wait_closed()
    if hasattr(app.state, "redis"):
        await app.state.redis.close()


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "module": "ISE-Style Policy Engine"}
