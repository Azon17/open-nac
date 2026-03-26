"""
Periodic scheduler for posture re-assessment.
Like Cisco ISE periodic posture reassessment (default every 4 hours).
"""

import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger("nac.scheduler")

scheduler = AsyncIOScheduler()


def start_scheduler(compliance_engine, fleet_client, coa_trigger):
    """Start periodic posture checks."""

    @scheduler.scheduled_job("interval", minutes=int(__import__("os").getenv("COMPLIANCE_CHECK_INTERVAL", "240")))
    async def periodic_reassessment():
        """Re-assess all endpoints with stale posture data."""
        logger.info("SCHEDULER: Starting periodic posture reassessment")
        from app.db import async_session
        async with async_session() as db:
            stale = await coa_trigger.bulk_reassess(db)
            for ep in stale:
                try:
                    if fleet_client.available:
                        fleet_data = await fleet_client.get_host_by_identifier(
                            ep["ip"] or ep["hostname"] or ep["mac"]
                        )
                        if fleet_data:
                            result = compliance_engine.evaluate_fleet(fleet_data)
                            from sqlalchemy import text
                            await db.execute(text(
                                "UPDATE nac_endpoints SET posture_status = :s, last_posture_check = NOW() WHERE mac_address = :m"
                            ), {"s": result["status"], "m": ep["mac"]})
                            await db.commit()
                            await coa_trigger.check_and_coa(db, ep["mac"], result["status"])
                except Exception as e:
                    logger.warning(f"Reassessment failed for {ep['mac']}: {e}")

        logger.info("SCHEDULER: Periodic reassessment complete")

    @scheduler.scheduled_job("interval", minutes=60)
    async def expire_stale_sessions():
        """Mark endpoints not seen in 24h as unknown posture."""
        logger.info("SCHEDULER: Expiring stale posture status")
        from app.db import async_session
        from sqlalchemy import text
        async with async_session() as db:
            r = await db.execute(text("""
                UPDATE nac_endpoints
                SET posture_status = 'unknown'
                WHERE posture_status IN ('compliant', 'non_compliant')
                  AND last_seen < NOW() - INTERVAL 24 HOUR
            """))
            await db.commit()
            logger.info(f"SCHEDULER: Expired {r.rowcount} stale endpoints")

    scheduler.start()
    logger.info(f"Scheduler started — reassessment interval: "
                f"{__import__('os').getenv('COMPLIANCE_CHECK_INTERVAL', '240')} minutes")
