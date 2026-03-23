"""
/api/v1/auth-log — лог аутентификаций из radpostauth.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db

router = APIRouter()


@router.get("/auth-log")
async def get_auth_log(
    search: str = Query(""),
    result: str = Query("", description="Access-Accept, Access-Reject"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    where = ["1=1"]
    params = {"limit": limit, "offset": offset}

    if search:
        where.append("(username LIKE :s OR callingstationid LIKE :s OR nasipaddress LIKE :s)")
        params["s"] = f"%{search}%"
    if result:
        where.append("reply = :result")
        params["result"] = result

    where_str = " AND ".join(where)

    count_r = await db.execute(text(f"SELECT COUNT(*) FROM radpostauth WHERE {where_str}"), params)
    total = count_r.scalar()

    rows_r = await db.execute(
        text(f"""
            SELECT id, username, reply, authdate, callingstationid, calledstationid, nasipaddress, class
            FROM radpostauth WHERE {where_str}
            ORDER BY id DESC LIMIT :limit OFFSET :offset
        """),
        params,
    )
    items = []
    for r in rows_r.fetchall():
        items.append({
            "id": r[0], "username": r[1], "result": r[2], "timestamp": str(r[3]),
            "mac": r[4], "called_station": r[5], "nas_ip": r[6], "class": r[7],
        })

    return {"total": total, "items": items}


@router.get("/auth-log/stats")
async def auth_log_stats(db: AsyncSession = Depends(get_db)):
    """Статистика за последний час."""
    result = await db.execute(text("""
        SELECT reply, COUNT(*) as cnt
        FROM radpostauth
        WHERE authdate >= NOW() - INTERVAL 1 HOUR
        GROUP BY reply
    """))
    stats = {r[0]: r[1] for r in result.fetchall()}

    top_users = await db.execute(text("""
        SELECT username, COUNT(*) as cnt
        FROM radpostauth
        WHERE authdate >= NOW() - INTERVAL 1 HOUR AND reply = 'Access-Accept'
        GROUP BY username ORDER BY cnt DESC LIMIT 10
    """))

    top_failures = await db.execute(text("""
        SELECT username, nasipaddress, COUNT(*) as cnt
        FROM radpostauth
        WHERE authdate >= NOW() - INTERVAL 1 HOUR AND reply = 'Access-Reject'
        GROUP BY username, nasipaddress ORDER BY cnt DESC LIMIT 10
    """))

    return {
        "last_hour": stats,
        "top_users": [{"username": r[0], "count": r[1]} for r in top_users.fetchall()],
        "top_failures": [{"username": r[0], "nas_ip": r[1], "count": r[2]} for r in top_failures.fetchall()],
    }
