"""
Open NAC — Generic async CRUD helpers for MariaDB
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import aiomysql

logger = logging.getLogger("crud")


async def get_all(pool: aiomysql.Pool, table: str,
                  filters: Optional[Dict[str, Any]] = None,
                  order_by: str = "id ASC",
                  limit: int = 1000, offset: int = 0) -> List[dict]:
    where_clauses = []
    params = []
    if filters:
        for k, v in filters.items():
            where_clauses.append(f"`{k}` = %s")
            params.append(v)
    where = " AND ".join(where_clauses) if where_clauses else "1=1"
    sql = f"SELECT * FROM `{table}` WHERE {where} ORDER BY {order_by} LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
    return [_serialize(r) for r in rows]


async def get_by_id(pool: aiomysql.Pool, table: str, row_id: int) -> Optional[dict]:
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(f"SELECT * FROM `{table}` WHERE id = %s", (row_id,))
            row = await cur.fetchone()
    return _serialize(row) if row else None


async def create(pool: aiomysql.Pool, table: str, data: dict) -> dict:
    # Filter out None values and serialize JSON fields
    clean = {}
    for k, v in data.items():
        if v is None:
            continue
        if isinstance(v, (dict, list)):
            clean[k] = json.dumps(v)
        elif hasattr(v, "value"):  # Enum
            clean[k] = v.value
        else:
            clean[k] = v

    cols = ", ".join(f"`{k}`" for k in clean.keys())
    placeholders = ", ".join(["%s"] * len(clean))
    sql = f"INSERT INTO `{table}` ({cols}) VALUES ({placeholders})"

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, list(clean.values()))
            new_id = cur.lastrowid
            await conn.commit()

    return await get_by_id(pool, table, new_id)


async def update(pool: aiomysql.Pool, table: str, row_id: int, data: dict) -> Optional[dict]:
    # Only include explicitly set (non-None) fields
    clean = {}
    for k, v in data.items():
        if v is None:
            continue
        if isinstance(v, (dict, list)):
            clean[k] = json.dumps(v)
        elif hasattr(v, "value"):
            clean[k] = v.value
        else:
            clean[k] = v

    if not clean:
        return await get_by_id(pool, table, row_id)

    set_clause = ", ".join(f"`{k}` = %s" for k in clean.keys())
    sql = f"UPDATE `{table}` SET {set_clause} WHERE id = %s"
    params = list(clean.values()) + [row_id]

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            await conn.commit()

    return await get_by_id(pool, table, row_id)


async def delete(pool: aiomysql.Pool, table: str, row_id: int) -> bool:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(f"DELETE FROM `{table}` WHERE id = %s", (row_id,))
            affected = cur.rowcount
            await conn.commit()
    return affected > 0


async def count(pool: aiomysql.Pool, table: str,
                filters: Optional[Dict[str, Any]] = None) -> int:
    where_clauses = []
    params = []
    if filters:
        for k, v in filters.items():
            where_clauses.append(f"`{k}` = %s")
            params.append(v)
    where = " AND ".join(where_clauses) if where_clauses else "1=1"
    sql = f"SELECT COUNT(*) as cnt FROM `{table}` WHERE {where}"

    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, params)
            row = await cur.fetchone()
    return row["cnt"] if row else 0


def _serialize(row: Optional[dict]) -> Optional[dict]:
    if row is None:
        return None
    out = {}
    for k, v in row.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif isinstance(v, bytes):
            out[k] = v.decode("utf-8", errors="replace")
        else:
            out[k] = v
    return out
