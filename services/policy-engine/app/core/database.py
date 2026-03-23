"""
Database: async SQLAlchemy + MariaDB через ProxySQL.
"""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DB_USER = os.getenv("MYSQL_USER", "radius")
DB_PASS = os.getenv("MYSQL_PASSWORD", "changeme_radius_pwd")
DB_HOST = os.getenv("MYSQL_HOST", "proxysql")
DB_PORT = os.getenv("MYSQL_PORT", "6033")
DB_NAME = os.getenv("MYSQL_DATABASE", "radius")

DATABASE_URL = f"mysql+aiomysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

engine = create_async_engine(DATABASE_URL, pool_size=20, max_overflow=10, pool_recycle=3600, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        yield session
