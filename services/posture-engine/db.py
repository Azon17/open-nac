"""Database connection for Posture Engine."""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DB_URL = (
    f"mysql+aiomysql://{os.getenv('MYSQL_USER', 'radius')}:"
    f"{os.getenv('MYSQL_PASSWORD', 'changeme_radius_pwd')}@"
    f"{os.getenv('MYSQL_HOST', 'mariadb-1')}:"
    f"{os.getenv('MYSQL_PORT', '3306')}/"
    f"{os.getenv('MYSQL_DATABASE', 'radius')}"
)

engine = create_async_engine(DB_URL, pool_size=10, max_overflow=20, pool_recycle=3600)

class Base(DeclarativeBase):
    pass

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with async_session() as session:
        yield session
