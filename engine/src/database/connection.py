# engine/src/database/connection.py
"""Gestion de la connexion à PostgreSQL"""

import os
import asyncpg
from loguru import logger
from contextlib import asynccontextmanager

# Configuration
DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", 5432)),
    "database": os.getenv("POSTGRES_DB", "vulnwatch"),
    "user": os.getenv("POSTGRES_USER", "vulnwatch"),
    "password": os.getenv("POSTGRES_PASSWORD", "ChangeMe123!")
}

# Pool de connexions
_pool = None

async def init_db():
    """Initialise le pool de connexions"""
    global _pool
    try:
        _pool = await asyncpg.create_pool(
            **DB_CONFIG,
            min_size=1,
            max_size=10,
            command_timeout=60
        )
        logger.info("✅ Pool de connexions PostgreSQL créé")
        
        # Tester la connexion
        async with _pool.acquire() as conn:
            result = await conn.fetchval("SELECT version()")
            logger.info(f"📊 PostgreSQL version: {result}")
            
    except Exception as e:
        logger.error(f"❌ Erreur de connexion à PostgreSQL: {e}")
        raise

async def close_db():
    """Ferme le pool de connexions"""
    global _pool
    if _pool:
        await _pool.close()
        logger.info("🔒 Pool de connexions fermé")

@asynccontextmanager
async def get_db_connection():
    """Context manager pour obtenir une connexion"""
    global _pool
    if not _pool:
        await init_db()
    
    async with _pool.acquire() as conn:
        yield conn

async def execute_query(query: str, *args):
    """Exécute une requête et retourne les résultats"""
    async with get_db_connection() as conn:
        return await conn.fetch(query, *args)

async def execute_query_row(query: str, *args):
    """Exécute une requête et retourne une ligne"""
    async with get_db_connection() as conn:
        return await conn.fetchrow(query, *args)

async def execute_query_val(query: str, *args):
    """Exécute une requête et retourne une valeur"""
    async with get_db_connection() as conn:
        return await conn.fetchval(query, *args)

async def execute_command(query: str, *args):
    """Exécute une commande (INSERT, UPDATE, DELETE)"""
    async with get_db_connection() as conn:
        return await conn.execute(query, *args)
