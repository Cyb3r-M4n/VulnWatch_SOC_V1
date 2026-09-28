# engine/src/main.py
"""Point d'entrée principal de l'API VulnWatch Engine"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .database.connection import init_db, close_db
from .api.routes import router
from .utils.logger import setup_logger

# Configuration du logger
setup_logger()

# Définir le lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gère le cycle de vie de l'application"""
    # Démarrage
    logger.info("🚀 Démarrage du VulnWatch Engine...")
    await init_db()
    logger.info("✅ Connexion à PostgreSQL établie")
    yield
    # Arrêt
    logger.info("🛑 Arrêt du VulnWatch Engine...")
    await close_db()

# Créer l'application FastAPI
app = FastAPI(
    title="VulnWatch Engine API",
    description="API de corrélation des vulnérabilités pour VulnWatch SOC",
    version="1.0.0",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclure les routes
app.include_router(router, prefix="/api/v1")

# Routes de base
@app.get("/")
async def root():
    """Route racine"""
    return {
        "name": "VulnWatch Engine",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check pour Docker"""
    return {
        "status": "healthy",
        "service": "vulnwatch-engine"
    }
