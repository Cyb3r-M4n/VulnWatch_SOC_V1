# engine/src/main.py
"""Point d'entrée VulnWatch Engine API"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from .api.routes import router
from .database.connection import close_db, init_db
from .utils.logger import setup_logger

setup_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Démarrage VulnWatch Engine")
    await init_db()
    yield
    logger.info("Arrêt VulnWatch Engine")
    await close_db()


app = FastAPI(
    title="VulnWatch Engine API",
    description=(
        "API de détection / corrélation / proposition de correctifs. "
        "Aucun correctif n'est appliqué automatiquement — validation cybersec obligatoire."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "name": "VulnWatch Engine",
        "version": "1.0.0",
        "status": "running",
        "policy": "detect-propose-validate — no auto-apply",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "vulnwatch-engine"}
