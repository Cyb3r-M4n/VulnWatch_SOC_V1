# engine/src/api/routes.py
"""Routes API du Vulnerability Engine"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from loguru import logger

from ..database.connection import execute_query, execute_query_row, execute_command

# Créer le routeur
router = APIRouter()

# ============================================
# MODÈLES Pydantic
# ============================================

class Asset(BaseModel):
    """Modèle d'un actif (machine)"""
    id: Optional[int] = None
    hostname: str
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: str = "active"
    last_seen: Optional[datetime] = None

class Software(BaseModel):
    """Modèle d'un logiciel installé"""
    id: Optional[int] = None
    asset_id: int
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None

class CVE(BaseModel):
    """Modèle d'une vulnérabilité"""
    id: Optional[int] = None
    cve_id: str
    product: Optional[str] = None
    vendor: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    kev: bool = False

class Finding(BaseModel):
    """Modèle d'une corrélation détectée"""
    id: Optional[int] = None
    asset_id: int
    software_id: Optional[int] = None
    cve_id: int
    risk_level: str
    cvss_at_detection: Optional[float] = None
    status: str = "active"

class CorrelationResult(BaseModel):
    """Résultat de la corrélation"""
    new_findings: int
    updated_findings: int
    process_findings: int

# ============================================
# ROUTES
# ============================================

@router.get("/assets", response_model=List[Asset])
async def get_assets(
    status: Optional[str] = Query(None, description="Filtrer par statut"),
    limit: int = Query(100, ge=1, le=1000)
):
    """Récupère la liste des actifs"""
    try:
        query = """
            SELECT id, hostname, ip_address, os_name, os_version, status, last_seen
            FROM assets
            WHERE ($1::text IS NULL OR status = $1)
            ORDER BY hostname
            LIMIT $2
        """
        rows = await execute_query(query, status, limit)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: int):
    """Récupère un actif par son ID"""
    try:
        query = """
            SELECT id, hostname, ip_address, os_name, os_version, status, last_seen
            FROM assets
            WHERE id = $1
        """
        row = await execute_query_row(query, asset_id)
        if not row:
            raise HTTPException(status_code=404, detail="Asset non trouvé")
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/assets/{asset_id}/software", response_model=List[Software])
async def get_asset_software(asset_id: int):
    """Récupère les logiciels installés sur un actif"""
    try:
        query = """
            SELECT id, asset_id, name, version, vendor
            FROM software
            WHERE asset_id = $1
            ORDER BY name
        """
        rows = await execute_query(query, asset_id)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des logiciels: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cves", response_model=List[CVE])
async def get_cves(
    severity: Optional[str] = Query(None, description="Filtrer par sévérité"),
    kev: Optional[bool] = Query(None, description="Filtrer par KEV"),
    limit: int = Query(100, ge=1, le=1000)
):
    """Récupère la liste des CVE"""
    try:
        query = """
            SELECT id, cve_id, product, vendor, cvss_score, severity, description, kev
            FROM cves
            WHERE ($1::text IS NULL OR severity = $1)
            AND ($2::boolean IS NULL OR kev = $2)
            ORDER BY cvss_score DESC
            LIMIT $3
        """
        rows = await execute_query(query, severity, kev, limit)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des CVE: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cves/{cve_id}", response_model=CVE)
async def get_cve(cve_id: str):
    """Récupère une CVE par son ID"""
    try:
        query = """
            SELECT id, cve_id, product, vendor, cvss_score, severity, description, kev
            FROM cves
            WHERE cve_id = $1
        """
        row = await execute_query_row(query, cve_id)
        if not row:
            raise HTTPException(status_code=404, detail="CVE non trouvée")
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/findings", response_model=List[Finding])
async def get_findings(
    asset_id: Optional[int] = Query(None, description="Filtrer par actif"),
    risk_level: Optional[str] = Query(None, description="Filtrer par niveau de risque"),
    status: Optional[str] = Query("active", description="Filtrer par statut"),
    limit: int = Query(100, ge=1, le=1000)
):
    """Récupère la liste des findings (corrélations)"""
    try:
        query = """
            SELECT id, asset_id, software_id, cve_id, risk_level, cvss_at_detection, status
            FROM findings
            WHERE ($1::int IS NULL OR asset_id = $1)
            AND ($2::text IS NULL OR risk_level = $2)
            AND ($3::text IS NULL OR status = $3)
            ORDER BY detected_at DESC
            LIMIT $4
        """
        rows = await execute_query(query, asset_id, risk_level, status, limit)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/correlation/run", response_model=CorrelationResult)
async def run_correlation():
    """Exécute la corrélation manuellement"""
    try:
        # Appeler la fonction PostgreSQL
        query = "SELECT * FROM run_correlation()"
        row = await execute_query_row(query)
        
        result = CorrelationResult(
            new_findings=row['new_findings'],
            updated_findings=row['updated_findings'],
            process_findings=row['process_findings']
        )
        
        logger.info(f"✅ Corrélation exécutée: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Erreur lors de la corrélation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Récupère les statistiques pour le dashboard"""
    try:
        query = "SELECT * FROM dashboard_stats"
        row = await execute_query_row(query)
        return dict(row)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/top-assets")
async def get_top_assets():
    """Récupère le top des machines exposées"""
    try:
        query = "SELECT * FROM top_exposed_assets"
        rows = await execute_query(query)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du top assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/risk-distribution")
async def get_risk_distribution():
    """Récupère la distribution des risques"""
    try:
        query = "SELECT * FROM risk_distribution"
        rows = await execute_query(query)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/top-vulnerable-software")
async def get_top_vulnerable_software():
    """Récupère le top des logiciels vulnérables"""
    try:
        query = "SELECT * FROM top_vulnerable_software"
        rows = await execute_query(query)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du top logiciels: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/risk-evolution")
async def get_risk_evolution():
    """Récupère l'évolution des risques sur 30 jours"""
    try:
        query = "SELECT * FROM risk_evolution"
        rows = await execute_query(query)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'évolution: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/kev-findings")
async def get_kev_findings():
    """Récupère les KEV actives"""
    try:
        query = "SELECT * FROM active_kev_findings"
        rows = await execute_query(query)
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des KEV: {e}")
        raise HTTPException(status_code=500, detail=str(e))
