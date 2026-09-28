# engine/src/api/routes.py
"""Routes API VulnWatch Engine — detect / propose / validate (jamais d'apply)."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from loguru import logger
from pydantic import BaseModel, Field

from ..database.connection import execute_command, execute_query, execute_query_row

router = APIRouter()


# ============================================
# Modèles
# ============================================

class Asset(BaseModel):
    id: Optional[int] = None
    hostname: str
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: str = "active"
    last_seen: Optional[datetime] = None


class Software(BaseModel):
    id: Optional[int] = None
    asset_id: int
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None


class CVE(BaseModel):
    id: Optional[int] = None
    cve_id: str
    product: Optional[str] = None
    vendor: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    kev: bool = False


class Finding(BaseModel):
    id: Optional[int] = None
    asset_id: int
    software_id: Optional[int] = None
    cve_id: int
    risk_level: str
    cvss_at_detection: Optional[float] = None
    status: str = "active"


class CorrelationResult(BaseModel):
    new_findings: int
    updated_findings: int
    process_findings: int
    new_proposals: int = 0


class ValidationRequest(BaseModel):
    validated_by: str = Field(..., min_length=1, description="Identifiant ingénieur cybersec")
    notes: Optional[str] = None


class MitigateRequest(BaseModel):
    mitigated_by: str = Field(..., min_length=1)
    notes: Optional[str] = None


# ============================================
# Assets / CVE / Findings
# ============================================

@router.get("/assets", response_model=List[Asset])
async def get_assets(
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        rows = await execute_query(
            """
            SELECT id, hostname, ip_address::text AS ip_address, os_name, os_version, status, last_seen
            FROM assets
            WHERE ($1::text IS NULL OR status = $1)
            ORDER BY hostname
            LIMIT $2
            """,
            status,
            limit,
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: int):
    try:
        row = await execute_query_row(
            """
            SELECT id, hostname, ip_address::text AS ip_address, os_name, os_version, status, last_seen
            FROM assets WHERE id = $1
            """,
            asset_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Asset non trouvé")
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets/{asset_id}/software", response_model=List[Software])
async def get_asset_software(asset_id: int):
    try:
        rows = await execute_query(
            """
            SELECT id, asset_id, name, version, vendor
            FROM software WHERE asset_id = $1 ORDER BY name
            """,
            asset_id,
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur software: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cves", response_model=List[CVE])
async def get_cves(
    severity: Optional[str] = Query(None),
    kev: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        rows = await execute_query(
            """
            SELECT id, cve_id, product, vendor, cvss_score, severity, description, kev
            FROM cves
            WHERE ($1::text IS NULL OR severity = $1)
              AND ($2::boolean IS NULL OR kev = $2)
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT $3
            """,
            severity,
            kev,
            limit,
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur cves: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings")
async def get_findings(
    asset_id: Optional[int] = Query(None),
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query("active"),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        rows = await execute_query(
            """
            SELECT f.id, f.asset_id, f.software_id, f.cve_id, f.risk_level,
                   f.cvss_at_detection, f.status, f.detected_at,
                   a.hostname, c.cve_id AS cve_name, c.kev, s.name AS software_name, s.version AS software_version
            FROM findings f
            JOIN assets a ON f.asset_id = a.id
            JOIN cves c ON f.cve_id = c.id
            LEFT JOIN software s ON f.software_id = s.id
            WHERE ($1::int IS NULL OR f.asset_id = $1)
              AND ($2::text IS NULL OR f.risk_level = $2)
              AND ($3::text IS NULL OR f.status = $3)
            ORDER BY f.detected_at DESC
            LIMIT $4
            """,
            asset_id,
            risk_level,
            status,
            limit,
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/findings/{finding_id}/mitigated")
async def mark_finding_mitigated(finding_id: int, body: MitigateRequest):
    """Marquage manuel après remediation réelle hors plateforme (pas d'auto-patch)."""
    try:
        row = await execute_query_row(
            "SELECT id, status FROM findings WHERE id = $1", finding_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Finding non trouvé")
        notes = f"Mitigé manuellement par {body.mitigated_by}"
        if body.notes:
            notes = f"{notes}: {body.notes}"
        await execute_command(
            """
            UPDATE findings
            SET status = 'mitigated', notes = COALESCE(notes || ' | ', '') || $2
            WHERE id = $1
            """,
            finding_id,
            notes,
        )
        return {"id": finding_id, "status": "mitigated", "mitigated_by": body.mitigated_by}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur mitigate: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Corrélation + propositions
# ============================================

@router.post("/correlation/run", response_model=CorrelationResult)
async def run_correlation():
    """Corrélation + génération de propositions de correctifs (sans application)."""
    try:
        row = await execute_query_row("SELECT * FROM run_correlation_and_propose()")
        result = CorrelationResult(
            new_findings=row["new_findings"],
            updated_findings=row["updated_findings"],
            process_findings=row["process_findings"],
            new_proposals=row["new_proposals"],
        )
        logger.info(f"Corrélation exécutée: {result}")
        return result
    except Exception as e:
        logger.error(f"Erreur corrélation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Remediations — validation cybersec
# ============================================

@router.get("/remediations")
async def list_remediations(
    status: Optional[str] = Query(
        "pending_validation",
        description="pending_validation | approved | rejected | all",
    ),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        status_filter = None if status == "all" else status
        rows = await execute_query(
            """
            SELECT
                r.id AS remediation_id,
                r.status AS remediation_status,
                r.proposed_action,
                r.recommended_version,
                r.references_text,
                r.proposed_at,
                r.validated_by,
                r.validated_at,
                r.validation_notes,
                f.id AS finding_id,
                f.risk_level,
                f.status AS finding_status,
                a.hostname,
                a.ip_address::text AS ip_address,
                s.name AS software_name,
                s.version AS software_version,
                c.cve_id,
                c.kev,
                c.cvss_score,
                c.severity
            FROM remediations r
            JOIN findings f ON r.finding_id = f.id
            JOIN assets a ON r.asset_id = a.id
            JOIN cves c ON r.cve_id = c.id
            LEFT JOIN software s ON f.software_id = s.id
            WHERE ($1::text IS NULL OR r.status = $1)
            ORDER BY
                CASE f.risk_level
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                r.proposed_at ASC
            LIMIT $2
            """,
            status_filter,
            limit,
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur remediations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediations/queue")
async def remediation_queue(limit: int = Query(100, ge=1, le=1000)):
    try:
        rows = await execute_query(
            "SELECT * FROM remediation_queue LIMIT $1", limit
        )
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Erreur queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _set_remediation_status(remediation_id: int, status: str, body: ValidationRequest):
    row = await execute_query_row(
        "SELECT id, status FROM remediations WHERE id = $1", remediation_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Remediation non trouvée")
    if row["status"] not in ("proposed", "pending_validation"):
        raise HTTPException(
            status_code=409,
            detail=f"Remediation déjà traitée (status={row['status']})",
        )
    await execute_command(
        """
        UPDATE remediations
        SET status = $2,
            validated_by = $3,
            validated_at = CURRENT_TIMESTAMP,
            validation_notes = $4
        WHERE id = $1
        """,
        remediation_id,
        status,
        body.validated_by,
        body.notes,
    )
    return {
        "id": remediation_id,
        "status": status,
        "validated_by": body.validated_by,
        "message": (
            "Correctif validé — appliquer manuellement hors plateforme, "
            "puis marquer le finding mitigé."
            if status == "approved"
            else "Proposition rejetée — aucune action automatique."
        ),
    }


@router.post("/remediations/{remediation_id}/approve")
async def approve_remediation(remediation_id: int, body: ValidationRequest):
    """Validation cybersec : OK pour remediation manuelle. N'applique aucun patch."""
    try:
        return await _set_remediation_status(remediation_id, "approved", body)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur approve: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediations/{remediation_id}/reject")
async def reject_remediation(remediation_id: int, body: ValidationRequest):
    """Rejet cybersec de la proposition — aucune application."""
    try:
        return await _set_remediation_status(remediation_id, "rejected", body)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur reject: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Dashboard
# ============================================

@router.get("/dashboard/stats")
async def get_dashboard_stats():
    try:
        row = await execute_query_row("SELECT * FROM dashboard_stats")
        return dict(row) if row else {}
    except Exception as e:
        logger.error(f"Erreur stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/top-assets")
async def get_top_assets():
    try:
        rows = await execute_query("SELECT * FROM top_exposed_assets")
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/risk-distribution")
async def get_risk_distribution():
    try:
        rows = await execute_query("SELECT * FROM risk_distribution")
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/top-vulnerable-software")
async def get_top_vulnerable_software():
    try:
        rows = await execute_query("SELECT * FROM top_vulnerable_software")
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/risk-evolution")
async def get_risk_evolution():
    try:
        rows = await execute_query("SELECT * FROM risk_evolution")
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/kev-findings")
async def get_kev_findings():
    try:
        rows = await execute_query("SELECT * FROM active_kev_findings")
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/remediation-stats")
async def get_remediation_stats():
    try:
        row = await execute_query_row("SELECT * FROM remediation_stats")
        return dict(row) if row else {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
