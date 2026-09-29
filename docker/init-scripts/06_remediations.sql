-- 06_remediations.sql
-- Propositions de correctifs (jamais appliqués automatiquement)
-- Validation obligatoire par ingénieur cybersec avant remediation manuelle

CREATE TABLE IF NOT EXISTS remediations (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    proposed_action TEXT NOT NULL,
    recommended_version VARCHAR(100),
    references_text TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'pending_validation'
        CHECK (status IN ('proposed', 'pending_validation', 'approved', 'rejected')),
    proposed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    validated_by VARCHAR(100),
    validated_at TIMESTAMP,
    validation_notes TEXT,
    UNIQUE(finding_id)
);

CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status);
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_remediations_proposed_at ON remediations(proposed_at DESC);

-- File d'attente cybersec
CREATE OR REPLACE VIEW remediation_queue AS
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
    f.cvss_at_detection,
    f.status AS finding_status,
    f.detected_at,
    a.hostname,
    a.ip_address,
    a.os_name,
    s.name AS software_name,
    s.version AS software_version,
    c.cve_id,
    c.kev,
    c.cvss_score,
    c.severity,
    c.description AS cve_description,
    c.reference_url
FROM remediations r
JOIN findings f ON r.finding_id = f.id
JOIN assets a ON r.asset_id = a.id
JOIN cves c ON r.cve_id = c.id
LEFT JOIN software s ON f.software_id = s.id
WHERE r.status = 'pending_validation'
ORDER BY
    CASE f.risk_level
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    r.proposed_at ASC;

-- Correctifs validés en attente de remediation manuelle
CREATE OR REPLACE VIEW approved_awaiting_manual_fix AS
SELECT
    r.id AS remediation_id,
    r.proposed_action,
    r.recommended_version,
    r.validated_by,
    r.validated_at,
    r.validation_notes,
    f.id AS finding_id,
    f.risk_level,
    a.hostname,
    s.name AS software_name,
    s.version AS software_version,
    c.cve_id,
    c.kev
FROM remediations r
JOIN findings f ON r.finding_id = f.id
JOIN assets a ON r.asset_id = a.id
JOIN cves c ON r.cve_id = c.id
LEFT JOIN software s ON f.software_id = s.id
WHERE r.status = 'approved'
  AND f.status = 'active'
ORDER BY r.validated_at DESC;

-- Stats remediation pour dashboard
CREATE OR REPLACE VIEW remediation_stats AS
SELECT
    (SELECT COUNT(*) FROM remediations WHERE status = 'pending_validation') AS pending_validation,
    (SELECT COUNT(*) FROM remediations WHERE status = 'approved') AS approved,
    (SELECT COUNT(*) FROM remediations WHERE status = 'rejected') AS rejected,
    (SELECT COUNT(*) FROM remediations WHERE status IN ('proposed', 'pending_validation', 'approved', 'rejected')) AS total,
    (SELECT COUNT(*) FROM approved_awaiting_manual_fix) AS awaiting_manual_fix;

-- Enrichir dashboard_stats avec la file de validation + dernier scan n8n
DROP VIEW IF EXISTS dashboard_stats;
CREATE VIEW dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM assets WHERE status = 'active') AS total_assets,
    (SELECT COUNT(*) FROM assets) AS total_assets_all,
    (SELECT COUNT(*) FROM software) AS total_software,
    (SELECT COUNT(*) FROM cves) AS total_cves,
    (SELECT COUNT(*) FROM processes WHERE status = 'RUNNING') AS total_processes,
    (SELECT COUNT(*) FROM ports) AS total_ports,
    (SELECT COUNT(*) FROM findings WHERE risk_level = 'CRITICAL' AND status = 'active') AS critical_findings,
    (SELECT COUNT(*) FROM findings WHERE risk_level = 'HIGH' AND status = 'active') AS high_findings,
    (SELECT COUNT(*) FROM findings WHERE risk_level = 'MEDIUM' AND status = 'active') AS medium_findings,
    (SELECT COUNT(*) FROM findings WHERE risk_level = 'LOW' AND status = 'active') AS low_findings,
    (SELECT COUNT(*) FROM findings WHERE status = 'active') AS total_findings,
    (SELECT COUNT(*) FROM cves WHERE kev = true) AS kev_count,
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND cve_id IN (SELECT id FROM cves WHERE kev = true)) AS kev_findings,
    (SELECT COUNT(*) FROM remediations WHERE status = 'pending_validation') AS pending_validations,
    (SELECT COUNT(*) FROM approved_awaiting_manual_fix) AS awaiting_manual_fix,
    (SELECT status FROM scan_history WHERE scan_type = 'daily_scan' ORDER BY started_at DESC LIMIT 1) AS last_daily_scan_status,
    (SELECT finished_at FROM scan_history WHERE scan_type = 'daily_scan' ORDER BY started_at DESC LIMIT 1) AS last_daily_scan_at;

-- Génère des propositions de correctifs pour les findings actifs sans remediation
-- IMPORTANT : ne fait AUCUNE application de patch
CREATE OR REPLACE FUNCTION propose_remediations()
RETURNS TABLE(new_proposals INTEGER) AS $$
DECLARE
    v_new INTEGER := 0;
BEGIN
    INSERT INTO remediations (
        finding_id,
        asset_id,
        cve_id,
        proposed_action,
        recommended_version,
        references_text,
        status
    )
    SELECT
        f.id,
        f.asset_id,
        f.cve_id,
        CASE
            WHEN c.kev THEN
                'PRIORITÉ KEV — Contenir / patcher dès validation cybersec. '
                || 'Mettre à jour ' || COALESCE(s.name, c.product, 'le composant')
                || COALESCE(' (version actuelle: ' || s.version || ')', '')
                || ' vers une version non affectée. Vérifier le bulletin vendor et les refs NVD.'
            ELSE
                'Proposer la mise à jour de ' || COALESCE(s.name, c.product, 'le composant')
                || COALESCE(' (version actuelle: ' || s.version || ')', '')
                || ' vers une version corrigée selon le vendor. '
                || 'Ne pas appliquer automatiquement — validation ingénieur cybersec requise.'
        END,
        CASE
            WHEN c.affected_versions IS NOT NULL AND cardinality(c.affected_versions) > 0
            THEN 'Éviter: ' || array_to_string(c.affected_versions, ', ')
            ELSE NULL
        END,
        COALESCE(c.reference_url, 'https://nvd.nist.gov/vuln/detail/' || c.cve_id),
        'pending_validation'
    FROM findings f
    JOIN cves c ON f.cve_id = c.id
    LEFT JOIN software s ON f.software_id = s.id
    WHERE f.status = 'active'
      AND NOT EXISTS (
          SELECT 1 FROM remediations r WHERE r.finding_id = f.id
      );

    GET DIAGNOSTICS v_new = ROW_COUNT;

    INSERT INTO scan_history (scan_type, status, records_processed, records_added, finished_at)
    VALUES ('propose_remediations', 'success', v_new, v_new, CURRENT_TIMESTAMP);

    RETURN QUERY SELECT v_new;
END;
$$ LANGUAGE plpgsql;

-- Enchaîne corrélation + propositions (utilisé par n8n / engine)
CREATE OR REPLACE FUNCTION run_correlation_and_propose()
RETURNS TABLE(
    new_findings INTEGER,
    updated_findings INTEGER,
    process_findings INTEGER,
    new_proposals INTEGER
) AS $$
DECLARE
    v_corr RECORD;
    v_prop INTEGER := 0;
BEGIN
    SELECT * INTO v_corr FROM run_correlation();
    SELECT p.new_proposals INTO v_prop FROM propose_remediations() p;
    RETURN QUERY SELECT v_corr.new_findings, v_corr.updated_findings, v_corr.process_findings, v_prop;
END;
$$ LANGUAGE plpgsql;
