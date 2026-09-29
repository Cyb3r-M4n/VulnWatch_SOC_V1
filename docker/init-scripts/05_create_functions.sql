-- 05-create-functions.sql
-- Fonctions de corrélation et utilitaires

-- Fonction de corrélation principale
CREATE OR REPLACE FUNCTION run_correlation()
RETURNS TABLE(
    new_findings INTEGER,
    updated_findings INTEGER,
    process_findings INTEGER
) AS $$
DECLARE
    v_new INTEGER := 0;
    v_updated INTEGER := 0;
    v_process INTEGER := 0;
BEGIN
    -- 1. Nettoyer les findings obsolètes
    -- Findings logiciels : software absent / trop vieux
    -- Findings process (software_id NULL) : plus de process RUNNING correspondant
    UPDATE findings
    SET status = 'mitigated'
    WHERE status = 'active'
    AND (
        NOT EXISTS (
            SELECT 1 FROM assets a
            WHERE a.id = findings.asset_id
            AND a.status = 'active'
        )
        OR (
            findings.software_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM software s
                WHERE s.id = findings.software_id
                AND s.last_seen > NOW() - INTERVAL '2 days'
            )
        )
        OR (
            findings.software_id IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM processes p
                WHERE p.asset_id = findings.asset_id
                AND p.status = 'RUNNING'
                AND p.last_seen > NOW() - INTERVAL '2 days'
                AND findings.notes = 'Process: ' || p.name
            )
        )
    );
    
    -- 2. Corrélation sur les logiciels installés
    DROP TABLE IF EXISTS tmp_new_correlations;
    CREATE TEMP TABLE tmp_new_correlations ON COMMIT DROP AS
        SELECT DISTINCT
            a.id AS asset_id,
            s.id AS software_id,
            c.id AS cve_id,
            CASE 
                WHEN c.kev = true THEN 'CRITICAL'
                WHEN c.cvss_score >= 9.0 THEN 'CRITICAL'
                WHEN c.cvss_score >= 7.0 THEN 'HIGH'
                WHEN c.cvss_score >= 4.0 THEN 'MEDIUM'
                ELSE 'LOW'
            END AS risk_level,
            c.cvss_score AS cvss_at_detection
        FROM assets a
        JOIN software s ON a.id = s.asset_id
        JOIN cves c ON (
            c.product IS NOT NULL
            AND (
                s.name ILIKE c.product
                OR s.name ILIKE '%' || c.product || '%'
                OR c.product ILIKE '%' || s.name || '%'
            )
            AND (
                c.affected_versions IS NULL
                OR cardinality(c.affected_versions) = 0
                OR s.version = ANY(c.affected_versions)
                OR EXISTS (
                    SELECT 1 FROM unnest(c.affected_versions) AS v(ver)
                    WHERE v.ver = s.version
                       OR s.version LIKE v.ver || '.%'
                       OR v.ver LIKE s.version || '%'
                )
            )
        )
        WHERE a.status = 'active'
        AND s.last_seen > NOW() - INTERVAL '2 days';

    INSERT INTO findings (asset_id, software_id, cve_id, risk_level, cvss_at_detection)
    SELECT 
        nc.asset_id, 
        nc.software_id, 
        nc.cve_id, 
        nc.risk_level, 
        nc.cvss_at_detection
    FROM tmp_new_correlations nc
    WHERE NOT EXISTS (
        SELECT 1 FROM findings f
        WHERE f.asset_id = nc.asset_id
        AND f.software_id = nc.software_id
        AND f.cve_id = nc.cve_id
    );

    GET DIAGNOSTICS v_new = ROW_COUNT;

    UPDATE findings f
    SET status = 'active',
        risk_level = nc.risk_level,
        cvss_at_detection = nc.cvss_at_detection
    FROM tmp_new_correlations nc
    WHERE f.asset_id = nc.asset_id
      AND f.software_id = nc.software_id
      AND f.cve_id = nc.cve_id
      AND f.status <> 'active';
    
    -- 3. Mettre à jour les niveaux de risque existants
    UPDATE findings f
    SET 
        risk_level = CASE 
            WHEN c.kev = true THEN 'CRITICAL'
            WHEN c.cvss_score >= 9.0 THEN 'CRITICAL'
            WHEN c.cvss_score >= 7.0 THEN 'HIGH'
            WHEN c.cvss_score >= 4.0 THEN 'MEDIUM'
            ELSE 'LOW'
        END,
        cvss_at_detection = c.cvss_score
    FROM cves c
    WHERE f.cve_id = c.id
    AND f.status = 'active'
    AND f.risk_level != CASE 
        WHEN c.kev = true THEN 'CRITICAL'
        WHEN c.cvss_score >= 9.0 THEN 'CRITICAL'
        WHEN c.cvss_score >= 7.0 THEN 'HIGH'
        WHEN c.cvss_score >= 4.0 THEN 'MEDIUM'
        ELSE 'LOW'
    END;
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    -- 4. Corrélation sur les processus en cours
    WITH process_correlations AS (
        SELECT DISTINCT
            a.id AS asset_id,
            p.id AS process_id,
            c.id AS cve_id,
            CASE 
                WHEN c.kev = true THEN 'CRITICAL'
                WHEN c.cvss_score >= 9.0 THEN 'CRITICAL'
                WHEN c.cvss_score >= 7.0 THEN 'HIGH'
                WHEN c.cvss_score >= 4.0 THEN 'MEDIUM'
                ELSE 'LOW'
            END AS risk_level,
            c.cvss_score AS cvss_at_detection,
            'Process: ' || p.name AS notes
        FROM assets a
        JOIN processes p ON a.id = p.asset_id
        JOIN cves c ON (
            c.product IS NOT NULL
            AND length(trim(c.product)) > 1
            AND p.name ILIKE '%' || c.product || '%'
        )
        WHERE a.status = 'active'
        AND p.status = 'RUNNING'
    )
    INSERT INTO findings (asset_id, cve_id, risk_level, cvss_at_detection, notes)
    SELECT 
        pc.asset_id, 
        pc.cve_id, 
        pc.risk_level, 
        pc.cvss_at_detection,
        pc.notes
    FROM process_correlations pc
    WHERE NOT EXISTS (
        SELECT 1 FROM findings f 
        WHERE f.asset_id = pc.asset_id 
        AND f.cve_id = pc.cve_id
        AND f.notes = pc.notes
        AND f.status = 'active'
    );
    
    GET DIAGNOSTICS v_process = ROW_COUNT;
    
    -- 5. Journaliser l'opération
    INSERT INTO scan_history (scan_type, status, records_processed, records_added, records_updated, finished_at)
    VALUES ('correlation', 'success', v_new + v_updated + v_process, v_new + v_process, v_updated, CURRENT_TIMESTAMP);
    
    RETURN QUERY SELECT v_new, v_updated, v_process;
END;
$$ LANGUAGE plpgsql;

-- Fonction de nettoyage des données obsolètes
CREATE OR REPLACE FUNCTION cleanup_old_data(days_to_keep INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    v_deleted INTEGER := 0;
BEGIN
    -- Supprimer les findings résolus vieux de plus de X jours
    WITH deleted AS (
        DELETE FROM findings
        WHERE status = 'mitigated'
        AND detected_at < NOW() - (days_to_keep || ' days')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO v_deleted FROM deleted;
    
    -- Supprimer l'historique des scans vieux de plus de X jours
    DELETE FROM scan_history
    WHERE started_at < NOW() - (days_to_keep || ' days')::INTERVAL;
    
    -- Supprimer les rapports vieux de plus de X jours
    DELETE FROM reports
    WHERE generated_at < NOW() - (days_to_keep || ' days')::INTERVAL;
    
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- Fonction de récupération des dernières nouvelles CVE
CREATE OR REPLACE FUNCTION get_recent_cves(days INTEGER DEFAULT 1)
RETURNS TABLE(
    cve_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    severity VARCHAR(20),
    product VARCHAR(255)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.cve_id,
        c.cvss_score,
        c.severity,
        c.product
    FROM cves c
    WHERE c.published_date > NOW() - (days || ' days')::INTERVAL
    ORDER BY c.cvss_score DESC;
END;
$$ LANGUAGE plpgsql;

-- Fonction de résumé des risques par machine
CREATE OR REPLACE FUNCTION get_asset_risk_summary(asset_hostname VARCHAR)
RETURNS TABLE(
    hostname VARCHAR(255),
    total_findings INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    highest_risk VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.hostname,
        COUNT(f.id)::INTEGER AS total_findings,
        COUNT(CASE WHEN f.risk_level = 'CRITICAL' THEN 1 END)::INTEGER AS critical_count,
        COUNT(CASE WHEN f.risk_level = 'HIGH' THEN 1 END)::INTEGER AS high_count,
        COUNT(CASE WHEN f.risk_level = 'MEDIUM' THEN 1 END)::INTEGER AS medium_count,
        COUNT(CASE WHEN f.risk_level = 'LOW' THEN 1 END)::INTEGER AS low_count,
        CASE MAX(
            CASE f.risk_level
                WHEN 'CRITICAL' THEN 4
                WHEN 'HIGH' THEN 3
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 1
                ELSE 0
            END
        )
            WHEN 4 THEN 'CRITICAL'
            WHEN 3 THEN 'HIGH'
            WHEN 2 THEN 'MEDIUM'
            WHEN 1 THEN 'LOW'
            ELSE NULL
        END AS highest_risk
    FROM assets a
    LEFT JOIN findings f ON a.id = f.asset_id AND f.status = 'active'
    WHERE a.hostname = asset_hostname
    GROUP BY a.id, a.hostname;
END;
$$ LANGUAGE plpgsql;
