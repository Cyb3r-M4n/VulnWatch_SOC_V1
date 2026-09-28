-- 04-create-views.sql
-- Vues pour Grafana et rapports

-- Vue 1 : Statistiques globales
CREATE OR REPLACE VIEW dashboard_stats AS
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
    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND cve_id IN (SELECT id FROM cves WHERE kev = true)) AS kev_findings;

-- Vue 2 : Top machines exposées
CREATE OR REPLACE VIEW top_exposed_assets AS
SELECT 
    a.hostname,
    a.ip_address,
    a.os_name,
    COUNT(f.id) AS finding_count,
    COUNT(CASE WHEN f.risk_level = 'CRITICAL' THEN 1 END) AS critical_count,
    COUNT(CASE WHEN f.risk_level = 'HIGH' THEN 1 END) AS high_count,
    COUNT(CASE WHEN f.risk_level = 'MEDIUM' THEN 1 END) AS medium_count,
    COUNT(CASE WHEN f.risk_level = 'LOW' THEN 1 END) AS low_count,
    MAX(f.risk_level) AS highest_risk,
    COUNT(DISTINCT p.id) AS process_count,
    COUNT(DISTINCT pt.id) AS open_ports
FROM assets a
LEFT JOIN findings f ON a.id = f.asset_id AND f.status = 'active'
LEFT JOIN processes p ON a.id = p.asset_id AND p.status = 'RUNNING'
LEFT JOIN ports pt ON a.id = pt.asset_id
WHERE a.status = 'active'
GROUP BY a.id, a.hostname, a.ip_address, a.os_name
ORDER BY finding_count DESC
LIMIT 10;

-- Vue 3 : Top logiciels vulnérables
CREATE OR REPLACE VIEW top_vulnerable_software AS
SELECT 
    s.name,
    s.version,
    s.vendor,
    COUNT(DISTINCT f.asset_id) AS affected_assets,
    COUNT(f.id) AS finding_count,
    COUNT(CASE WHEN f.risk_level = 'CRITICAL' THEN 1 END) AS critical_count,
    COUNT(CASE WHEN f.risk_level = 'HIGH' THEN 1 END) AS high_count,
    MAX(c.cvss_score) AS max_cvss,
    MAX(c.cvss_score) >= 9.0 AS has_critical
FROM software s
JOIN findings f ON s.id = f.software_id
JOIN cves c ON f.cve_id = c.id
WHERE f.status = 'active'
GROUP BY s.id, s.name, s.version, s.vendor
ORDER BY finding_count DESC
LIMIT 10;

-- Vue 4 : Distribution des risques
CREATE OR REPLACE VIEW risk_distribution AS
SELECT 
    risk_level,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM findings WHERE status = 'active'), 1) AS percentage
FROM findings
WHERE status = 'active'
GROUP BY risk_level
ORDER BY 
    CASE risk_level
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END;

-- Vue 5 : Évolution des risques (30 jours)
CREATE OR REPLACE VIEW risk_evolution AS
SELECT 
    DATE(detected_at) AS day,
    risk_level,
    COUNT(*) AS count
FROM findings
WHERE detected_at > NOW() - INTERVAL '30 days'
AND status = 'active'
GROUP BY DATE(detected_at), risk_level
ORDER BY day DESC, risk_level;

-- Vue 6 : Détail complet des machines
CREATE OR REPLACE VIEW asset_details AS
SELECT 
    a.hostname,
    a.ip_address,
    a.os_name,
    a.os_version,
    a.architecture,
    a.last_seen,
    COUNT(DISTINCT s.id) AS software_count,
    COUNT(DISTINCT p.id) AS process_count,
    COUNT(DISTINCT pt.id) AS open_ports,
    COUNT(DISTINCT u.id) AS user_count,
    COUNT(f.id) AS total_findings,
    COUNT(CASE WHEN f.risk_level = 'CRITICAL' THEN 1 END) AS critical_findings,
    COUNT(CASE WHEN f.risk_level = 'HIGH' THEN 1 END) AS high_findings,
    COUNT(CASE WHEN f.risk_level = 'MEDIUM' THEN 1 END) AS medium_findings,
    COUNT(CASE WHEN f.risk_level = 'LOW' THEN 1 END) AS low_findings
FROM assets a
LEFT JOIN software s ON a.id = s.asset_id
LEFT JOIN processes p ON a.id = p.asset_id AND p.status = 'RUNNING'
LEFT JOIN ports pt ON a.id = pt.asset_id
LEFT JOIN users u ON a.id = u.asset_id
LEFT JOIN findings f ON a.id = f.asset_id AND f.status = 'active'
WHERE a.status = 'active'
GROUP BY a.id, a.hostname, a.ip_address, a.os_name, a.os_version, a.architecture, a.last_seen;

-- Vue 7 : KEV actives
CREATE OR REPLACE VIEW active_kev_findings AS
SELECT 
    a.hostname,
    s.name AS software_name,
    s.version AS software_version,
    c.cve_id,
    c.cvss_score,
    c.description,
    f.detected_at,
    f.risk_level
FROM findings f
JOIN assets a ON f.asset_id = a.id
JOIN software s ON f.software_id = s.id
JOIN cves c ON f.cve_id = c.id
WHERE f.status = 'active'
AND c.kev = true
ORDER BY c.cvss_score DESC;

-- Vue 8 : Top processus vulnérables
CREATE OR REPLACE VIEW top_vulnerable_processes AS
SELECT 
    p.name AS process_name,
    COUNT(DISTINCT p.asset_id) AS machines_affected,
    COUNT(f.id) AS finding_count,
    MAX(c.cvss_score) AS max_cvss,
    STRING_AGG(DISTINCT c.cve_id, ', ') AS cves
FROM processes p
JOIN findings f ON p.asset_id = f.asset_id
JOIN cves c ON f.cve_id = c.id
WHERE p.status = 'RUNNING'
AND f.status = 'active'
GROUP BY p.name
ORDER BY finding_count DESC
LIMIT 10;
