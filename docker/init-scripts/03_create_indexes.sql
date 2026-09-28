-- 03-create-indexes.sql
-- Index pour les performances

-- Assets
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip_address ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);

-- Software
CREATE INDEX IF NOT EXISTS idx_software_asset_id ON software(asset_id);
CREATE INDEX IF NOT EXISTS idx_software_name ON software(name);
CREATE INDEX IF NOT EXISTS idx_software_version ON software(version);
CREATE INDEX IF NOT EXISTS idx_software_last_seen ON software(last_seen);

-- CVEs
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);
CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev);

-- Findings
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_software_id ON findings(software_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk_level ON findings(risk_level);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at);

-- Processes
CREATE INDEX IF NOT EXISTS idx_processes_asset_id ON processes(asset_id);
CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);

-- Ports
CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON ports(asset_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_ports_protocol ON ports(protocol);

-- Users
CREATE INDEX IF NOT EXISTS idx_users_asset_id ON users(asset_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Scan History
CREATE INDEX IF NOT EXISTS idx_scan_history_type ON scan_history(scan_type);
CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_started_at ON scan_history(started_at);
