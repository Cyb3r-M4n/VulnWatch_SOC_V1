-- 02-create-tables.sql
-- Création des tables principales

-- Table : assets (machines)
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    architecture VARCHAR(20),
    status VARCHAR(20) DEFAULT 'active',
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(hostname)
);

-- Table : software (logiciels installés)
CREATE TABLE IF NOT EXISTS software (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    vendor VARCHAR(100),
    install_date DATE,
    install_path TEXT,
    package_manager VARCHAR(50),
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(asset_id, name, version)
);

-- Table : cves (vulnérabilités)
CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    product VARCHAR(255),
    vendor VARCHAR(100),
    affected_versions TEXT[],
    cvss_score DECIMAL(3,1),
    severity VARCHAR(20),
    description TEXT,
    published_date DATE,
    modified_date DATE,
    kev BOOLEAN DEFAULT FALSE,
    reference_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table : findings (corrélations détectées)
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    software_id INTEGER REFERENCES software(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
    risk_level VARCHAR(20) NOT NULL,
    cvss_at_detection DECIMAL(3,1),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    notes TEXT,
    UNIQUE(asset_id, software_id, cve_id)
);

-- Table : processes (processus en cours)
CREATE TABLE IF NOT EXISTS processes (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    path TEXT,
    cmdline TEXT,
    status VARCHAR(20),
    uid INTEGER,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    UNIQUE(asset_id, pid)
);

-- Table : ports (ports ouverts)
CREATE TABLE IF NOT EXISTS ports (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    process_name VARCHAR(255),
    process_id INTEGER,
    address VARCHAR(50),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    UNIQUE(asset_id, port, protocol)
);

-- Table : users (utilisateurs)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,
    uid INTEGER,
    gid INTEGER,
    shell VARCHAR(255),
    home_directory TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    UNIQUE(asset_id, username)
);

-- Table : scan_history (historique des scans)
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(50),
    status VARCHAR(20),
    records_processed INTEGER,
    records_added INTEGER,
    records_updated INTEGER,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    error_message TEXT
);

-- Table : reports (rapports PDF générés)
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    report_name VARCHAR(255) NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(100),
    asset_count INTEGER,
    finding_count INTEGER,
    critical INTEGER,
    high INTEGER,
    medium INTEGER,
    low INTEGER,
    file_path TEXT
);

-- Table : workflow_logs (pour n8n)
CREATE TABLE IF NOT EXISTS workflow_logs (
    id SERIAL PRIMARY KEY,
    workflow_name VARCHAR(255),
    status VARCHAR(20),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    duration INTEGER,
    message TEXT
);
