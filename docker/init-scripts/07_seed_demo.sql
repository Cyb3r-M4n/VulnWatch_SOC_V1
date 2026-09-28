-- 07_seed_demo.sql
-- Inventaire démo uniquement (pas de CVE fictives — les CVE viennent de NVD/KEV)

INSERT INTO assets (hostname, ip_address, os_name, os_version, architecture, status, last_seen)
VALUES
    ('srv-web-01', '10.0.10.11', 'Ubuntu', '22.04', 'x86_64', 'active', NOW()),
    ('srv-db-01', '10.0.10.21', 'Ubuntu', '22.04', 'x86_64', 'active', NOW()),
    ('srv-app-01', '10.0.10.31', 'Debian', '12', 'x86_64', 'active', NOW())
ON CONFLICT (hostname) DO UPDATE
SET last_seen = NOW(), status = 'active', updated_at = NOW();

INSERT INTO software (asset_id, name, version, vendor, package_manager, last_seen)
SELECT a.id, s.name, s.version, s.vendor, s.pm, NOW()
FROM assets a
CROSS JOIN (VALUES
    ('openssl', '3.0.2', 'OpenSSL', 'apt'),
    ('nginx', '1.18.0', 'Nginx', 'apt'),
    ('curl', '7.81.0', 'curl', 'apt'),
    ('python3', '3.10.12', 'Python', 'apt')
) AS s(name, version, vendor, pm)
WHERE a.hostname = 'srv-web-01'
ON CONFLICT (asset_id, name, version) DO UPDATE SET last_seen = NOW();

INSERT INTO software (asset_id, name, version, vendor, package_manager, last_seen)
SELECT a.id, s.name, s.version, s.vendor, s.pm, NOW()
FROM assets a
CROSS JOIN (VALUES
    ('postgresql', '15.3', 'PostgreSQL', 'apt'),
    ('openssl', '3.0.2', 'OpenSSL', 'apt'),
    ('openssh', '8.9p1', 'OpenBSD', 'apt')
) AS s(name, version, vendor, pm)
WHERE a.hostname = 'srv-db-01'
ON CONFLICT (asset_id, name, version) DO UPDATE SET last_seen = NOW();

INSERT INTO software (asset_id, name, version, vendor, package_manager, last_seen)
SELECT a.id, s.name, s.version, s.vendor, s.pm, NOW()
FROM assets a
CROSS JOIN (VALUES
    ('nodejs', '18.17.0', 'Node.js', 'apt'),
    ('openssl', '3.0.2', 'OpenSSL', 'apt'),
    ('git', '2.39.2', 'Git', 'apt')
) AS s(name, version, vendor, pm)
WHERE a.hostname = 'srv-app-01'
ON CONFLICT (asset_id, name, version) DO UPDATE SET last_seen = NOW();
