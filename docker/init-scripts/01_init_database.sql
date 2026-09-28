-- 01_init_database.sql
-- Extensions PostgreSQL (la DB est créée par POSTGRES_DB au démarrage du conteneur)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
