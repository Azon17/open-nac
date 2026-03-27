-- ============================================================================
-- Open NAC — Create MariaDB monitoring user for mysqld_exporter
-- Run on ONE Galera node (will replicate automatically):
--   docker exec -i opennac-mariadb-node1 mysql -uroot -p'MyStr0ng!' < db_exporter_user.sql
-- ============================================================================

CREATE USER IF NOT EXISTS 'exporter'@'%' IDENTIFIED BY 'MyStr0ng!' WITH MAX_USER_CONNECTIONS 3;

GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';

-- Galera-specific grants
GRANT SELECT ON performance_schema.* TO 'exporter'@'%';

FLUSH PRIVILEGES;
