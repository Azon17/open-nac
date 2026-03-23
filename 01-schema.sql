-- ==========================================================================
--  Open NAC System — MariaDB Schema Initialization
--  Запускается автоматически при первом старте Galera кластера
-- ==========================================================================

-- ── Стандартная FreeRADIUS SQL-схема ────────────────────────────────────

CREATE DATABASE IF NOT EXISTS `radius`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS `ejbca`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `radius`;

-- Таблица RADIUS-клиентов (NAS)
CREATE TABLE IF NOT EXISTS `nas` (
  `id`          INT(10) NOT NULL AUTO_INCREMENT,
  `nasname`     VARCHAR(128) NOT NULL DEFAULT '',
  `shortname`   VARCHAR(32)  NOT NULL DEFAULT '',
  `type`        VARCHAR(30)  NOT NULL DEFAULT 'other',
  `ports`       INT(5),
  `secret`      VARCHAR(60)  NOT NULL DEFAULT 'secret',
  `server`      VARCHAR(64),
  `community`   VARCHAR(50),
  `description` VARCHAR(200) DEFAULT 'RADIUS Client',
  PRIMARY KEY (`id`),
  KEY `nasname` (`nasname`)
) ENGINE=InnoDB;

-- Таблица пользователей (check-авторы)
CREATE TABLE IF NOT EXISTS `radcheck` (
  `id`        INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`  VARCHAR(64) NOT NULL DEFAULT '',
  `attribute` VARCHAR(64) NOT NULL DEFAULT '',
  `op`        CHAR(2) NOT NULL DEFAULT ':=',
  `value`     VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `username` (`username`(32))
) ENGINE=InnoDB;

-- Таблица ответных атрибутов пользователей
CREATE TABLE IF NOT EXISTS `radreply` (
  `id`        INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`  VARCHAR(64) NOT NULL DEFAULT '',
  `attribute` VARCHAR(64) NOT NULL DEFAULT '',
  `op`        CHAR(2) NOT NULL DEFAULT '=',
  `value`     VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `username` (`username`(32))
) ENGINE=InnoDB;

-- Таблица групп
CREATE TABLE IF NOT EXISTS `radusergroup` (
  `id`        INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`  VARCHAR(64) NOT NULL DEFAULT '',
  `groupname` VARCHAR(64) NOT NULL DEFAULT '',
  `priority`  INT(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `username` (`username`(32))
) ENGINE=InnoDB;

-- Check-атрибуты группы
CREATE TABLE IF NOT EXISTS `radgroupcheck` (
  `id`        INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `groupname` VARCHAR(64) NOT NULL DEFAULT '',
  `attribute` VARCHAR(64) NOT NULL DEFAULT '',
  `op`        CHAR(2) NOT NULL DEFAULT ':=',
  `value`     VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `groupname` (`groupname`(32))
) ENGINE=InnoDB;

-- Reply-атрибуты группы
CREATE TABLE IF NOT EXISTS `radgroupreply` (
  `id`        INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `groupname` VARCHAR(64) NOT NULL DEFAULT '',
  `attribute` VARCHAR(64) NOT NULL DEFAULT '',
  `op`        CHAR(2) NOT NULL DEFAULT '=',
  `value`     VARCHAR(253) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `groupname` (`groupname`(32))
) ENGINE=InnoDB;

-- Accounting (RADIUS)
CREATE TABLE IF NOT EXISTS `radacct` (
  `radacctid`             BIGINT(21) NOT NULL AUTO_INCREMENT,
  `acctsessionid`         VARCHAR(64) NOT NULL DEFAULT '',
  `acctuniqueid`          VARCHAR(32) NOT NULL DEFAULT '',
  `username`              VARCHAR(64) NOT NULL DEFAULT '',
  `realm`                 VARCHAR(64) DEFAULT '',
  `nasipaddress`          VARCHAR(15) NOT NULL DEFAULT '',
  `nasportid`             VARCHAR(32) DEFAULT NULL,
  `nasporttype`           VARCHAR(32) DEFAULT NULL,
  `acctstarttime`         DATETIME DEFAULT NULL,
  `acctupdatetime`        DATETIME DEFAULT NULL,
  `acctstoptime`          DATETIME DEFAULT NULL,
  `acctinterval`          INT(12) DEFAULT NULL,
  `acctsessiontime`       INT(12) UNSIGNED DEFAULT NULL,
  `acctauthentic`         VARCHAR(32) DEFAULT NULL,
  `connectinfo_start`     VARCHAR(128) DEFAULT NULL,
  `connectinfo_stop`      VARCHAR(128) DEFAULT NULL,
  `acctinputoctets`       BIGINT(20) DEFAULT NULL,
  `acctoutputoctets`      BIGINT(20) DEFAULT NULL,
  `calledstationid`       VARCHAR(50) NOT NULL DEFAULT '',
  `callingstationid`      VARCHAR(50) NOT NULL DEFAULT '',
  `acctterminatecause`    VARCHAR(32) NOT NULL DEFAULT '',
  `servicetype`           VARCHAR(32) DEFAULT NULL,
  `framedprotocol`        VARCHAR(32) DEFAULT NULL,
  `framedipaddress`       VARCHAR(15) NOT NULL DEFAULT '',
  `framedipv6address`     VARCHAR(45) NOT NULL DEFAULT '',
  `framedipv6prefix`      VARCHAR(45) NOT NULL DEFAULT '',
  `framedinterfaceid`     VARCHAR(44) NOT NULL DEFAULT '',
  `delegatedipv6prefix`   VARCHAR(45) NOT NULL DEFAULT '',
  `class`                 VARCHAR(64) DEFAULT NULL,
  PRIMARY KEY (`radacctid`),
  UNIQUE KEY `acctuniqueid` (`acctuniqueid`),
  KEY `username` (`username`),
  KEY `framedipaddress` (`framedipaddress`),
  KEY `framedipv6address` (`framedipv6address`),
  KEY `acctsessionid` (`acctsessionid`),
  KEY `acctsessiontime` (`acctsessiontime`),
  KEY `acctstarttime` (`acctstarttime`),
  KEY `acctinterval` (`acctinterval`),
  KEY `acctstoptime` (`acctstoptime`),
  KEY `nasipaddress` (`nasipaddress`),
  KEY `callingstationid` (`callingstationid`)
) ENGINE=InnoDB;

-- Post-Auth логирование
CREATE TABLE IF NOT EXISTS `radpostauth` (
  `id`                INT(11) NOT NULL AUTO_INCREMENT,
  `username`          VARCHAR(64) NOT NULL DEFAULT '',
  `pass`              VARCHAR(64) NOT NULL DEFAULT '',
  `reply`             VARCHAR(32) NOT NULL DEFAULT '',
  `authdate`          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `class`             VARCHAR(64) DEFAULT NULL,
  `calledstationid`   VARCHAR(50) DEFAULT '',
  `callingstationid`  VARCHAR(50) DEFAULT '',
  `nasipaddress`      VARCHAR(15) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `username` (`username`),
  KEY `authdate` (`authdate`),
  KEY `callingstationid` (`callingstationid`)
) ENGINE=InnoDB;

-- ── NAC-специфичные таблицы ─────────────────────────────────────────────

-- Реестр эндпоинтов (профилирование)
CREATE TABLE IF NOT EXISTS `nac_endpoints` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `mac_address`         CHAR(17) NOT NULL,
  `ip_address`          VARCHAR(45) DEFAULT NULL,
  `hostname`            VARCHAR(255) DEFAULT NULL,
  `device_profile`      VARCHAR(128) DEFAULT NULL,
  `device_vendor`       VARCHAR(128) DEFAULT NULL,
  `device_category`     VARCHAR(64) DEFAULT NULL,
  `profile_confidence`  DECIMAL(5,2) DEFAULT 0.00,
  `posture_status`      ENUM('unknown','compliant','non_compliant','quarantined','exempt') DEFAULT 'unknown',
  `auth_status`         ENUM('unknown','authenticated','rejected','pending') DEFAULT 'unknown',
  `auth_method`         VARCHAR(32) DEFAULT NULL,
  `username`            VARCHAR(128) DEFAULT NULL,
  `ad_domain`           VARCHAR(128) DEFAULT NULL,
  `ad_groups`           TEXT DEFAULT NULL,
  `nas_ip`              VARCHAR(15) DEFAULT NULL,
  `nas_port`            VARCHAR(32) DEFAULT NULL,
  `assigned_vlan`       VARCHAR(32) DEFAULT NULL,
  `assigned_sgt`        VARCHAR(32) DEFAULT NULL,
  `site_id`             VARCHAR(64) DEFAULT NULL,
  `mdm_enrolled`        BOOLEAN DEFAULT FALSE,
  `mdm_compliant`       BOOLEAN DEFAULT NULL,
  `first_seen`          DATETIME DEFAULT CURRENT_TIMESTAMP,
  `last_seen`           DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_auth`           DATETIME DEFAULT NULL,
  `last_profiled`       DATETIME DEFAULT NULL,
  `last_posture_check`  DATETIME DEFAULT NULL,
  `fingerbank_device_id` INT DEFAULT NULL,
  `dhcp_fingerprint`    VARCHAR(255) DEFAULT NULL,
  `dhcp_vendor`         VARCHAR(255) DEFAULT NULL,
  `user_agent`          TEXT DEFAULT NULL,
  `notes`               TEXT DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `mac_address` (`mac_address`),
  KEY `ip_address` (`ip_address`),
  KEY `device_profile` (`device_profile`),
  KEY `posture_status` (`posture_status`),
  KEY `auth_status` (`auth_status`),
  KEY `site_id` (`site_id`),
  KEY `last_seen` (`last_seen`),
  KEY `username` (`username`)
) ENGINE=InnoDB;

-- Политики авторизации
CREATE TABLE IF NOT EXISTS `nac_policies` (
  `id`              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`            VARCHAR(128) NOT NULL,
  `description`     TEXT DEFAULT NULL,
  `priority`        INT NOT NULL DEFAULT 100,
  `enabled`         BOOLEAN NOT NULL DEFAULT TRUE,
  `policy_set`      VARCHAR(64) NOT NULL DEFAULT 'default',
  `conditions_json` JSON NOT NULL,
  `actions_json`    JSON NOT NULL,
  `hit_count`       BIGINT UNSIGNED DEFAULT 0,
  `created_at`      DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by`      VARCHAR(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `policy_set_priority` (`policy_set`, `priority`)
) ENGINE=InnoDB;

-- Профили устройств (справочник)
CREATE TABLE IF NOT EXISTS `nac_device_profiles` (
  `id`                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`                VARCHAR(128) NOT NULL,
  `category`            VARCHAR(64) NOT NULL DEFAULT 'unknown',
  `vendor`              VARCHAR(128) DEFAULT NULL,
  `os_family`           VARCHAR(64) DEFAULT NULL,
  `fingerbank_device_id` INT DEFAULT NULL,
  `default_vlan`        VARCHAR(32) DEFAULT NULL,
  `default_acl`         VARCHAR(128) DEFAULT NULL,
  `posture_required`    BOOLEAN DEFAULT FALSE,
  `dot1x_required`      BOOLEAN DEFAULT FALSE,
  `auto_register`       BOOLEAN DEFAULT FALSE,
  `created_at`          DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `category` (`category`)
) ENGINE=InnoDB;

-- Гостевые аккаунты
CREATE TABLE IF NOT EXISTS `nac_guest_accounts` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(128) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `email`         VARCHAR(255) DEFAULT NULL,
  `phone`         VARCHAR(32) DEFAULT NULL,
  `sponsor`       VARCHAR(128) DEFAULT NULL,
  `company`       VARCHAR(128) DEFAULT NULL,
  `valid_from`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `valid_until`   DATETIME NOT NULL,
  `max_devices`   INT DEFAULT 3,
  `status`        ENUM('active','expired','disabled','pending') DEFAULT 'pending',
  `created_at`    DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `status_valid` (`status`, `valid_until`)
) ENGINE=InnoDB;

-- Аудит-лог (все административные действия)
CREATE TABLE IF NOT EXISTS `nac_audit_log` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `timestamp`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `admin_user`    VARCHAR(64) NOT NULL,
  `action`        VARCHAR(32) NOT NULL,
  `resource_type` VARCHAR(32) NOT NULL,
  `resource_id`   VARCHAR(128) DEFAULT NULL,
  `details_json`  JSON DEFAULT NULL,
  `source_ip`     VARCHAR(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `admin_user` (`admin_user`),
  KEY `resource_type` (`resource_type`)
) ENGINE=InnoDB;

-- ── Данные по умолчанию ─────────────────────────────────────────────────

-- Тестовый NAS (для отладки)
INSERT IGNORE INTO `nas` (`nasname`, `shortname`, `type`, `secret`, `description`)
VALUES ('127.0.0.1', 'localhost', 'other', 'testing123', 'Local test client');

-- Группы с VLAN по умолчанию
INSERT IGNORE INTO `radgroupreply` (`groupname`, `attribute`, `op`, `value`) VALUES
('employees',    'Tunnel-Type',         '=', '13'),
('employees',    'Tunnel-Medium-Type',  '=', '6'),
('employees',    'Tunnel-Private-Group-Id', '=', '100'),
('contractors',  'Tunnel-Type',         '=', '13'),
('contractors',  'Tunnel-Medium-Type',  '=', '6'),
('contractors',  'Tunnel-Private-Group-Id', '=', '200'),
('guests',       'Tunnel-Type',         '=', '13'),
('guests',       'Tunnel-Medium-Type',  '=', '6'),
('guests',       'Tunnel-Private-Group-Id', '=', '300'),
('quarantine',   'Tunnel-Type',         '=', '13'),
('quarantine',   'Tunnel-Medium-Type',  '=', '6'),
('quarantine',   'Tunnel-Private-Group-Id', '=', '999');

-- Базовые профили устройств
INSERT IGNORE INTO `nac_device_profiles` (`name`, `category`, `default_vlan`, `posture_required`, `dot1x_required`) VALUES
('Windows Workstation', 'workstation', '100', TRUE, TRUE),
('macOS Workstation',   'workstation', '100', TRUE, TRUE),
('Linux Workstation',   'workstation', '100', TRUE, TRUE),
('iPhone',              'mobile',      '150', FALSE, TRUE),
('Android Phone',       'mobile',      '150', FALSE, TRUE),
('IP Phone',            'voip',        '50',  FALSE, FALSE),
('Printer',             'peripheral',  '250', FALSE, FALSE),
('IP Camera',           'iot',         '260', FALSE, FALSE),
('Unknown',             'unknown',     '999', FALSE, FALSE);

-- EJBCA database user
CREATE USER IF NOT EXISTS 'ejbca'@'%' IDENTIFIED BY 'changeme_ejbca_pwd';
GRANT ALL PRIVILEGES ON `ejbca`.* TO 'ejbca'@'%';
FLUSH PRIVILEGES;
