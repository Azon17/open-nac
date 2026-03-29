-- ============================================================
-- Open NAC — ISE-Style Policy Module Schema
-- Replaces flat nac_policies with 3-level hierarchy
-- ============================================================

SET NAMES utf8mb4;
USE open_nac;

-- ============================================================
-- 1. IDENTITY SOURCES
-- ============================================================
CREATE TABLE IF NOT EXISTS identity_sources (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    source_type     ENUM('internal','active_directory','ldap','certificate','mab') NOT NULL,
    description     VARCHAR(512) DEFAULT '',
    -- Connection config (JSON): host, port, base_dn, bind_dn, bind_pw, domain, etc.
    config_json     JSON DEFAULT NULL,
    priority        INT DEFAULT 0,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 2. ALLOWED PROTOCOLS
-- ============================================================
CREATE TABLE IF NOT EXISTS allowed_protocols (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     VARCHAR(512) DEFAULT '',
    -- Each flag enables/disables an EAP method
    allow_pap       BOOLEAN DEFAULT TRUE,
    allow_chap      BOOLEAN DEFAULT FALSE,
    allow_mschap_v2 BOOLEAN DEFAULT TRUE,
    allow_peap      BOOLEAN DEFAULT TRUE,
    allow_eap_tls   BOOLEAN DEFAULT TRUE,
    allow_eap_fast  BOOLEAN DEFAULT FALSE,
    allow_eap_ttls  BOOLEAN DEFAULT FALSE,
    allow_eap_md5   BOOLEAN DEFAULT FALSE,
    -- Inner methods for tunneled EAP
    peap_inner_mschap_v2  BOOLEAN DEFAULT TRUE,
    peap_inner_eap_gtc    BOOLEAN DEFAULT FALSE,
    ttls_inner_pap        BOOLEAN DEFAULT TRUE,
    ttls_inner_mschap_v2  BOOLEAN DEFAULT FALSE,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 3. AUTHORIZATION PROFILES
-- ============================================================
CREATE TABLE IF NOT EXISTS authorization_profiles (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     VARCHAR(512) DEFAULT '',
    -- Access type
    access_type     ENUM('access_accept','access_reject') DEFAULT 'access_accept',
    -- VLAN assignment
    vlan_id         INT DEFAULT NULL,
    vlan_name       VARCHAR(64) DEFAULT NULL,
    -- ACL
    acl_name        VARCHAR(128) DEFAULT NULL,
    dacl_name       VARCHAR(128) DEFAULT NULL,
    -- Security Group Tag (Cisco TrustSec)
    sgt             INT DEFAULT NULL,
    -- Web redirect
    url_redirect    VARCHAR(512) DEFAULT NULL,
    url_redirect_acl VARCHAR(128) DEFAULT NULL,
    -- Session limits
    session_timeout INT DEFAULT NULL,
    idle_timeout    INT DEFAULT NULL,
    -- Reauthentication
    reauth_timer    INT DEFAULT NULL,
    reauth_type     ENUM('default','last','reauth') DEFAULT 'default',
    -- Voice VLAN
    voice_vlan      INT DEFAULT NULL,
    -- Additional RADIUS attributes as JSON: [{"vendor":0,"attr_id":64,"value":"Tunnel-Type=VLAN"}, ...]
    extra_attributes_json JSON DEFAULT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 4. CONDITION LIBRARY
-- ============================================================
CREATE TABLE IF NOT EXISTS condition_library (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     VARCHAR(512) DEFAULT '',
    -- Type of condition
    condition_type  ENUM('simple','compound') NOT NULL DEFAULT 'simple',
    -- For simple conditions:
    attribute       VARCHAR(128) DEFAULT NULL,      -- e.g. 'RADIUS:NAS-Port-Type', 'AD:memberOf', 'Device:DeviceType'
    operator        ENUM('equals','not_equals','contains','not_contains','starts_with',
                         'ends_with','matches_regex','in','not_in',
                         'greater_than','less_than','exists','not_exists') DEFAULT 'equals',
    value           VARCHAR(512) DEFAULT NULL,      -- comparison value
    -- For compound conditions: JSON structure
    -- {"operator": "AND|OR|NOT", "children": [condition_id, condition_id, ...]}
    compound_json   JSON DEFAULT NULL,
    -- Categorization (like ISE condition studio)
    category        VARCHAR(64) DEFAULT 'General',  -- Network, Device, User, Posture, General
    reusable        BOOLEAN DEFAULT TRUE,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 5. POLICY SETS (Top-level containers)
-- ============================================================
CREATE TABLE IF NOT EXISTS policy_sets (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     VARCHAR(512) DEFAULT '',
    -- Condition that routes a RADIUS request into this set
    -- NULL condition = Default policy set (catch-all)
    condition_id    INT DEFAULT NULL,
    -- Inline condition (for sets that don't use library)
    condition_json  JSON DEFAULT NULL,
    -- Allowed protocols for this set
    allowed_protocols_id INT DEFAULT NULL,
    -- Ordering
    priority        INT NOT NULL DEFAULT 100,
    -- Status
    is_default      BOOLEAN DEFAULT FALSE,
    enabled         BOOLEAN DEFAULT TRUE,
    hit_count       BIGINT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (condition_id) REFERENCES condition_library(id) ON DELETE SET NULL,
    FOREIGN KEY (allowed_protocols_id) REFERENCES allowed_protocols(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 6. AUTHENTICATION POLICIES (inside each Policy Set)
-- ============================================================
CREATE TABLE IF NOT EXISTS authentication_policies (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    description     VARCHAR(512) DEFAULT '',
    policy_set_id   INT NOT NULL,
    -- Condition (from library or inline)
    condition_id    INT DEFAULT NULL,
    condition_json  JSON DEFAULT NULL,
    -- Identity source to use when condition matches
    identity_source_id INT DEFAULT NULL,
    -- What to do on auth failure
    on_failure      ENUM('reject','continue','drop') DEFAULT 'reject',
    -- Ordering within the policy set
    priority        INT NOT NULL DEFAULT 100,
    enabled         BOOLEAN DEFAULT TRUE,
    hit_count       BIGINT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_set_id) REFERENCES policy_sets(id) ON DELETE CASCADE,
    FOREIGN KEY (condition_id) REFERENCES condition_library(id) ON DELETE SET NULL,
    FOREIGN KEY (identity_source_id) REFERENCES identity_sources(id) ON DELETE SET NULL,
    UNIQUE KEY uk_auth_policy_set_name (policy_set_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- 7. AUTHORIZATION POLICIES (inside each Policy Set)
-- ============================================================
CREATE TABLE IF NOT EXISTS authorization_policies (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    description     VARCHAR(512) DEFAULT '',
    policy_set_id   INT NOT NULL,
    -- Condition (from library or inline) — typically compound
    condition_id    INT DEFAULT NULL,
    condition_json  JSON DEFAULT NULL,
    -- Result: which authorization profile to apply
    authorization_profile_id INT DEFAULT NULL,
    -- Ordering within the policy set
    priority        INT NOT NULL DEFAULT 100,
    is_default      BOOLEAN DEFAULT FALSE,
    enabled         BOOLEAN DEFAULT TRUE,
    hit_count       BIGINT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_set_id) REFERENCES policy_sets(id) ON DELETE CASCADE,
    FOREIGN KEY (condition_id) REFERENCES condition_library(id) ON DELETE SET NULL,
    FOREIGN KEY (authorization_profile_id) REFERENCES authorization_profiles(id) ON DELETE SET NULL,
    UNIQUE KEY uk_authz_policy_set_name (policy_set_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- INDEXES for performance
-- ============================================================
ALTER TABLE policy_sets ADD INDEX idx_ps_priority (priority, enabled);
ALTER TABLE authentication_policies ADD INDEX idx_auth_ps_priority (policy_set_id, priority, enabled);
ALTER TABLE authorization_policies ADD INDEX idx_authz_ps_priority (policy_set_id, priority, enabled);
ALTER TABLE condition_library ADD INDEX idx_cond_category (category, reusable, enabled);

-- ============================================================
-- SEED DATA
-- ============================================================

-- Identity Sources
INSERT INTO identity_sources (name, source_type, description, config_json) VALUES
('Internal Users', 'internal', 'Local user database in MariaDB', '{"table": "radcheck"}'),
('Active Directory', 'active_directory', 'Corporate AD/LDAP', '{"host": "10.10.10.50", "port": 389, "base_dn": "dc=corp,dc=local", "bind_dn": "cn=svc-nac,ou=Service Accounts,dc=corp,dc=local", "domain": "corp.local"}'),
('LDAP Server', 'ldap', 'Generic LDAP directory', '{"host": "10.10.10.51", "port": 389, "base_dn": "dc=example,dc=com"}'),
('Certificate Auth', 'certificate', 'X.509 certificate-based authentication', '{"ca_cert_path": "/etc/freeradius/certs/ca.pem", "check_crl": true}'),
('MAB Internal', 'mab', 'MAC Authentication Bypass — endpoint DB', '{"table": "endpoints", "mac_field": "mac_address"}');

-- Allowed Protocols
INSERT INTO allowed_protocols (name, description, allow_pap, allow_chap, allow_mschap_v2, allow_peap, allow_eap_tls, allow_eap_fast, allow_eap_ttls) VALUES
('Default Allowed Protocols', 'Standard 802.1X protocols', TRUE, FALSE, TRUE, TRUE, TRUE, FALSE, FALSE),
('EAP-TLS Only', 'Certificate-only authentication', FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, FALSE),
('MAB Protocols', 'PAP/CHAP for MAC auth bypass', TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE),
('Guest Protocols', 'Guest portal authentication', TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE),
('All Protocols', 'Allow everything', TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE);

-- Authorization Profiles
INSERT INTO authorization_profiles (name, description, access_type, vlan_id, vlan_name, acl_name, session_timeout) VALUES
('PermitAccess', 'Full network access', 'access_accept', NULL, NULL, NULL, NULL),
('DenyAccess', 'Deny all access', 'access_reject', NULL, NULL, NULL, NULL),
('VLAN100_Employee', 'Employee VLAN 100', 'access_accept', 100, 'EMPLOYEES', 'ACL-EMPLOYEE', 28800),
('VLAN200_Guest', 'Guest VLAN 200', 'access_accept', 200, 'GUESTS', 'ACL-GUEST', 3600),
('VLAN300_IOT', 'IoT/BYOD VLAN 300', 'access_accept', 300, 'IOT', 'ACL-IOT', 86400),
('VLAN999_Quarantine', 'Quarantine for non-compliant', 'access_accept', 999, 'QUARANTINE', 'ACL-QUARANTINE', 600);

UPDATE authorization_profiles SET url_redirect = 'https://nac.corp.local/guest', url_redirect_acl = 'ACL-REDIRECT' WHERE name = 'VLAN200_Guest';
UPDATE authorization_profiles SET url_redirect = 'https://nac.corp.local/remediation', url_redirect_acl = 'ACL-REDIRECT' WHERE name = 'VLAN999_Quarantine';

-- Condition Library
INSERT INTO condition_library (name, description, condition_type, attribute, operator, value, category) VALUES
('Wired 802.1X',            'NAS-Port-Type is Ethernet',         'simple', 'RADIUS:NAS-Port-Type', 'equals', 'Ethernet', 'Network'),
('Wireless 802.1X',         'NAS-Port-Type is Wireless',         'simple', 'RADIUS:NAS-Port-Type', 'equals', 'Wireless-IEEE-802-11', 'Network'),
('EAP-TLS Auth',            'EAP type is TLS',                   'simple', 'RADIUS:EAP-Type', 'equals', 'TLS', 'Network'),
('PEAP Auth',               'EAP type is PEAP',                  'simple', 'RADIUS:EAP-Type', 'equals', 'PEAP', 'Network'),
('AD Group: Employees',     'User is member of Employees group', 'simple', 'AD:memberOf', 'contains', 'CN=Employees', 'User'),
('AD Group: IT-Admins',     'User is member of IT-Admins group', 'simple', 'AD:memberOf', 'contains', 'CN=IT-Admins', 'User'),
('AD Group: Contractors',   'User is member of Contractors',     'simple', 'AD:memberOf', 'contains', 'CN=Contractors', 'User'),
('Device: Cisco Switch',    'Device type is Cisco switch',       'simple', 'Device:DeviceType', 'equals', 'Cisco Switch', 'Device'),
('Device: Cisco AP',        'Device type is Cisco AP',           'simple', 'Device:DeviceType', 'equals', 'Cisco AP', 'Device'),
('Posture: Compliant',      'Endpoint posture is compliant',     'simple', 'Posture:Status', 'equals', 'Compliant', 'Posture'),
('Posture: Non-Compliant',  'Endpoint posture is non-compliant', 'simple', 'Posture:Status', 'equals', 'Non-Compliant', 'Posture'),
('MAB Request',             'Service-Type is Call-Check (MAB)',   'simple', 'RADIUS:Service-Type', 'equals', 'Call-Check', 'Network'),
('Guest Portal',            'User from guest portal',            'simple', 'OpenNAC:AuthSource', 'equals', 'GuestPortal', 'User'),
('Internal User',           'User from internal DB',             'simple', 'OpenNAC:AuthSource', 'equals', 'Internal', 'User');

-- Compound condition examples
INSERT INTO condition_library (name, description, condition_type, compound_json, category) VALUES
('Employee + Compliant', 'Employee group AND posture compliant', 'compound',
 '{"operator": "AND", "children": [5, 10]}', 'User'),
('Employee + Non-Compliant', 'Employee group AND posture non-compliant', 'compound',
 '{"operator": "AND", "children": [5, 11]}', 'User'),
('IT-Admin + EAP-TLS', 'IT-Admins group AND certificate auth', 'compound',
 '{"operator": "AND", "children": [6, 3]}', 'User');

-- ============================================================
-- POLICY SETS with Authentication & Authorization Policies
-- ============================================================

-- Policy Set 1: Wired 802.1X
INSERT INTO policy_sets (name, description, condition_id, allowed_protocols_id, priority, is_default) VALUES
('Wired 802.1X', 'Wired 802.1X authentication', 1, 1, 10, FALSE);

-- Policy Set 2: Wireless 802.1X
INSERT INTO policy_sets (name, description, condition_id, allowed_protocols_id, priority, is_default) VALUES
('Wireless 802.1X', 'Wireless 802.1X authentication', 2, 1, 20, FALSE);

-- Policy Set 3: MAB
INSERT INTO policy_sets (name, description, condition_id, allowed_protocols_id, priority, is_default) VALUES
('MAB', 'MAC Authentication Bypass', 12, 3, 30, FALSE);

-- Policy Set 4: Guest CWA
INSERT INTO policy_sets (name, description, condition_id, allowed_protocols_id, priority, is_default) VALUES
('Guest CWA', 'Guest Central Web Authentication', 13, 4, 40, FALSE);

-- Policy Set 5: Default (catch-all)
INSERT INTO policy_sets (name, description, condition_id, allowed_protocols_id, priority, is_default) VALUES
('Default', 'Default catch-all policy set', NULL, 5, 9999, TRUE);

-- Authentication Policies for "Wired 802.1X" (policy_set_id=1)
INSERT INTO authentication_policies (name, policy_set_id, condition_id, identity_source_id, on_failure, priority) VALUES
('EAP-TLS Certificate', 1, 3, 4, 'continue', 10),
('PEAP → Active Directory', 1, 4, 2, 'continue', 20),
('Fallback → Internal Users', 1, NULL, 1, 'reject', 100);

-- Authentication Policies for "Wireless 802.1X" (policy_set_id=2)
INSERT INTO authentication_policies (name, policy_set_id, condition_id, identity_source_id, on_failure, priority) VALUES
('EAP-TLS Certificate', 2, 3, 4, 'continue', 10),
('PEAP → Active Directory', 2, 4, 2, 'reject', 20);

-- Authentication Policies for "MAB" (policy_set_id=3)
INSERT INTO authentication_policies (name, policy_set_id, condition_id, identity_source_id, on_failure, priority) VALUES
('MAC Lookup', 3, NULL, 5, 'reject', 10);

-- Authentication Policies for "Guest CWA" (policy_set_id=4)
INSERT INTO authentication_policies (name, policy_set_id, condition_id, identity_source_id, on_failure, priority) VALUES
('Guest → Internal Users', 4, NULL, 1, 'reject', 10);

-- Authentication Policies for "Default" (policy_set_id=5)
INSERT INTO authentication_policies (name, policy_set_id, condition_id, identity_source_id, on_failure, priority) VALUES
('Default Auth', 5, NULL, 1, 'reject', 100);

-- Authorization Policies for "Wired 802.1X" (policy_set_id=1)
INSERT INTO authorization_policies (name, policy_set_id, condition_id, authorization_profile_id, priority, is_default) VALUES
('IT-Admins Full Access', 1, 17, 1, 10, FALSE),
('Employees Compliant', 1, 15, 3, 20, FALSE),
('Employees Non-Compliant', 1, 16, 6, 30, FALSE),
('Default Deny', 1, NULL, 2, 9999, TRUE);

-- Authorization Policies for "Wireless 802.1X" (policy_set_id=2)
INSERT INTO authorization_policies (name, policy_set_id, condition_id, authorization_profile_id, priority, is_default) VALUES
('Employees → VLAN100', 2, 15, 3, 10, FALSE),
('Contractors → VLAN300', 2, 7, 5, 20, FALSE),
('Default Deny', 2, NULL, 2, 9999, TRUE);

-- Authorization Policies for "MAB" (policy_set_id=3)
INSERT INTO authorization_policies (name, policy_set_id, condition_id, authorization_profile_id, priority, is_default) VALUES
('Known Device → IoT VLAN', 3, NULL, 5, 10, FALSE),
('Default Deny', 3, NULL, 2, 9999, TRUE);

-- Authorization Policies for "Guest CWA" (policy_set_id=4)
INSERT INTO authorization_policies (name, policy_set_id, condition_id, authorization_profile_id, priority, is_default) VALUES
('Guest Access', 4, NULL, 4, 10, FALSE);

-- Authorization Policies for "Default" (policy_set_id=5)
INSERT INTO authorization_policies (name, policy_set_id, condition_id, authorization_profile_id, priority, is_default) VALUES
('Default Deny', 5, NULL, 2, 9999, TRUE);
