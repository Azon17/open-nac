-- ============================================================
-- Open NAC — Extended Posture Schema v2
-- ISE-equivalent: 11 condition types + compound conditions
-- ============================================================

-- Drop old table to recreate with extended ENUM
-- (на сервере: сделать ALTER TABLE ADD к enum, или recreate)
ALTER TABLE nac_posture_conditions MODIFY COLUMN category
  ENUM('antivirus','firewall','disk_encryption','patches','os_version',
       'application','registry','file','service','usb','compound',
       'patch_management','custom') NOT NULL;

ALTER TABLE nac_posture_conditions MODIFY COLUMN operator
  ENUM('installed','running','enabled','version_gte','version_lte',
       'exists','not_exists','equals','not_equals','greater_than','less_than',
       'contains','not_contains','regex_match',
       'all_profiles_enabled','specific_profile_enabled',
       'kb_installed','kb_not_installed',
       'file_exists','file_not_exists','file_version_gte','file_sha256',
       'registry_exists','registry_value_equals','registry_value_contains',
       'service_running','service_stopped','service_auto_start',
       'usb_storage_blocked','usb_class_blocked',
       'compound_and','compound_or','compound_not') NOT NULL DEFAULT 'enabled';

-- Extended metadata for rich conditions (vendor, product specifics)
ALTER TABLE nac_posture_conditions
  ADD COLUMN IF NOT EXISTS vendor VARCHAR(128) DEFAULT NULL AFTER expected_value,
  ADD COLUMN IF NOT EXISTS product_name VARCHAR(255) DEFAULT NULL AFTER vendor,
  ADD COLUMN IF NOT EXISTS min_version VARCHAR(64) DEFAULT NULL AFTER product_name,
  ADD COLUMN IF NOT EXISTS file_path VARCHAR(512) DEFAULT NULL AFTER min_version,
  ADD COLUMN IF NOT EXISTS registry_path VARCHAR(512) DEFAULT NULL AFTER file_path,
  ADD COLUMN IF NOT EXISTS registry_key VARCHAR(255) DEFAULT NULL AFTER registry_path,
  ADD COLUMN IF NOT EXISTS service_name VARCHAR(128) DEFAULT NULL AFTER registry_key,
  ADD COLUMN IF NOT EXISTS kb_numbers JSON DEFAULT NULL AFTER service_name,
  ADD COLUMN IF NOT EXISTS usb_classes JSON DEFAULT NULL AFTER kb_numbers,
  ADD COLUMN IF NOT EXISTS firewall_profiles JSON DEFAULT NULL AFTER usb_classes,
  ADD COLUMN IF NOT EXISTS sub_conditions JSON DEFAULT NULL AFTER firewall_profiles,
  ADD COLUMN IF NOT EXISTS compound_operator ENUM('AND','OR','NOT') DEFAULT NULL AFTER sub_conditions;

-- ─── AV Vendor reference table ───
CREATE TABLE IF NOT EXISTS nac_av_vendors (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  vendor_name VARCHAR(128) NOT NULL,
  product_name VARCHAR(255) NOT NULL,
  os_type ENUM('windows','macos','linux') NOT NULL,
  process_name VARCHAR(128) DEFAULT NULL,
  service_name VARCHAR(128) DEFAULT NULL,
  registry_path VARCHAR(512) DEFAULT NULL,
  osquery_table VARCHAR(128) DEFAULT 'windows_security_products',
  min_def_age_days INT DEFAULT 7,
  UNIQUE KEY vendor_product_os (vendor_name, product_name, os_type)
) ENGINE=InnoDB;

-- Populate known AV vendors
INSERT IGNORE INTO nac_av_vendors (vendor_name, product_name, os_type, process_name, service_name) VALUES
('Microsoft', 'Windows Defender', 'windows', 'MsMpEng.exe', 'WinDefend'),
('Microsoft', 'System Center Endpoint Protection', 'windows', 'MsMpEng.exe', 'WinDefend'),
('CrowdStrike', 'Falcon Sensor', 'windows', 'CSFalconService.exe', 'CSFalconService'),
('CrowdStrike', 'Falcon Sensor', 'macos', 'falcond', NULL),
('CrowdStrike', 'Falcon Sensor', 'linux', 'falcond', NULL),
('SentinelOne', 'SentinelOne Agent', 'windows', 'SentinelAgent.exe', 'SentinelAgent'),
('SentinelOne', 'SentinelOne Agent', 'macos', 'sentineld', NULL),
('SentinelOne', 'SentinelOne Agent', 'linux', 'sentineld', NULL),
('Symantec', 'Endpoint Protection', 'windows', 'ccSvcHst.exe', 'SepMasterService'),
('Trend Micro', 'Apex One', 'windows', 'PccNTMon.exe', 'TmCCSF'),
('Kaspersky', 'Endpoint Security', 'windows', 'avp.exe', 'AVP'),
('ESET', 'Endpoint Security', 'windows', 'ekrn.exe', 'ekrn'),
('Sophos', 'Intercept X', 'windows', 'SophosHealth.exe', 'Sophos Endpoint Defense Service'),
('Bitdefender', 'GravityZone', 'windows', 'EPSecurityService.exe', 'EPSecurityService'),
('Palo Alto', 'Cortex XDR', 'windows', 'CortexXDR.exe', 'CortexXDR'),
('Palo Alto', 'Cortex XDR', 'macos', 'cortex_xdr', NULL),
('Carbon Black', 'CB Defense', 'windows', 'RepMgr.exe', 'CbDefense'),
('McAfee', 'Endpoint Security', 'windows', 'mfemms.exe', 'mfemms'),
('Cisco', 'AMP for Endpoints', 'windows', 'sfc.exe', 'CiscoAMP'),
('Cisco', 'Secure Endpoint', 'windows', 'sfc.exe', 'CiscoAMP');

-- ─── Firewall profile reference ───
CREATE TABLE IF NOT EXISTS nac_firewall_profiles (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  profile_name VARCHAR(64) NOT NULL,
  os_type ENUM('windows','macos','linux') NOT NULL,
  description VARCHAR(255) DEFAULT NULL,
  UNIQUE KEY profile_os (profile_name, os_type)
) ENGINE=InnoDB;

INSERT IGNORE INTO nac_firewall_profiles (profile_name, os_type, description) VALUES
('Domain', 'windows', 'Windows Domain network profile'),
('Private', 'windows', 'Windows Private network profile'),
('Public', 'windows', 'Windows Public network profile'),
('ALF', 'macos', 'macOS Application Layer Firewall'),
('pf', 'macos', 'macOS Packet Filter'),
('iptables', 'linux', 'Linux iptables/nftables'),
('ufw', 'linux', 'Ubuntu Uncomplicated Firewall'),
('firewalld', 'linux', 'RHEL/CentOS firewalld');

-- ─── Posture assessment history ───
CREATE TABLE IF NOT EXISTS nac_posture_assessments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  mac_address VARCHAR(17) NOT NULL,
  policy_id INT UNSIGNED DEFAULT NULL,
  status ENUM('compliant','non_compliant','unknown','error','pending') NOT NULL,
  checks_json JSON DEFAULT NULL,
  source ENUM('fleet','agent','basic','network','manual') DEFAULT 'agent',
  assessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_mac_time (mac_address, assessed_at DESC),
  INDEX idx_status (status)
) ENGINE=InnoDB;

-- ─── Extended seed conditions for ISE-style checks ───

-- Anti-Malware with vendor selection
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, vendor, product_name, min_version) VALUES
('CrowdStrike Falcon Active', 'CrowdStrike Falcon sensor must be running', 'antivirus',
 '["windows","macos","linux"]', 'running', 'true', 'critical', 'CrowdStrike', 'Falcon Sensor', '7.0'),
('SentinelOne Active', 'SentinelOne agent must be running and current', 'antivirus',
 '["windows","macos","linux"]', 'running', 'true', 'critical', 'SentinelOne', 'SentinelOne Agent', '23.0'),
('Any AV Installed', 'At least one AV product must be detected', 'antivirus',
 '["windows","macos"]', 'installed', 'true', 'critical', NULL, NULL, NULL);

-- Firewall with profile checks
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, firewall_profiles) VALUES
('FW All Profiles', 'All Windows firewall profiles must be enabled', 'firewall',
 '["windows"]', 'all_profiles_enabled', 'true', 'critical', '["Domain","Private","Public"]'),
('FW Domain Profile', 'Domain firewall profile must be enabled', 'firewall',
 '["windows"]', 'specific_profile_enabled', 'Domain', 'critical', '["Domain"]');

-- Patch Management with KB numbers
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, kb_numbers) VALUES
('Critical KB Patches', 'Specific critical KB patches must be installed', 'patch_management',
 '["windows"]', 'kb_installed', 'true', 'critical', '["KB5034441","KB5034123","KB5033375"]');

-- File checks
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, file_path) VALUES
('VPN Client Installed', 'Corporate VPN client must be present', 'file',
 '["windows"]', 'file_exists', 'true', 'warning', 'C:\\Program Files\\Cisco\\AnyConnect Secure Mobility Client\\vpnagent.exe'),
('No Unauthorized Tools', 'Wireshark should not be installed (security policy)', 'file',
 '["windows"]', 'file_not_exists', 'true', 'warning', 'C:\\Program Files\\Wireshark\\Wireshark.exe');

-- Registry checks
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, registry_path, registry_key) VALUES
('Screen Lock Enabled', 'Screensaver lock must be enabled', 'registry',
 '["windows"]', 'registry_value_equals', '1', 'warning',
 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization', 'NoLockScreen'),
('UAC Enabled', 'User Account Control must be enabled', 'registry',
 '["windows"]', 'registry_value_equals', '1', 'critical',
 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA');

-- Service checks
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, service_name) VALUES
('Windows Update Running', 'Windows Update service must be running', 'service',
 '["windows"]', 'service_running', 'true', 'warning', 'wuauserv'),
('Remote Desktop Disabled', 'RDP service must be stopped', 'service',
 '["windows"]', 'service_stopped', 'true', 'warning', 'TermService');

-- USB checks
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, expected_value, severity, usb_classes) VALUES
('USB Storage Blocked', 'USB mass storage devices must be blocked', 'usb',
 '["windows","macos","linux"]', 'usb_storage_blocked', 'true', 'critical', '["mass_storage"]'),
('USB All External Blocked', 'All removable USB storage blocked', 'usb',
 '["windows"]', 'usb_class_blocked', 'true', 'warning', '["mass_storage","portable_device","cdrom"]');

-- Compound conditions
INSERT IGNORE INTO nac_posture_conditions
  (name, description, category, os_types, operator, severity, sub_conditions, compound_operator) VALUES
('Full AV + FW Combo', 'Both AV active AND firewall enabled for all profiles', 'compound',
 '["windows"]', 'compound_and', 'critical', '["CrowdStrike Falcon Active","FW All Profiles"]', 'AND'),
('Any Approved AV', 'CrowdStrike OR SentinelOne must be active', 'compound',
 '["windows","macos"]', 'compound_or', 'critical', '["CrowdStrike Falcon Active","SentinelOne Active"]', 'OR');
