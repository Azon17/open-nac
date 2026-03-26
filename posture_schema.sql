-- Posture conditions (individual checks)
CREATE TABLE IF NOT EXISTS nac_posture_conditions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  description TEXT DEFAULT NULL,
  category ENUM('antivirus','firewall','disk_encryption','patches','os_version','application','registry','file','service','custom') NOT NULL,
  os_types JSON NOT NULL DEFAULT '["windows","macos","linux"]',
  operator ENUM('installed','running','enabled','version_gte','version_lte','exists','not_exists','equals','greater_than','less_than') NOT NULL DEFAULT 'enabled',
  expected_value VARCHAR(255) DEFAULT NULL,
  severity ENUM('critical','warning','info') DEFAULT 'critical',
  enabled BOOLEAN DEFAULT TRUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY name (name)
) ENGINE=InnoDB;

-- Posture requirements (groups of conditions)
CREATE TABLE IF NOT EXISTS nac_posture_requirements (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  description TEXT DEFAULT NULL,
  os_types JSON NOT NULL DEFAULT '["windows","macos","linux"]',
  conditions JSON NOT NULL DEFAULT '[]',
  remediation JSON DEFAULT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY name (name)
) ENGINE=InnoDB;

-- Posture policies (map requirements to identity groups)  
CREATE TABLE IF NOT EXISTS nac_posture_policies (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  description TEXT DEFAULT NULL,
  priority INT DEFAULT 100,
  identity_match JSON DEFAULT '{}',
  requirements JSON NOT NULL DEFAULT '[]',
  action_compliant VARCHAR(32) DEFAULT 'permit',
  action_non_compliant VARCHAR(32) DEFAULT 'quarantine',
  reassessment_minutes INT DEFAULT 240,
  grace_minutes INT DEFAULT 0,
  enabled BOOLEAN DEFAULT TRUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY name (name)
) ENGINE=InnoDB;

-- Default conditions
INSERT IGNORE INTO nac_posture_conditions (name, category, os_types, operator, expected_value, severity, description) VALUES
('AV Installed', 'antivirus', '["windows","macos"]', 'installed', 'true', 'critical', 'Antivirus product must be installed'),
('AV Running', 'antivirus', '["windows","macos"]', 'running', 'true', 'critical', 'Antivirus real-time protection must be active'),
('AV Definitions Current', 'antivirus', '["windows","macos"]', 'enabled', 'true', 'warning', 'Antivirus definitions updated within 7 days'),
('Firewall Enabled', 'firewall', '["windows","macos","linux"]', 'enabled', 'true', 'critical', 'OS firewall must be enabled for all profiles'),
('BitLocker/FileVault', 'disk_encryption', '["windows","macos"]', 'enabled', 'true', 'warning', 'Full disk encryption must be enabled'),
('No Critical Patches', 'patches', '["windows","macos","linux"]', 'equals', '0', 'critical', 'No pending critical OS security patches'),
('Max 10 Pending Patches', 'patches', '["windows","macos","linux"]', 'less_than', '11', 'warning', 'Maximum 10 pending non-critical patches'),
('Windows 10+', 'os_version', '["windows"]', 'version_gte', '10.0', 'warning', 'Minimum Windows 10 or later'),
('macOS 13+', 'os_version', '["macos"]', 'version_gte', '13.0', 'warning', 'Minimum macOS Ventura or later');

-- Default requirements
INSERT IGNORE INTO nac_posture_requirements (name, description, os_types, conditions, remediation) VALUES
('Corporate Workstation', 'Full compliance for corporate-managed Windows/Mac', '["windows","macos"]',
 '["AV Installed","AV Running","Firewall Enabled","BitLocker/FileVault","No Critical Patches"]',
 '{"av":"Install approved antivirus (Defender, CrowdStrike, SentinelOne)","firewall":"Enable Windows Firewall or macOS ALF","encryption":"Enable BitLocker (Windows) or FileVault (macOS)","patches":"Run Windows Update / Software Update immediately"}'),
('BYOD Minimum', 'Minimum compliance for personal devices', '["windows","macos","linux","ios","android"]',
 '["AV Installed","Firewall Enabled"]',
 '{"av":"Install antivirus software","firewall":"Enable device firewall"}'),
('Linux Server', 'Compliance for Linux endpoints', '["linux"]',
 '["Firewall Enabled","No Critical Patches"]',
 '{"firewall":"Enable iptables/nftables","patches":"Run apt upgrade or yum update"}');

-- Default policies
INSERT IGNORE INTO nac_posture_policies (name, description, priority, identity_match, requirements, action_compliant, action_non_compliant, reassessment_minutes) VALUES
('Corporate Employees', 'Full posture for domain-joined machines', 10,
 '{"AD-Group":"Domain Users","Device-Category":"workstation"}',
 '["Corporate Workstation"]', 'permit', 'quarantine', 240),
('BYOD Users', 'Basic posture for personal devices', 20,
 '{"Device-Category":"mobile"}',
 '["BYOD Minimum"]', 'permit', 'quarantine', 480),
('Contractors', 'Contractor device compliance', 30,
 '{"AD-Group":"Contractors"}',
 '["BYOD Minimum"]', 'permit', 'quarantine', 240);
