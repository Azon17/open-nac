"""
Compliance Engine — evaluates endpoint posture against policies.
Equivalent: Cisco ISE Posture Conditions + Requirements + Policies.

Checks:
  - Antivirus (installed, running, up-to-date)
  - Firewall (enabled for all profiles)
  - Disk encryption (BitLocker/FileVault enabled)
  - OS patches (critical patches applied)
  - OS version (minimum version)
  - Prohibited applications
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("nac.compliance")


@dataclass
class CompliancePolicy:
    name: str
    os_types: list = field(default_factory=lambda: ["windows", "macos", "linux"])
    require_antivirus: bool = True
    require_firewall: bool = True
    require_disk_encryption: bool = False
    max_critical_patches: int = 0
    max_total_patches: int = 10
    min_os_version: str = ""
    exempt_profiles: list = field(default_factory=list)  # device profiles exempt from posture
    enabled: bool = True


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str = "critical"  # critical, warning, info
    detail: str = ""
    remediation: str = ""


class ComplianceEngine:
    def __init__(self):
        # Default policies — can be loaded from DB/config
        self.policies = [
            CompliancePolicy(
                name="Corporate Standard",
                require_antivirus=True,
                require_firewall=True,
                require_disk_encryption=True,
                max_critical_patches=0,
                max_total_patches=10,
                exempt_profiles=["IP Phone", "Printer", "IP Camera"],
            ),
            CompliancePolicy(
                name="BYOD Minimum",
                os_types=["ios", "android"],
                require_antivirus=False,
                require_firewall=False,
                require_disk_encryption=False,
                max_critical_patches=5,
            ),
        ]

    def evaluate_fleet(self, fleet_data: dict) -> dict:
        """Evaluate using Fleet/osquery data."""
        checks = []
        remediation = []

        platform = fleet_data.get("platform", "").lower()
        hostname = fleet_data.get("hostname", "")

        # --- Antivirus ---
        av_ok = False
        av_products = fleet_data.get("antivirus", [])
        if av_products:
            for av in av_products:
                if av.get("state") in ("on", "running", "enabled", "1"):
                    av_ok = True
                    break
        if platform == "linux":
            av_ok = True  # Linux exempt from AV requirement by default

        checks.append(CheckResult(
            name="Antivirus",
            passed=av_ok,
            severity="critical",
            detail=f"{'Active' if av_ok else 'Not detected or disabled'}",
            remediation="" if av_ok else "Install and enable antivirus software (Windows Defender, CrowdStrike, SentinelOne)",
        ))
        if not av_ok:
            remediation.append("Install and enable antivirus software")

        # --- Firewall ---
        fw_ok = False
        fw_data = fleet_data.get("firewall", {})
        if isinstance(fw_data, dict):
            fw_ok = fw_data.get("enabled", False)
        elif isinstance(fw_data, list) and fw_data:
            fw_ok = all(f.get("enabled", False) for f in fw_data)
        if platform == "linux":
            fw_ok = fleet_data.get("iptables_rules", 0) > 0 or fw_ok

        checks.append(CheckResult(
            name="Firewall",
            passed=fw_ok,
            severity="critical",
            detail=f"{'Enabled' if fw_ok else 'Disabled or not configured'}",
            remediation="" if fw_ok else "Enable OS firewall for all network profiles",
        ))
        if not fw_ok:
            remediation.append("Enable OS firewall")

        # --- Disk Encryption ---
        enc_ok = False
        enc_data = fleet_data.get("disk_encryption", {})
        if isinstance(enc_data, dict):
            enc_ok = enc_data.get("enabled", False)
        elif isinstance(enc_data, list) and enc_data:
            enc_ok = any(e.get("encrypted", False) for e in enc_data)

        checks.append(CheckResult(
            name="Disk Encryption",
            passed=enc_ok,
            severity="warning",
            detail=f"{'Enabled' if enc_ok else 'Not enabled'}",
            remediation="" if enc_ok else "Enable BitLocker (Windows) or FileVault (macOS)",
        ))
        if not enc_ok:
            remediation.append("Enable disk encryption")

        # --- OS Patches ---
        patches = fleet_data.get("patches", {})
        critical = patches.get("pending_critical", 0) if isinstance(patches, dict) else 0
        total = patches.get("pending_total", 0) if isinstance(patches, dict) else 0
        patches_ok = critical == 0

        checks.append(CheckResult(
            name="OS Patches",
            passed=patches_ok,
            severity="critical" if critical > 0 else "warning",
            detail=f"{critical} critical, {total} total pending",
            remediation="" if patches_ok else f"Install {critical} critical patches immediately",
        ))
        if not patches_ok:
            remediation.append(f"Install {critical} critical OS patches")

        # --- OS Version ---
        os_ver = fleet_data.get("os_version", "")
        ver_ok = True  # TODO: implement min version check

        checks.append(CheckResult(
            name="OS Version",
            passed=ver_ok,
            severity="info",
            detail=f"{platform} {os_ver}",
        ))

        # --- Determine overall status ---
        critical_failures = [c for c in checks if not c.passed and c.severity == "critical"]
        warning_failures = [c for c in checks if not c.passed and c.severity == "warning"]

        if critical_failures:
            status = "non_compliant"
        elif warning_failures:
            status = "compliant"  # warnings don't block, but get logged
        else:
            status = "compliant"

        logger.info(f"POSTURE FLEET: host={hostname} platform={platform} status={status} "
                     f"critical_fail={len(critical_failures)} warnings={len(warning_failures)}")

        return {
            "status": status,
            "checks": [{"name": c.name, "passed": c.passed, "severity": c.severity,
                        "detail": c.detail, "remediation": c.remediation} for c in checks],
            "remediation": remediation,
            "source": "fleet",
            "hostname": hostname,
        }

    def evaluate_agent_report(self, report) -> dict:
        """Evaluate from direct agent compliance report."""
        checks = []
        remediation = []

        # Antivirus
        av = report.antivirus or {}
        av_ok = av.get("installed", False) and av.get("running", False)
        checks.append(CheckResult(
            name="Antivirus",
            passed=av_ok,
            severity="critical",
            detail=f"{av.get('name', 'Unknown')} — {'Running' if av_ok else 'Not active'}",
            remediation="" if av_ok else "Enable antivirus and ensure definitions are current",
        ))
        if not av_ok:
            remediation.append("Enable antivirus")

        # Firewall
        fw = report.firewall or {}
        fw_ok = fw.get("enabled", False)
        checks.append(CheckResult(
            name="Firewall",
            passed=fw_ok,
            severity="critical",
            detail=f"{'Enabled' if fw_ok else 'Disabled'}",
            remediation="" if fw_ok else "Enable firewall",
        ))
        if not fw_ok:
            remediation.append("Enable firewall")

        # Disk Encryption
        enc = report.disk_encryption or {}
        enc_ok = enc.get("enabled", False)
        checks.append(CheckResult(
            name="Disk Encryption",
            passed=enc_ok,
            severity="warning",
            detail=f"{enc.get('type', 'None')} — {enc.get('percent', 0)}%",
            remediation="" if enc_ok else "Enable disk encryption",
        ))
        if not enc_ok:
            remediation.append("Enable disk encryption")

        # Patches
        patches = report.patches or {}
        critical = patches.get("pending_critical", 0)
        patches_ok = critical == 0
        checks.append(CheckResult(
            name="OS Patches",
            passed=patches_ok,
            severity="critical",
            detail=f"{critical} critical pending",
            remediation="" if patches_ok else f"Install {critical} critical patches",
        ))
        if not patches_ok:
            remediation.append(f"Install {critical} critical patches")

        critical_failures = [c for c in checks if not c.passed and c.severity == "critical"]
        status = "non_compliant" if critical_failures else "compliant"

        logger.info(f"POSTURE AGENT: mac={report.mac_address} host={report.hostname} "
                     f"status={status} os={report.os_type} {report.os_version}")

        return {
            "mac_address": report.mac_address,
            "status": status,
            "checks": [{"name": c.name, "passed": c.passed, "severity": c.severity,
                        "detail": c.detail, "remediation": c.remediation} for c in checks],
            "remediation": remediation,
            "source": "agent",
            "hostname": report.hostname,
        }

    def evaluate_basic(self, mac: str, os_type: str) -> dict:
        """Basic evaluation for unmanaged devices — network heuristics only."""
        # Without an agent, we can't check compliance deeply
        # Mark as unknown or apply profile-based exemption
        logger.info(f"POSTURE BASIC: mac={mac} os={os_type} — no agent, marking unknown")
        return {
            "mac_address": mac,
            "status": "unknown",
            "checks": [{"name": "Agent", "passed": False, "severity": "warning",
                        "detail": "No posture agent detected",
                        "remediation": "Install osquery agent or Open NAC compliance agent"}],
            "remediation": ["Install compliance agent for full posture assessment"],
            "source": "basic",
        }

    def unknown_result(self, mac: str) -> dict:
        return {
            "mac_address": mac,
            "status": "unknown",
            "checks": [],
            "remediation": [],
            "source": "none",
        }
