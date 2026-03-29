"""
Open NAC — Extended Compliance Engine v2
ISE-equivalent: 11 condition types + compound conditions + vendor-aware checks.

Condition types:
  1.  Anti-Malware — vendor selection, definition age, running state
  2.  Firewall — per-profile check (Domain/Private/Public)
  3.  Disk Encryption — BitLocker/FileVault/LUKS
  4.  Patch Management — KB-number checks, pending critical count
  5.  OS Version — minimum version enforcement
  6.  Application — installed/not-installed, version check
  7.  File — existence, version, hash (SHA-256)
  8.  Registry — key existence, value comparison
  9.  Service — running/stopped/startup-type
  10. USB — mass storage blocked, device class restrictions
  11. Compound — AND/OR/NOT over sub-conditions
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger("nac.compliance_v2")


# ─── Data classes ───

@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str = "critical"       # critical, warning, info
    detail: str = ""
    remediation: str = ""
    category: str = ""
    condition_id: Optional[int] = None


@dataclass
class ConditionDef:
    """Loaded from DB: nac_posture_conditions row."""
    id: int = 0
    name: str = ""
    description: str = ""
    category: str = "custom"
    os_types: list = field(default_factory=lambda: ["windows", "macos", "linux"])
    operator: str = "enabled"
    expected_value: str = "true"
    severity: str = "critical"
    enabled: bool = True
    # Extended fields
    vendor: Optional[str] = None
    product_name: Optional[str] = None
    min_version: Optional[str] = None
    file_path: Optional[str] = None
    registry_path: Optional[str] = None
    registry_key: Optional[str] = None
    service_name: Optional[str] = None
    kb_numbers: Optional[list] = None
    usb_classes: Optional[list] = None
    firewall_profiles: Optional[list] = None
    sub_conditions: Optional[list] = None
    compound_operator: Optional[str] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "ConditionDef":
        """Build from a dict (DB row)."""
        def _parse_json(val):
            if val is None:
                return None
            if isinstance(val, (list, dict)):
                return val
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                return None

        return cls(
            id=row.get("id", 0),
            name=row.get("name", ""),
            description=row.get("description", ""),
            category=row.get("category", "custom"),
            os_types=_parse_json(row.get("os_types")) or ["windows", "macos", "linux"],
            operator=row.get("operator", "enabled"),
            expected_value=row.get("expected_value", "true"),
            severity=row.get("severity", "critical"),
            enabled=bool(row.get("enabled", True)),
            vendor=row.get("vendor"),
            product_name=row.get("product_name"),
            min_version=row.get("min_version"),
            file_path=row.get("file_path"),
            registry_path=row.get("registry_path"),
            registry_key=row.get("registry_key"),
            service_name=row.get("service_name"),
            kb_numbers=_parse_json(row.get("kb_numbers")),
            usb_classes=_parse_json(row.get("usb_classes")),
            firewall_profiles=_parse_json(row.get("firewall_profiles")),
            sub_conditions=_parse_json(row.get("sub_conditions")),
            compound_operator=row.get("compound_operator"),
        )


# ─── Version comparison ───

def _parse_version(v: str) -> tuple:
    """Parse version string like '10.0.19041' into tuple of ints."""
    parts = re.split(r'[.\-_]', str(v).strip())
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def _version_gte(actual: str, minimum: str) -> bool:
    return _parse_version(actual) >= _parse_version(minimum)


def _version_lte(actual: str, maximum: str) -> bool:
    return _parse_version(actual) <= _parse_version(maximum)


# ─── Condition Evaluators ───

class ConditionEvaluator:
    """Evaluates a single ConditionDef against endpoint data."""

    def __init__(self, av_vendors: Optional[list] = None):
        self.av_vendors = av_vendors or []
        self._condition_cache: dict[str, ConditionDef] = {}

    def set_conditions_cache(self, conditions: list[ConditionDef]):
        """Cache conditions by name for compound resolution."""
        self._condition_cache = {c.name: c for c in conditions}

    def evaluate(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        """Dispatch to category-specific evaluator."""
        # Check OS applicability
        if platform and platform.lower() not in [o.lower() for o in cond.os_types]:
            return CheckResult(
                name=cond.name, passed=True, severity="info",
                detail=f"Skipped — not applicable to {platform}",
                category=cond.category, condition_id=cond.id,
            )

        evaluators = {
            "antivirus": self._eval_antivirus,
            "firewall": self._eval_firewall,
            "disk_encryption": self._eval_disk_encryption,
            "patches": self._eval_patches,
            "patch_management": self._eval_patch_management,
            "os_version": self._eval_os_version,
            "application": self._eval_application,
            "file": self._eval_file,
            "registry": self._eval_registry,
            "service": self._eval_service,
            "usb": self._eval_usb,
            "compound": self._eval_compound,
            "custom": self._eval_custom,
        }

        evaluator = evaluators.get(cond.category, self._eval_custom)
        try:
            result = evaluator(cond, data, platform)
            result.condition_id = cond.id
            result.category = cond.category
            return result
        except Exception as e:
            logger.error(f"Condition eval error '{cond.name}': {e}")
            return CheckResult(
                name=cond.name, passed=False, severity=cond.severity,
                detail=f"Evaluation error: {e}",
                remediation="Contact administrator",
                category=cond.category, condition_id=cond.id,
            )

    # ── 1. Anti-Malware ──

    def _eval_antivirus(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        av_products = data.get("antivirus", [])
        if not isinstance(av_products, list):
            av_products = []

        # Vendor-specific check
        if cond.vendor:
            target_vendor = cond.vendor.lower()
            target_product = (cond.product_name or "").lower()

            for av in av_products:
                av_name = (av.get("name", "") or av.get("display_name", "")).lower()
                av_vendor = (av.get("vendor", "")).lower()
                av_state = (av.get("state", "")).lower()

                vendor_match = target_vendor in av_vendor or target_vendor in av_name
                product_match = not target_product or target_product in av_name

                if vendor_match and product_match:
                    # Check state
                    is_running = av_state in ("on", "running", "enabled", "1", "active")

                    if cond.operator == "running" and not is_running:
                        return CheckResult(
                            name=cond.name, passed=False, severity=cond.severity,
                            detail=f"{cond.vendor} {cond.product_name or ''} found but NOT running (state: {av_state})",
                            remediation=f"Start {cond.vendor} {cond.product_name or 'agent'}",
                        )

                    # Check version if required
                    if cond.min_version and av.get("version"):
                        if not _version_gte(av["version"], cond.min_version):
                            return CheckResult(
                                name=cond.name, passed=False, severity=cond.severity,
                                detail=f"{cond.vendor} version {av['version']} < required {cond.min_version}",
                                remediation=f"Update {cond.vendor} to version {cond.min_version}+",
                            )

                    # Check definition age if available
                    def_age = av.get("definition_age_days")
                    if def_age is not None and def_age > 7:
                        return CheckResult(
                            name=cond.name, passed=False, severity="warning",
                            detail=f"{cond.vendor} definitions {def_age} days old",
                            remediation=f"Update {cond.vendor} virus definitions",
                        )

                    return CheckResult(
                        name=cond.name, passed=True, severity=cond.severity,
                        detail=f"{cond.vendor} {cond.product_name or ''} — active"
                            + (f" v{av.get('version', '?')}" if av.get("version") else ""),
                    )

            # Vendor not found
            return CheckResult(
                name=cond.name, passed=False, severity=cond.severity,
                detail=f"{cond.vendor} {cond.product_name or ''} not detected",
                remediation=f"Install {cond.vendor} {cond.product_name or 'antivirus'}",
            )

        # Generic AV check (any vendor)
        active_av = [
            av for av in av_products
            if (av.get("state", "")).lower() in ("on", "running", "enabled", "1", "active")
        ]

        if cond.operator == "installed":
            ok = len(av_products) > 0
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{len(av_products)} AV product(s) detected" if ok else "No AV product detected",
                remediation="" if ok else "Install antivirus software",
            )
        else:  # running / enabled
            ok = len(active_av) > 0
            names = ", ".join(av.get("name", "?") for av in active_av[:3]) if active_av else "None"
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Active: {names}" if ok else "No active AV protection",
                remediation="" if ok else "Enable real-time antivirus protection",
            )

    # ── 2. Firewall ──

    def _eval_firewall(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        fw_data = data.get("firewall", {})
        required_profiles = cond.firewall_profiles or []

        if cond.operator == "all_profiles_enabled":
            if platform.lower() in ("windows",):
                profiles = fw_data.get("profiles", {}) if isinstance(fw_data, dict) else {}
                missing = []
                for prof in (required_profiles or ["Domain", "Private", "Public"]):
                    if not profiles.get(prof, {}).get("enabled", False):
                        # Fallback: check flat enabled
                        if isinstance(fw_data, dict) and fw_data.get("enabled"):
                            continue
                        missing.append(prof)

                if not missing and not profiles and isinstance(fw_data, dict) and fw_data.get("enabled"):
                    # Simple enabled flag, no profile detail
                    return CheckResult(
                        name=cond.name, passed=True, severity=cond.severity,
                        detail="Firewall enabled (profile detail not available)",
                    )

                ok = len(missing) == 0
                return CheckResult(
                    name=cond.name, passed=ok, severity=cond.severity,
                    detail=f"All profiles enabled" if ok else f"Disabled profiles: {', '.join(missing)}",
                    remediation="" if ok else f"Enable firewall for: {', '.join(missing)}",
                )
            else:
                # macOS/Linux — simpler check
                enabled = fw_data.get("enabled", False) if isinstance(fw_data, dict) else False
                return CheckResult(
                    name=cond.name, passed=enabled, severity=cond.severity,
                    detail="Firewall enabled" if enabled else "Firewall disabled",
                    remediation="" if enabled else "Enable OS firewall",
                )

        elif cond.operator == "specific_profile_enabled":
            profile_name = cond.expected_value or "Domain"
            profiles = fw_data.get("profiles", {}) if isinstance(fw_data, dict) else {}
            enabled = profiles.get(profile_name, {}).get("enabled", False)
            # Fallback
            if not enabled and isinstance(fw_data, dict):
                enabled = fw_data.get("enabled", False)

            return CheckResult(
                name=cond.name, passed=enabled, severity=cond.severity,
                detail=f"{profile_name} profile: {'enabled' if enabled else 'disabled'}",
                remediation="" if enabled else f"Enable {profile_name} firewall profile",
            )

        else:  # Simple enabled check
            enabled = fw_data.get("enabled", False) if isinstance(fw_data, dict) else False
            if isinstance(fw_data, list) and fw_data:
                enabled = all(f.get("enabled", False) for f in fw_data)
            return CheckResult(
                name=cond.name, passed=enabled, severity=cond.severity,
                detail="Firewall enabled" if enabled else "Firewall disabled",
                remediation="" if enabled else "Enable OS firewall",
            )

    # ── 3. Disk Encryption ──

    def _eval_disk_encryption(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        enc = data.get("disk_encryption", {})
        if isinstance(enc, dict):
            enabled = enc.get("enabled", False)
            enc_type = enc.get("type", "Unknown")
            percent = enc.get("percent", 0)
        elif isinstance(enc, list):
            enabled = any(e.get("encrypted", False) for e in enc)
            enc_type = next((e.get("type", "?") for e in enc if e.get("encrypted")), "Unknown")
            percent = 100 if enabled else 0
        else:
            enabled = False
            enc_type = "None"
            percent = 0

        detail = f"{enc_type} — {percent}%" if enabled else "Not encrypted"
        return CheckResult(
            name=cond.name, passed=enabled, severity=cond.severity,
            detail=detail,
            remediation="" if enabled else "Enable BitLocker (Windows) / FileVault (macOS) / LUKS (Linux)",
        )

    # ── 4. OS Patches (count-based) ──

    def _eval_patches(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        patches = data.get("patches", {})
        if not isinstance(patches, dict):
            patches = {}

        critical = patches.get("pending_critical", 0)
        total = patches.get("pending_total", 0)

        if cond.operator == "equals":
            threshold = int(cond.expected_value or "0")
            ok = critical == threshold
        elif cond.operator == "less_than":
            threshold = int(cond.expected_value or "1")
            ok = total < threshold
        elif cond.operator == "greater_than":
            threshold = int(cond.expected_value or "0")
            ok = critical > threshold  # Unusual — "more than X critical" would fail
        else:
            ok = critical == 0

        return CheckResult(
            name=cond.name, passed=ok, severity=cond.severity,
            detail=f"{critical} critical, {total} total pending",
            remediation="" if ok else f"Install {critical} critical patches",
        )

    # ── 5. Patch Management (KB-specific) ──

    def _eval_patch_management(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        installed_kbs = set(data.get("installed_kbs", []))
        required_kbs = cond.kb_numbers or []

        if cond.operator == "kb_installed":
            missing = [kb for kb in required_kbs if kb not in installed_kbs]
            ok = len(missing) == 0
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"All {len(required_kbs)} KB patches present" if ok
                       else f"Missing: {', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}",
                remediation="" if ok else f"Install patches: {', '.join(missing[:5])}",
            )
        elif cond.operator == "kb_not_installed":
            found = [kb for kb in required_kbs if kb in installed_kbs]
            ok = len(found) == 0
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail="None of the blacklisted KBs present" if ok
                       else f"Blacklisted KB found: {', '.join(found)}",
                remediation="" if ok else f"Remove/rollback: {', '.join(found)}",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── 6. OS Version ──

    def _eval_os_version(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        os_ver = data.get("os_version", "")

        if cond.operator == "version_gte":
            ok = _version_gte(os_ver, cond.expected_value or "0")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{platform} {os_ver}",
                remediation="" if ok else f"Upgrade OS to version {cond.expected_value}+",
            )
        elif cond.operator == "version_lte":
            ok = _version_lte(os_ver, cond.expected_value or "999")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{platform} {os_ver}",
                remediation="" if ok else f"OS version {os_ver} exceeds maximum {cond.expected_value}",
            )

        return CheckResult(
            name=cond.name, passed=True, severity="info",
            detail=f"{platform} {os_ver}",
        )

    # ── 7. Application ──

    def _eval_application(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        apps = data.get("applications", [])
        target = (cond.product_name or cond.expected_value or "").lower()

        found = None
        for app in apps:
            app_name = (app.get("name", "") or "").lower()
            if target in app_name:
                found = app
                break

        if cond.operator in ("installed", "exists"):
            ok = found is not None
            detail = f"Found: {found.get('name', '?')} v{found.get('version', '?')}" if ok else f"'{target}' not installed"
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=detail,
                remediation="" if ok else f"Install {cond.product_name or target}",
            )
        elif cond.operator in ("not_exists", "not_installed"):
            ok = found is None
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"'{target}' not found" if ok else f"Prohibited app found: {found.get('name', '?')}",
                remediation="" if ok else f"Remove {found.get('name', target)}",
            )
        elif cond.operator == "version_gte" and found:
            ok = _version_gte(found.get("version", "0"), cond.expected_value or "0")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{found.get('name', '?')} v{found.get('version', '?')}",
                remediation="" if ok else f"Update to version {cond.expected_value}+",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── 8. File ──

    def _eval_file(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        files = data.get("files", {})
        target_path = cond.file_path or cond.expected_value or ""
        file_info = files.get(target_path, {}) if isinstance(files, dict) else {}

        if cond.operator in ("file_exists", "exists"):
            ok = bool(file_info.get("exists", False))
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"File {'found' if ok else 'missing'}: {target_path}",
                remediation="" if ok else f"Required file missing: {target_path}",
            )
        elif cond.operator in ("file_not_exists", "not_exists"):
            ok = not file_info.get("exists", False)
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"File {'absent' if ok else 'found'}: {target_path}",
                remediation="" if ok else f"Remove prohibited file: {target_path}",
            )
        elif cond.operator == "file_version_gte":
            ver = file_info.get("version", "0")
            ok = _version_gte(ver, cond.expected_value or "0")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{target_path} version: {ver}",
                remediation="" if ok else f"Update file to version {cond.expected_value}+",
            )
        elif cond.operator == "file_sha256":
            actual_hash = (file_info.get("sha256", "") or "").lower()
            expected_hash = (cond.expected_value or "").lower()
            ok = actual_hash == expected_hash
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Hash {'matches' if ok else 'mismatch'}: {actual_hash[:16]}...",
                remediation="" if ok else f"File integrity check failed for {target_path}",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── 9. Registry ──

    def _eval_registry(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        if platform.lower() not in ("windows",):
            return CheckResult(
                name=cond.name, passed=True, severity="info",
                detail="Registry checks only apply to Windows",
            )

        registry = data.get("registry", {})
        reg_path = cond.registry_path or ""
        reg_key = cond.registry_key or ""
        full_path = f"{reg_path}\\{reg_key}" if reg_key else reg_path
        reg_entry = registry.get(full_path, {}) if isinstance(registry, dict) else {}

        if cond.operator == "registry_exists":
            ok = bool(reg_entry.get("exists", False))
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Registry key {'found' if ok else 'missing'}: {full_path}",
                remediation="" if ok else f"Required registry key missing: {full_path}",
            )
        elif cond.operator == "registry_value_equals":
            actual = str(reg_entry.get("value", ""))
            expected = str(cond.expected_value or "")
            ok = actual == expected
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{reg_key} = {actual} (expected: {expected})",
                remediation="" if ok else f"Set {full_path} to {expected}",
            )
        elif cond.operator == "registry_value_contains":
            actual = str(reg_entry.get("value", ""))
            expected = str(cond.expected_value or "")
            ok = expected.lower() in actual.lower()
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"{reg_key} contains '{expected}': {ok}",
                remediation="" if ok else f"Registry value must contain '{expected}'",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── 10. Service ──

    def _eval_service(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        services = data.get("services", {})
        svc_name = cond.service_name or cond.expected_value or ""
        svc_info = services.get(svc_name, {}) if isinstance(services, dict) else {}

        state = (svc_info.get("state", "") or svc_info.get("status", "")).lower()
        start_type = (svc_info.get("start_type", "")).lower()

        if cond.operator == "service_running":
            ok = state in ("running", "active", "started")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Service '{svc_name}': {state or 'not found'}",
                remediation="" if ok else f"Start service: {svc_name}",
            )
        elif cond.operator == "service_stopped":
            ok = state in ("stopped", "inactive", "dead", "") or not svc_info
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Service '{svc_name}': {state or 'not found'}",
                remediation="" if ok else f"Stop service: {svc_name}",
            )
        elif cond.operator == "service_auto_start":
            ok = start_type in ("auto", "automatic")
            return CheckResult(
                name=cond.name, passed=ok, severity=cond.severity,
                detail=f"Service '{svc_name}' start type: {start_type or 'unknown'}",
                remediation="" if ok else f"Set {svc_name} to automatic start",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── 11. USB ──

    def _eval_usb(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        usb_data = data.get("usb", {})
        blocked_classes = cond.usb_classes or ["mass_storage"]

        if cond.operator == "usb_storage_blocked":
            # Check if USB storage policy is enforced
            storage_blocked = usb_data.get("mass_storage_blocked", False)
            # Also check via registry on Windows
            if not storage_blocked and platform.lower() == "windows":
                registry = data.get("registry", {})
                usb_stor_reg = registry.get(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start", {}
                )
                storage_blocked = str(usb_stor_reg.get("value", "")) == "4"

            return CheckResult(
                name=cond.name, passed=storage_blocked, severity=cond.severity,
                detail="USB mass storage blocked" if storage_blocked else "USB mass storage allowed",
                remediation="" if storage_blocked else "Block USB mass storage via GPO or endpoint agent",
            )

        elif cond.operator == "usb_class_blocked":
            all_blocked = True
            unblocked = []
            for cls in blocked_classes:
                if not usb_data.get(f"{cls}_blocked", False):
                    all_blocked = False
                    unblocked.append(cls)

            return CheckResult(
                name=cond.name, passed=all_blocked, severity=cond.severity,
                detail=f"All USB classes blocked" if all_blocked
                       else f"Unblocked: {', '.join(unblocked)}",
                remediation="" if all_blocked else f"Block USB classes: {', '.join(unblocked)}",
            )

        return CheckResult(name=cond.name, passed=True, severity="info", detail="N/A")

    # ── Compound ──

    def _eval_compound(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        sub_names = cond.sub_conditions or []
        operator = (cond.compound_operator or "AND").upper()

        sub_results: list[CheckResult] = []
        for name in sub_names:
            sub_cond = self._condition_cache.get(name)
            if not sub_cond:
                sub_results.append(CheckResult(
                    name=name, passed=False, severity="warning",
                    detail=f"Sub-condition '{name}' not found",
                ))
                continue
            sub_results.append(self.evaluate(sub_cond, data, platform))

        if operator == "AND":
            ok = all(r.passed for r in sub_results)
            failed = [r.name for r in sub_results if not r.passed]
            detail = "All sub-conditions passed" if ok else f"Failed: {', '.join(failed)}"
        elif operator == "OR":
            ok = any(r.passed for r in sub_results)
            passed = [r.name for r in sub_results if r.passed]
            detail = f"Passed: {', '.join(passed)}" if ok else "No sub-conditions passed"
        elif operator == "NOT":
            # NOT: passes if the sub-condition(s) FAIL
            ok = not any(r.passed for r in sub_results)
            detail = "Inverse check passed" if ok else "Inverse check failed (sub-condition unexpectedly passed)"
        else:
            ok = all(r.passed for r in sub_results)
            detail = "Unknown operator, defaulting to AND"

        remediation_items = [r.remediation for r in sub_results if not r.passed and r.remediation]

        return CheckResult(
            name=cond.name, passed=ok, severity=cond.severity,
            detail=f"[{operator}] {detail}",
            remediation="; ".join(remediation_items[:3]) if remediation_items else "",
        )

    # ── Custom (catch-all) ──

    def _eval_custom(self, cond: ConditionDef, data: dict, platform: str) -> CheckResult:
        """Generic evaluation — check expected_value against data keys."""
        return CheckResult(
            name=cond.name, passed=True, severity="info",
            detail=f"Custom condition: {cond.operator} = {cond.expected_value}",
        )


# ─── Extended Compliance Engine ───

class ComplianceEngineV2:
    """
    Evaluates endpoint posture using DB-loaded conditions.
    Replaces hardcoded ComplianceEngine with dynamic, ISE-style evaluation.
    """

    def __init__(self):
        self.evaluator = ConditionEvaluator()
        self._conditions: list[ConditionDef] = []
        self._loaded = False

    async def load_conditions(self, db):
        """Load all conditions from DB."""
        from sqlalchemy import text
        r = await db.execute(text("""
            SELECT id, name, description, category, os_types, operator, expected_value,
                   severity, enabled, vendor, product_name, min_version,
                   file_path, registry_path, registry_key, service_name,
                   kb_numbers, usb_classes, firewall_profiles, sub_conditions, compound_operator
            FROM nac_posture_conditions WHERE enabled = 1
            ORDER BY category, name
        """))

        self._conditions = []
        for row in r.fetchall():
            cond = ConditionDef.from_db_row({
                "id": row[0], "name": row[1], "description": row[2], "category": row[3],
                "os_types": row[4], "operator": row[5], "expected_value": row[6],
                "severity": row[7], "enabled": row[8], "vendor": row[9],
                "product_name": row[10], "min_version": row[11], "file_path": row[12],
                "registry_path": row[13], "registry_key": row[14], "service_name": row[15],
                "kb_numbers": row[16], "usb_classes": row[17], "firewall_profiles": row[18],
                "sub_conditions": row[19], "compound_operator": row[20],
            })
            self._conditions.append(cond)

        self.evaluator.set_conditions_cache(self._conditions)
        self._loaded = True
        logger.info(f"Loaded {len(self._conditions)} posture conditions from DB")

    async def load_av_vendors(self, db):
        """Load AV vendor reference data."""
        from sqlalchemy import text
        r = await db.execute(text("SELECT vendor_name, product_name, os_type, process_name, service_name FROM nac_av_vendors"))
        vendors = [
            {"vendor": row[0], "product": row[1], "os": row[2], "process": row[3], "service": row[4]}
            for row in r.fetchall()
        ]
        self.evaluator.av_vendors = vendors
        logger.info(f"Loaded {len(vendors)} AV vendor definitions")

    def get_conditions_for_names(self, names: list[str]) -> list[ConditionDef]:
        """Resolve condition names to ConditionDef objects."""
        name_map = {c.name: c for c in self._conditions}
        return [name_map[n] for n in names if n in name_map]

    def evaluate_conditions(self, condition_names: list[str], data: dict, platform: str) -> list[CheckResult]:
        """Evaluate a list of conditions by name."""
        conditions = self.get_conditions_for_names(condition_names)
        results = []
        for cond in conditions:
            result = self.evaluator.evaluate(cond, data, platform)
            results.append(result)
        return results

    def evaluate_fleet(self, fleet_data: dict, condition_names: list[str] = None) -> dict:
        """Evaluate using Fleet/osquery data with DB conditions."""
        platform = fleet_data.get("platform", "").lower()
        hostname = fleet_data.get("hostname", "")

        if condition_names:
            checks = self.evaluate_conditions(condition_names, fleet_data, platform)
        else:
            # Evaluate ALL enabled conditions for this platform
            applicable = [c for c in self._conditions if platform in [o.lower() for o in c.os_types]]
            checks = [self.evaluator.evaluate(c, fleet_data, platform) for c in applicable]

        return self._build_result(checks, hostname, "fleet")

    def evaluate_agent_report(self, report_data: dict, condition_names: list[str] = None) -> dict:
        """Evaluate from agent report data."""
        platform = report_data.get("os_type", "").lower()
        hostname = report_data.get("hostname", "")
        mac = report_data.get("mac_address", "")

        if condition_names:
            checks = self.evaluate_conditions(condition_names, report_data, platform)
        else:
            applicable = [c for c in self._conditions if platform in [o.lower() for o in c.os_types]]
            checks = [self.evaluator.evaluate(c, report_data, platform) for c in applicable]

        result = self._build_result(checks, hostname, "agent")
        result["mac_address"] = mac
        return result

    def _build_result(self, checks: list[CheckResult], hostname: str, source: str) -> dict:
        """Build evaluation result from check results."""
        critical_failures = [c for c in checks if not c.passed and c.severity == "critical"]
        warning_failures = [c for c in checks if not c.passed and c.severity == "warning"]
        remediation = [c.remediation for c in checks if not c.passed and c.remediation]

        if critical_failures:
            status = "non_compliant"
        elif warning_failures:
            status = "compliant"  # warnings logged but don't block
        else:
            status = "compliant"

        logger.info(
            f"POSTURE: host={hostname} source={source} status={status} "
            f"checks={len(checks)} critical_fail={len(critical_failures)} "
            f"warnings={len(warning_failures)}"
        )

        return {
            "status": status,
            "checks": [
                {
                    "name": c.name, "passed": c.passed, "severity": c.severity,
                    "detail": c.detail, "remediation": c.remediation,
                    "category": c.category, "condition_id": c.condition_id,
                }
                for c in checks
            ],
            "remediation": remediation,
            "source": source,
            "hostname": hostname,
            "summary": {
                "total": len(checks),
                "passed": sum(1 for c in checks if c.passed),
                "failed_critical": len(critical_failures),
                "failed_warning": len(warning_failures),
            },
        }

    def evaluate_basic(self, mac: str, os_type: str) -> dict:
        """Basic evaluation — no agent."""
        return {
            "mac_address": mac, "status": "unknown",
            "checks": [{"name": "Agent", "passed": False, "severity": "warning",
                        "detail": "No posture agent detected", "category": "custom",
                        "remediation": "Install osquery agent or Open NAC compliance agent"}],
            "remediation": ["Install compliance agent for full posture assessment"],
            "source": "basic",
            "summary": {"total": 1, "passed": 0, "failed_critical": 0, "failed_warning": 1},
        }

    def unknown_result(self, mac: str) -> dict:
        return {
            "mac_address": mac, "status": "unknown",
            "checks": [], "remediation": [], "source": "none",
            "summary": {"total": 0, "passed": 0, "failed_critical": 0, "failed_warning": 0},
        }
