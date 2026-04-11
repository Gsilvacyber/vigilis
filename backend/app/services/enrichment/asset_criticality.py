"""Asset criticality and user risk scoring for the Vigilis enrichment engine.

WHY THIS EXISTS: A compromised domain controller should score 20 points higher
than a compromised dev laptop. A CEO's account should score higher than an
intern's. Elite SOC teams (Mandiant, CrowdStrike IR) always factor in business
impact — Vigilis now does too.

ARCHITECTURE:
  - Asset criticality: detected from hostname patterns + device context
  - User risk tier: detected from identity patterns + HR context flags
  - Both return integer weights added directly to the confidence score
  - Both are computed ONCE per case in compute_confidence(), not per-signal

CUSTOMIZATION: Customers can override the hostname patterns and tier weights
via /api/v1/config/asset-criticality (future endpoint).
"""
from __future__ import annotations

import re as _re
from typing import Any


# ── Asset Criticality Tiers ───────────────────────────────────────────
# Weight added to confidence score based on target asset importance.
# A domain controller compromise automatically scores 20 points higher
# than a dev laptop — matching how elite SOC teams prioritize.

_ASSET_TIERS: dict[str, int] = {
    "critical": 20,    # Domain controllers, SCADA, payment systems, CA servers
    "high": 12,         # Production servers, executive devices, HR systems
    "standard": 0,      # Regular workstations, standard user accounts
    "low": -5,          # Dev/test, sandbox, monitoring accounts
}

# Hostname patterns for asset tier detection (case-insensitive)
_CRITICAL_PATTERNS = _re.compile(
    r"(^dc[-_.]|^ad[-_.]|^ca[-_.]|^pki[-_.]|^scada[-_.]|^hmi[-_.]|^plc[-_.]"
    r"|^pci[-_.]|^pay[-_.]|^sql[-_.]prod|^db[-_.]prod|^exchange[-_.]"
    r"|^krbtgt|domain.?controller|certificate.?authority)",
    _re.IGNORECASE,
)
_HIGH_PATTERNS = _re.compile(
    r"(^srv[-_.]|^prod[-_.]|^server[-_.]|^exec[-_.]|^hr[-_.]|^fin[-_.]"
    r"|^erp[-_.]|^sap[-_.]|^citrix[-_.]|^vpn[-_.]|^jump[-_.]|^bastion[-_.]"
    r"|^trader[-_.]|^trading[-_.]|^trad[-_.]|^treasury[-_.]|^pay[-_.]|^billing[-_.]"
    r"|^file[-_.]|^fs[-_.]|^nas[-_.]|^backup[-_.]|^db[-_.]|^sql[-_.]|^mail[-_.])",
    _re.IGNORECASE,
)
_LOW_PATTERNS = _re.compile(
    r"(^dev[-_.]|^test[-_.]|^sandbox[-_.]|^staging[-_.]|^lab[-_.]"
    r"|^demo[-_.]|^tmp[-_.]|^build[-_.])",
    _re.IGNORECASE,
)


def compute_asset_criticality(raw: dict[str, Any]) -> tuple[int, str]:
    """Detect asset criticality tier from device hostname and context.

    Returns (weight, tier_name). Weight is added directly to the confidence
    score. Tier name is included in enrichment notes for analyst context.
    """
    device = raw.get("device") or {}
    hostname = (device.get("hostname") or "").strip()

    # Check structured field first (if explicitly set by source tool)
    explicit_tier = (raw.get("_assetCriticality") or "").lower().strip()
    if explicit_tier in _ASSET_TIERS:
        return _ASSET_TIERS[explicit_tier], explicit_tier

    # Hostname pattern detection
    if hostname:
        if _CRITICAL_PATTERNS.search(hostname):
            return _ASSET_TIERS["critical"], "critical"
        if _HIGH_PATTERNS.search(hostname):
            return _ASSET_TIERS["high"], "high"
        if _LOW_PATTERNS.search(hostname):
            return _ASSET_TIERS["low"], "low"

    # Device type from structured fields (IoT/OT context)
    device_type = (raw.get("_deviceType") or "").lower()
    if device_type:
        if any(kw in device_type for kw in ("plc", "scada", "hmi", "rtu", "controller")):
            return _ASSET_TIERS["critical"], "critical"
        if any(kw in device_type for kw in ("server", "appliance", "firewall", "switch")):
            return _ASSET_TIERS["high"], "high"
        if any(kw in device_type for kw in ("printer", "camera", "iot", "sensor")):
            return _ASSET_TIERS["high"], "high"

    # Safety level from IoT/OT context (SIL-rated = always critical)
    safety = (raw.get("_safetyLevel") or "").lower()
    if "sil" in safety:
        return _ASSET_TIERS["critical"], "critical"

    # Default: standard (no weight adjustment)
    return _ASSET_TIERS["standard"], "standard"


# ── User Risk Tier ────────────────────────────────────────────────────
# Lightweight UEBA proxy: detects user risk from identity context and
# HR flags without requiring a 60-day behavioral baseline.

_USER_RISK_TIERS: dict[str, int] = {
    "critical_user": 15,   # C-suite, CISO — highest value targets
    "high_risk_user": 10,  # Admin accounts, users with resignation on file
    "standard_user": 0,    # Regular employees
    "low_risk_user": -5,   # Monitoring accounts, system accounts
}

_EXECUTIVE_PATTERNS = _re.compile(
    r"(^ceo[@.\b_-]|^cfo[@.\b_-]|^cto[@.\b_-]|^ciso[@.\b_-]|^coo[@.\b_-]"
    r"|^cmo[@.\b_-]|^cpo[@.\b_-]|^svp[@.\b_-]|^evp[@.\b_-]"
    r"|chief.?(executive|financial|technology|information|security|operating))",
    _re.IGNORECASE,
)


def compute_user_risk(raw: dict[str, Any]) -> tuple[int, str]:
    """Detect user risk tier from identity context and HR flags.

    Returns (weight, tier_name). Weight is added directly to the confidence
    score. Tier name is included in enrichment notes.
    """
    identity = raw.get("identity") or {}
    upn = identity.get("upn") or ""
    display = identity.get("displayName") or ""
    combined = f"{upn} {display}"

    # Check HR flags first (highest confidence)
    if raw.get("_insiderResignation") is True:
        return _USER_RISK_TIERS["high_risk_user"], "high_risk_user"

    # C-suite detection
    if _EXECUTIVE_PATTERNS.search(combined):
        return _USER_RISK_TIERS["critical_user"], "critical_user"

    # Title-based detection
    title_lower = display.lower()
    if any(t in title_lower for t in ("chief ", "officer", "president", "director")):
        return _USER_RISK_TIERS["critical_user"], "critical_user"

    # Admin accounts (already detected by is_privileged_identity, but
    # we add user risk on top for the scoring boost)
    priv_tier = identity.get("privilegeTier")
    if priv_tier in ("admin", "privileged"):
        return _USER_RISK_TIERS["high_risk_user"], "high_risk_user"

    # Monitoring / system accounts (low risk — routine activity)
    if priv_tier in ("service", "service_account"):
        return _USER_RISK_TIERS["low_risk_user"], "low_risk_user"

    # Check for monitoring account patterns
    monitoring_patterns = ("monitor", "health", "watchdog", "nagios", "datadog", "newrelic")
    if any(p in upn.lower() for p in monitoring_patterns):
        return _USER_RISK_TIERS["low_risk_user"], "low_risk_user"

    return _USER_RISK_TIERS["standard_user"], "standard_user"
