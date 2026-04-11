"""
Centralized constants for the Vigilis enrichment engine.

All magic numbers, thresholds, and mappings that were previously
scattered across services are collected here for easy tuning.
"""

# ── Confidence Score Thresholds ────────────────────────
CONFIDENCE_CRITICAL = 85   # Score >= this → "critical" label
CONFIDENCE_HIGH = 60       # Score >= this → "high" label
CONFIDENCE_MEDIUM = 30     # Score >= this → "medium" label
# Below CONFIDENCE_MEDIUM → "low" label

# ── Incident Correlation ──────────────────────────────
LINK_THRESHOLD = 2                  # Minimum link strength to merge cases
SPRAY_MIN_USERS = 3                 # Minimum distinct users for spray detection
MIN_CONFIDENCE_FOR_INCIDENT = 60    # Cases below this are excluded from clustering
HIGH_VOLUME_MIN_ALERTS = 5          # Minimum alerts for single-stage pattern incident
HIGH_VOLUME_MIN_SCORE = 70          # Minimum score for pattern incidents

# ── Grouping ──────────────────────────────────────────
DEDUP_WINDOW_MINUTES = 10           # Fingerprint dedup window within groups
ADAPTIVE_BOUNDARY_MINUTES = 5       # Fuzzy boundary for adaptive time buckets

# ── Upload / Ingestion Caps ───────────────────────────
MAX_UPLOAD_ROWS = 2000              # Maximum rows per file upload
MAX_BATCH_ALERTS = 2000             # Maximum alerts per batch enrich
MAX_WEBHOOK_BATCH = 100             # Maximum alerts per webhook batch

# ── Kill-Chain Stage Ordering ─────────────────────────
KILL_CHAIN_STAGES = [
    "reconnaissance",
    "initial_access",
    "credential_access",
    "privilege_escalation",
    "execution",
    "persistence",
    "lateral_movement",
    "collection",
    "exfiltration",
]

# ── Alert Type → Kill-Chain Stage Mapping ─────────────
ALERT_TYPE_TO_STAGE: dict[str, str] = {
    "email.forwardingRule": "persistence",
    "email.phishingDetected": "initial_access",
    "identity.suspiciousSignIn": "initial_access",
    "identity.passwordSpray": "credential_access",
    "identity.mfaFatigue": "credential_access",
    "identity.oauthConsentRisk": "credential_access",
    "identity.privilegeElevation": "privilege_escalation",
    "endpoint.malwareDetection": "execution",
    "endpoint.suspiciousProcess": "execution",
    "cloud.secretStoreAccessAnomaly": "exfiltration",
    "cloud.iamPrivilegeEscalation": "privilege_escalation",
    "cloud.suspiciousApiCall": "execution",
    "network.impossibleGeoAccess": "lateral_movement",
    "network.dataExfiltration": "exfiltration",
}

# ── Severity Ranking ──────────────────────────────────
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ── Supported Source Systems ──────────────────────────
VALID_SOURCE_SYSTEMS = {"idp", "edr", "email", "cloud", "network", "custom"}
