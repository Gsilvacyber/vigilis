"""Staged ingestion pipeline: parse, detect source, map columns, validate rows.

This module sits between file upload and the enrichment engine,
providing a dry-run preview step before any cases are created.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.app.services.suppression_service import evaluate_suppression
from backend.app.services.alert_mapper import (
    _ALERT_NAME_FIELDS,
    _DEVICE_FIELDS,
    _EMAIL_METADATA_FIELDS,
    _FILE_PATH_FIELDS,
    _GEO_FIELDS,
    _IDENTITY_FIELDS,
    _IP_FIELDS,
    _DEST_IP_FIELDS,
    _PROCESS_FIELDS,
    _SEVERITY_FIELDS,
    extract_event_time,
    guess_alert_type,
    map_row_to_raw_alert,
    parse_severity,
)
from backend.app.services.grouping import (
    AlertGroup,
    EnrichedAlert,
    build_grouped_case,
    group_enriched_alerts,
)
from backend.app.services.normalizer import normalize_case_from_request


# ── JSON flattening ──────────────────────────────────────────────────────

def flatten_row(row: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Recursively flatten nested dicts into dot-notation keys.

    Example: {"user": {"name": "alice", "id": 1}} ->
             {"user.name": "alice", "user.id": 1}

    Arrays are handled smartly:
    - List of dicts: flatten the first element (common in UDM securityResult)
    - List of strings/primitives: extract first element as scalar value
    - Empty list: store as empty string
    """
    flat: dict[str, Any] = {}
    for k, v in row.items():
        full_key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            flat.update(flatten_row(v, full_key))
        elif isinstance(v, list):
            if not v:
                flat[full_key] = ""
            elif isinstance(v[0], dict):
                # Array of objects (e.g., securityResult): flatten first element
                flat.update(flatten_row(v[0], full_key))
            elif isinstance(v[0], str):
                # Array of strings: keep first for identity fields (email),
                # join all for multi-value fields (scopes, recipients)
                if len(v) == 1:
                    flat[full_key] = v[0]
                else:
                    flat[full_key] = ", ".join(v)
            else:
                # Array of other primitives: take first
                flat[full_key] = v[0]
        else:
            flat[full_key] = v
    return flat

# ── Source profiles ──────────────────────────────────────────────────────

_SOURCE_PROFILES: dict[str, dict[str, Any]] = {
    "splunk": {
        "label": "Splunk CSV Export",
        "signature_fields": {"_time", "src_ip", "dest_ip", "src_user", "action", "signature"},
        "min_match": 3,
    },
    "sentinel": {
        "label": "Microsoft Sentinel / Defender",
        "signature_fields": {
            "timegenerated", "userprincipalname", "ipaddress",
            "alertseverity", "alertname", "tenantid",
        },
        "min_match": 3,
    },
    "crowdstrike": {
        "label": "CrowdStrike Falcon",
        "signature_fields": {"aid", "cid", "detectid", "machinedomain", "filename"},
        "min_match": 3,
    },
    "qradar": {
        "label": "IBM QRadar",
        "signature_fields": {"starttime", "sourceip", "logsourceid", "magnitude", "eventcount"},
        "min_match": 3,
    },
    "google_secops": {
        "label": "Google SecOps / Chronicle (UDM)",
        "signature_fields": {
            "metadata.event_timestamp", "metadata.event_type",
            "metadata.vendor_name", "metadata.product_name",
            "principal.ip", "principal.hostname",
            "principal.user.userid", "principal.user.email_addresses",
            "securityresult.severity",
        },
        "min_match": 4,
    },
}


@dataclass
class ColumnMapping:
    source_column: str
    canonical_field: str  # identity | ip | dest_ip | device | severity | alert_name | process | file_path | geo | email_metadata | unmapped
    confidence: float  # 0.0 - 1.0
    reason: str


@dataclass
class SourceProfile:
    detected: str  # profile key or "unknown"
    label: str
    confidence: float
    matched_fields: list[str]


@dataclass
class RowValidation:
    index: int
    valid: bool
    reasons: list[str]  # empty if valid
    detected_alert_type: str | None = None
    detected_severity: str | None = None


@dataclass
class UploadPreview:
    """Returned by dry-run: everything the UI needs to show before processing."""
    filename: str
    file_format: str  # csv | json | jsonl
    total_rows: int
    columns: list[str]
    source_profile: SourceProfile
    column_mappings: list[ColumnMapping]
    sample_rows: list[dict[str, Any]]  # first 5 rows raw
    row_validations: list[RowValidation]
    summary: dict[str, Any]  # rollup counts


@dataclass
class EnrichedRow:
    index: int
    alert_type: str
    severity: str
    score: int
    label: str
    signals_fired: int
    ready_for_action: bool
    case_id: str | None = None
    validation: RowValidation | None = None


@dataclass
class UploadResult:
    """Final result after processing with confirmed mappings."""
    processed: int
    enriched: int
    skipped: int
    failed: int
    errors: list[dict[str, Any]]
    avg_score: float
    label_distribution: dict[str, int]
    alert_type_distribution: dict[str, int]
    ready_for_action: int
    unknown_alert_types: int
    missing_context_count: int
    results: list[dict[str, Any]]
    # Grouping metadata
    grouping_enabled: bool = False
    case_count: int = 0
    groups: list[dict[str, Any]] | None = None
    # Truncation info
    original_row_count: int = 0
    truncated: bool = False


# ── Canonical field sets with confidence tiers ───────────────────────────

_CANONICAL_FIELDS: dict[str, dict[str, float]] = {}

def _build_canonical():
    """Build lookup: lowered column name -> (canonical_field, confidence)."""
    _high_identity = {
        "userprincipalname", "upn", "email", "user", "username", "src_user",
        "identity", "user.name", "actor",
        "principal.user.email_addresses", "principal.user.userid",
        "target.user.email_addresses", "target.user.userid",
    }
    _high_ip = {
        "ipaddress", "ip", "src_ip", "sourceip", "origin.addr", "origin_addr", "client_addr",
        "network.src_ip", "principal.ip", "target.ip",
    }
    _high_device = {
        "hostname", "computername", "devicename", "host", "asset_tag", "computer_name",
        "principal.hostname", "target.hostname",
    }
    _high_alert = {
        "alertname", "alert_name", "title", "det_name", "detection_name", "alerttitle",
        "metadata.product_event_type", "metadata.description",
        "securityresult.summary", "securityresult.description",
    }
    # Register broad categories first, then specific ones last so they
    # overwrite any overlapping keys (e.g. "subject" in both identity
    # and email_metadata — email_metadata should win).
    for col in _IDENTITY_FIELDS:
        _CANONICAL_FIELDS[col] = ("identity", 0.9 if col in _high_identity else 0.7)
    for col in _IP_FIELDS:
        _CANONICAL_FIELDS[col] = ("ip", 0.9 if col in _high_ip else 0.7)
    for col in _DEST_IP_FIELDS:
        _CANONICAL_FIELDS[col] = ("dest_ip", 0.85)
    for col in _DEVICE_FIELDS:
        _CANONICAL_FIELDS[col] = ("device", 0.9 if col in _high_device else 0.7)
    for col in _SEVERITY_FIELDS:
        _CANONICAL_FIELDS[col] = ("severity", 0.95)
    for col in _ALERT_NAME_FIELDS:
        _CANONICAL_FIELDS[col] = ("alert_name", 0.85 if col in _high_alert else 0.6)
    # Specific categories registered last — overwrite broad matches
    for col in _PROCESS_FIELDS:
        _CANONICAL_FIELDS[col] = ("process", 0.85)
    for col in _FILE_PATH_FIELDS:
        _CANONICAL_FIELDS[col] = ("file_path", 0.85)
    for col in _GEO_FIELDS:
        _CANONICAL_FIELDS[col] = ("geo", 0.80)
    for col in _EMAIL_METADATA_FIELDS:
        _CANONICAL_FIELDS[col] = ("email_metadata", 0.80)

_build_canonical()


# ── File parsing ─────────────────────────────────────────────────────────

def _flatten_json_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten any nested dicts/arrays in JSON rows to dot-notation keys."""
    result = []
    for row in rows:
        has_nested = any(
            isinstance(v, dict) or (isinstance(v, list) and v and isinstance(v[0], dict))
            for v in row.values()
        )
        if has_nested:
            result.append(flatten_row(row))
        else:
            result.append(row)
    return result


def _parse_xml_splunk(content: str) -> list[dict[str, Any]]:
    """Parse Splunk XML export format into rows."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    rows = []
    # Handle Splunk <results><result><field name="x"><value>v</value></field>...
    for result in root.iter("result"):
        row: dict[str, Any] = {}
        for field in result.iter("field"):
            name = field.get("name", "")
            value_el = field.find("value")
            if name and value_el is not None and value_el.text:
                row[name] = value_el.text.strip()
        if row:
            rows.append(row)

    # Also try generic <event> or <row> formats
    if not rows:
        for tag in ("event", "row", "record", "entry"):
            for elem in root.iter(tag):
                row = {}
                for child in elem:
                    if child.text and child.text.strip():
                        row[child.tag] = child.text.strip()
                if row:
                    rows.append(row)
            if rows:
                break

    return rows


def _parse_leef(content: str) -> list[dict[str, Any]]:
    """Parse IBM QRadar LEEF (Log Event Extended Format) into rows.

    LEEF format: header fields separated by | then key=value pairs separated by |
    LEEF:2.0|Vendor|Product|Version|EventName|key=value|key=value|...
    """
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("LEEF:"):
            continue
        # Split LEEF header from payload — exactly 5 splits to keep payload intact
        parts = line.split("|", 5)  # LEEF:ver|vendor|product|version|name|key=val|key=val...
        if len(parts) < 5:
            continue
        row: dict[str, Any] = {}
        row["_leef_vendor"] = parts[1]
        row["_leef_product"] = parts[2]
        row["_leef_version"] = parts[3]
        row["_leef_event"] = parts[4]
        # Parse key=value payload
        payload = parts[5] if len(parts) > 5 else ""
        # LEEF uses | as separator between key=value pairs
        for kv in payload.split("|"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                row[k.strip()] = v.strip()
        # Map common LEEF fields to standard names
        if "usrName" in row and "user" not in row:
            row["user"] = row["usrName"]
        if "usrEmail" in row and "user_upn" not in row:
            row["user_upn"] = row["usrEmail"]
        # Device mapping — try multiple LEEF variants
        for dev_field in ("srcHostname", "deviceHostname", "srcDevice", "dstHostname", "dstDevice"):
            if dev_field in row and "device" not in row:
                row["device"] = row[dev_field]
                break
        # IP mapping
        if "deviceIp" in row and "src_ip" not in row:
            row["src_ip"] = row["deviceIp"]
        if "srcIp" in row and "src_ip" not in row:
            row["src_ip"] = row["srcIp"]
        if "sev" in row and "severity" not in row:
            # LEEF sev is numeric 0-10, convert to label
            try:
                s = int(row["sev"])
                row["severity"] = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
            except ValueError:
                pass
        if "cat" in row and "category" not in row:
            row["category"] = row["cat"]
        if "note" in row and "analyst_note" not in row:
            row["analyst_note"] = row["note"]
        if "_leef_event" in row and "alert_name" not in row:
            row["alert_name"] = row["_leef_event"]
        if "_leef_product" in row and "source_tool" not in row:
            vendor = row.get("_leef_vendor", "")
            product = row.get("_leef_product", "")
            row["source_tool"] = f"{vendor} {product}".strip() if vendor else product
        if "devTime" in row and "timestamp" not in row:
            row["timestamp"] = row["devTime"]
        if "mitreTactic" in row and "mitre_tactic" not in row:
            row["mitre_tactic"] = row["mitreTactic"]
        if "mitreTechnique" in row and "mitre_technique" not in row:
            row["mitre_technique"] = row["mitreTechnique"]
        if "alertId" in row and "alert_id" not in row:
            row["alert_id"] = row["alertId"]
        if row and len(row) > 3:
            rows.append(row)
    return rows


def _parse_kv_log(content: str) -> list[dict[str, Any]]:
    """Parse key=value log format. One event per line, # for comments."""
    import shlex
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        row: dict[str, Any] = {}
        # Parse key=value pairs — handles quoted values with spaces
        try:
            # Use shlex to handle quoted values
            tokens = shlex.split(line)
            for token in tokens:
                if "=" in token:
                    k, v = token.split("=", 1)
                    row[k.strip()] = v.strip()
        except ValueError:
            # Fallback: regex-based parsing for malformed lines
            import re
            for match in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)', line):
                k = match.group(1)
                v = match.group(2).strip('"')
                row[k] = v
        if row and len(row) > 2:  # need at least a few fields to be a real event
            rows.append(row)
    return rows


def parse_file(content: str, filename: str) -> tuple[str, list[dict[str, Any]]]:
    """Parse uploaded file content into rows. Returns (format, rows)."""
    lower = filename.lower()

    # LEEF (IBM QRadar Log Event Extended Format)
    if lower.endswith(".leef") or content.strip().startswith("LEEF:"):
        rows = _parse_leef(content)
        if rows:
            return "leef", rows

    # Key=Value log format (.kv, .log, or content that looks like key=value)
    if lower.endswith(".kv") or lower.endswith(".log"):
        rows = _parse_kv_log(content)
        if rows:
            return "kv", rows

    # Auto-detect KV format: lines starting with word=value pattern (not XML/JSON/CSV)
    stripped = content.lstrip("\ufeff").strip()
    first_data_line = ""
    for line in stripped.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("//"):
            first_data_line = line
            break
    if (first_data_line
        and "=" in first_data_line
        and not first_data_line.startswith("{")
        and not first_data_line.startswith("[")
        and not first_data_line.startswith("<")
        and first_data_line.count("=") >= 3):  # at least 3 key=value pairs
        rows = _parse_kv_log(content)
        if rows:
            return "kv", rows

    # XML (Splunk, generic SIEM exports)
    if lower.endswith(".xml") or (stripped.startswith("<?xml") or stripped.startswith("<results")):
        rows = _parse_xml_splunk(content)
        if rows:
            return "xml", rows

    if lower.endswith(".tsv") or lower.endswith(".tab"):
        reader = csv.DictReader(io.StringIO(content), delimiter="\t")
        return "tsv", [{k: v for k, v in dict(r).items() if k is not None} for r in reader]

    if lower.endswith(".csv"):
        # Auto-detect delimiter: if first line has more tabs than commas, use tab
        first_line = content.split("\n", 1)[0]
        delimiter = "\t" if first_line.count("\t") > first_line.count(",") else ","
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        return "csv", [{k: v for k, v in dict(r).items() if k is not None} for r in reader]

    if lower.endswith(".json") or lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        # Strip BOM and whitespace
        stripped = content.lstrip("\ufeff").strip()
        # Try JSON array first
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return "json", _flatten_json_rows(parsed)
            return "json", _flatten_json_rows([parsed])
        except json.JSONDecodeError:
            pass
        # Fall back to JSONL (one object per line)
        rows = []
        for line in stripped.splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # Skip malformed lines
        fmt = "ndjson" if lower.endswith(".ndjson") else "jsonl"
        return fmt, _flatten_json_rows(rows)

    # Unknown extension: try JSON then CSV
    try:
        stripped = content.lstrip("\ufeff").strip()
        parsed = json.loads(stripped)
        rows = parsed if isinstance(parsed, list) else [parsed]
        return "json", _flatten_json_rows(rows)
    except json.JSONDecodeError:
        # Auto-detect delimiter
        first_line = content.split("\n", 1)[0]
        delimiter = "\t" if first_line.count("\t") > first_line.count(",") else ","
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        return "csv", [{k: v for k, v in dict(r).items() if k is not None} for r in reader]


# ── Source profile detection ─────────────────────────────────────────────

def detect_source_profile(columns: list[str]) -> SourceProfile:
    """Match column names against known SIEM export signatures."""
    lower_cols = {c.lower().strip() for c in columns}
    best_key = "unknown"
    best_label = "Unknown / Generic CSV"
    best_conf = 0.0
    best_matched: list[str] = []

    for key, profile in _SOURCE_PROFILES.items():
        sig = profile["signature_fields"]
        matched = [c for c in columns if c.lower().strip() in sig]
        if len(matched) >= profile["min_match"]:
            conf = len(matched) / len(sig)
            if conf > best_conf:
                best_key = key
                best_label = profile["label"]
                best_conf = round(min(conf, 1.0), 2)
                best_matched = matched

    return SourceProfile(
        detected=best_key,
        label=best_label,
        confidence=best_conf,
        matched_fields=best_matched,
    )


# ── Column mapping ───────────────────────────────────────────────────────

def map_columns(columns: list[str]) -> list[ColumnMapping]:
    """Produce a mapping guess for each column in the file."""
    mappings = []
    for col in columns:
        if col is None or str(col).strip() == "":
            continue
        key = col.lower().strip()
        # Direct match (full key)
        if key in _CANONICAL_FIELDS:
            canonical, conf = _CANONICAL_FIELDS[key]
            mappings.append(ColumnMapping(
                source_column=col,
                canonical_field=canonical,
                confidence=conf,
                reason=f"Direct match: '{col}' is a known {canonical} field",
            ))
            continue

        # Leaf-key direct match for dot-notation keys
        # e.g., "principal.ip" -> leaf "ip" -> known IP field at 90%
        # This takes priority over partial parent matches like "principal"
        if "." in key:
            leaf = key.rsplit(".", 1)[1]
            if leaf in _CANONICAL_FIELDS:
                canonical, conf = _CANONICAL_FIELDS[leaf]
                mappings.append(ColumnMapping(
                    source_column=col,
                    canonical_field=canonical,
                    confidence=round(conf * 0.9, 2),  # Slight discount for leaf match
                    reason=f"Leaf match: '{col}' leaf '{leaf}' is a known {canonical} field",
                ))
                continue

        # Partial / substring match — require minimum 4-char overlap to avoid
        # false positives like "ip" matching inside "description_blob".
        # Skip partial matching for "additional.*" and "raw_log.*" fields —
        # these are arbitrary enrichment/context metadata and partial hits
        # create false positives (e.g. "additional.actor_type" matching
        # "actor" -> identity, or "raw_log.mfa_used" matching "mfa").
        found = False
        if not key.startswith(("additional.", "raw_log.")):
            for candidate, (canonical, conf) in _CANONICAL_FIELDS.items():
                if len(candidate) < 4 and len(key) < 4:
                    # Both short: only match if exact
                    if candidate != key:
                        continue
                elif len(candidate) < 4:
                    # Short candidate like "ip": skip substring matching into long names
                    continue
                elif len(key) < 4:
                    # Short key like "ts": skip substring matching into long candidates
                    continue
                if candidate in key or key in candidate:
                    mappings.append(ColumnMapping(
                        source_column=col,
                        canonical_field=canonical,
                        confidence=round(conf * 0.6, 2),
                        reason=f"Partial match: '{col}' resembles {canonical} field '{candidate}'",
                    ))
                    found = True
                    break

        if not found:
            # Check for timestamp-like columns
            # Check for timestamp-like columns — "ts" must be exact or a
            # prefix/suffix separated by _ or . to avoid matching "secrets"
            ts_substrs = ("time", "date", "timestamp", "when", "created")
            is_ts = any(t in key for t in ts_substrs)
            if not is_ts and (key == "ts" or key.startswith("ts.") or key.startswith("ts_") or key.endswith("_ts") or key.endswith(".ts")):
                is_ts = True
            if is_ts:
                mappings.append(ColumnMapping(
                    source_column=col,
                    canonical_field="timestamp",
                    confidence=0.7,
                    reason=f"Heuristic: '{col}' looks like a timestamp field",
                ))
            else:
                mappings.append(ColumnMapping(
                    source_column=col,
                    canonical_field="unmapped",
                    confidence=0.0,
                    reason=f"No known mapping for '{col}'",
                ))

    return mappings


# ── Row validation ───────────────────────────────────────────────────────

_TIMESTAMP_RE = re.compile(
    r"(?:"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"     # ISO: 2026-03-26T10:14:22
    r"|"
    r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}"       # US: 03/26/2026 06:52:01
    r"|"
    r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}"       # Alt: 2026/03/26 06:52:01
    r")"
)


def validate_row(index: int, row: dict[str, Any], column_mappings: list[ColumnMapping]) -> RowValidation:
    """Check a single row for usability before enrichment."""
    reasons: list[str] = []

    # Build quick lookup: canonical -> source columns that mapped to it
    mapped = {}
    for m in column_mappings:
        if m.canonical_field != "unmapped":
            mapped.setdefault(m.canonical_field, []).append(m.source_column)

    # Check identity
    has_identity = False
    for col in mapped.get("identity", []):
        val = row.get(col, "")
        if val and str(val).strip() and str(val).strip().lower() not in ("", "-", "n/a", "null", "none"):
            has_identity = True
            break
    if not has_identity:
        reasons.append("No identity field detected (user/email/UPN)")

    # Check IP
    has_ip = False
    for group in ("ip", "dest_ip"):
        for col in mapped.get(group, []):
            val = row.get(col, "")
            if val and str(val).strip() and str(val).strip() != "0.0.0.0":
                has_ip = True
                break
    if not has_ip:
        reasons.append("No usable IP address found")

    # Check alert type inferability
    alert_type = None
    try:
        alert_type = guess_alert_type(row)
    except Exception:
        pass
    if not alert_type or alert_type == "identity.suspiciousSignIn":
        # Check if there's any text that could help classification
        parts = []
        for k, v in row.items():
            parts.append(k.lower())
            if v is not None:
                parts.append(str(v).lower())
        searchable = " ".join(parts)
        has_keywords = any(kw in searchable for kw in (
            "malware", "virus", "login", "sign-in", "password", "mfa",
            "oauth", "forwarding", "privilege", "geo", "travel", "process",
            "ransomware", "brute", "phishing", "vault", "secret",
            "powershell", "encoded", "consent", "role_grant", "auth",
        ))
        if not has_keywords:
            reasons.append("Could not infer alert type (no recognizable keywords)")

    # Check severity
    severity = None
    try:
        severity = parse_severity(row)
    except Exception:
        pass

    # Check timestamp
    has_timestamp = False
    for col in mapped.get("timestamp", []):
        val = str(row.get(col, ""))
        if _TIMESTAMP_RE.search(val):
            has_timestamp = True
            break
    # Also check unmapped columns for timestamps
    if not has_timestamp:
        for v in row.values():
            if isinstance(v, str) and _TIMESTAMP_RE.search(v):
                has_timestamp = True
                break
    if not has_timestamp:
        reasons.append("No usable timestamp found")

    # A row is valid if it has ENOUGH context to be useful, not if it's perfect.
    # K8s/cloud alerts may lack user+IP but have device/node + severity + rich context.
    # Only skip if the row is truly empty or has 3+ missing core fields.
    has_device = False
    for col in mapped.get("device", []):
        val = row.get(col, "")
        if val and str(val).strip() and str(val).strip().lower() not in ("", "-", "n/a", "null", "none", "unknown"):
            has_device = True
            break
    has_context = any(
        k.lower() in ("analyst_note", "additional_context", "context", "description", "notes")
        and v and len(str(v)) > 30
        for k, v in row.items()
    )

    # Valid if: no reasons, OR has enough alternate context
    has_severity = severity is not None
    is_valid = (len(reasons) == 0
                or (has_device and has_severity)
                or (has_context and has_severity)
                or (has_identity and has_severity)
                or (has_ip and has_severity))

    return RowValidation(
        index=index,
        valid=is_valid,
        reasons=reasons,
        detected_alert_type=alert_type,
        detected_severity=severity,
    )


# ── Dry-run preview ─────────────────────────────────────────────────────

def build_preview(
    content: str,
    filename: str,
    max_rows: int = 2000,
) -> UploadPreview:
    """Parse file and return a full preview without creating any cases."""
    file_format, rows = parse_file(content, filename)
    if not rows:
        return UploadPreview(
            filename=filename,
            file_format=file_format,
            total_rows=0,
            columns=[],
            source_profile=SourceProfile("unknown", "Empty file", 0.0, []),
            column_mappings=[],
            sample_rows=[],
            row_validations=[],
            summary={"total": 0, "valid": 0, "warnings": 0, "invalid": 0},
        )

    if len(rows) > max_rows:
        rows = rows[:max_rows]

    # Collect ALL unique columns across all rows (important for NDJSON
    # where each line can have a different schema)
    seen_columns: dict[str, None] = {}  # ordered dict behavior
    for row in rows:
        for k in row.keys():
            if k not in seen_columns:
                seen_columns[k] = None
    columns = list(seen_columns.keys())

    source_profile = detect_source_profile(columns)
    column_mappings = map_columns(columns)

    # Validate every row — use per-row mappings for heterogeneous schemas
    def _validate_with_row_cols(i: int, row: dict[str, Any]) -> RowValidation:
        row_cols = list(row.keys())
        row_mappings = map_columns(row_cols) if set(row_cols) != set(columns) else column_mappings
        return validate_row(i, row, row_mappings)

    validations = [_validate_with_row_cols(i, row) for i, row in enumerate(rows)]

    valid_count = sum(1 for v in validations if v.valid)
    warning_count = sum(1 for v in validations if not v.valid and len(v.reasons) <= 1)
    invalid_count = sum(1 for v in validations if not v.valid and len(v.reasons) > 1)

    # Alert type distribution from validation
    type_counts: dict[str, int] = {}
    for v in validations:
        t = v.detected_alert_type or "unknown"
        type_counts[t] = type_counts.get(t, 0) + 1

    return UploadPreview(
        filename=filename,
        file_format=file_format,
        total_rows=len(rows),
        columns=columns,
        source_profile=source_profile,
        column_mappings=column_mappings,
        sample_rows=rows[:5],
        row_validations=validations,
        summary={
            "total": len(rows),
            "valid": valid_count,
            "warnings": warning_count,
            "invalid": invalid_count,
            "alertTypeDistribution": type_counts,
        },
    )


# ── Error translation for user-friendly messages ────────────────────────

def _translate_error(msg: str) -> str:
    """Translate developer error messages to user-friendly explanations."""
    _TRANSLATIONS = [
        ("bulkTarget", "Password spray alert missing target count info. Try adding columns: target_count, success_count"),
        ("entities.file", "Alert missing file details. Try adding columns: filename, file_path, sha256"),
        ("file.fileName", "Alert missing file name. Try adding a column: filename, process_name, file_path"),
        ("entities.app", "Alert missing application info. Try adding columns: app_name, app_id, application"),
        ("entities.device", "Alert missing device info. Try adding columns: hostname, device_name, endpoint"),
        ("entities.ips", "Alert missing IP address info. Try adding columns: src_ip, ip_address, source_ip"),
        ("Missing required entities", "Some entity data is missing but the alert was still enriched."),
    ]
    lower = msg.lower()
    for pattern, friendly in _TRANSLATIONS:
        if pattern.lower() in lower:
            return friendly
    return f"Processing error: {msg}"


# ── Process with overrides ───────────────────────────────────────────────

def process_upload(
    content: str,
    filename: str,
    tenant_id: str,
    alert_type_override: str | None = None,
    column_overrides: dict[str, str] | None = None,
    persist: bool = False,
    grouping: bool = False,
    max_rows: int = 2000,
) -> UploadResult:
    """Full processing: parse, validate, enrich, optionally group & persist.

    Two modes:
      grouping=False  →  1 alert = 1 case  (debug mode)
      grouping=True   →  N alerts = 1 case  (SOC mode)

    column_overrides: {source_column: canonical_field} — lets user
    correct any misdetected mappings before processing.
    """
    from backend.app.schemas.case_v0_2 import Customer, Source
    from backend.app.schemas.requests import CreateCaseRequest
    from backend.app.services.case_service import create_case, create_grouped_case
    from backend.app.core.db import get_session

    file_format, rows = parse_file(content, filename)
    original_row_count = len(rows)
    truncated = False
    if len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True

    # Collect ALL unique columns across all rows
    seen_columns: dict[str, None] = {}
    for row in rows:
        for k in row.keys():
            if k not in seen_columns:
                seen_columns[k] = None
    columns = list(seen_columns.keys())
    column_mappings = map_columns(columns)

    # Apply user overrides
    if column_overrides:
        for m in column_mappings:
            if m.source_column in column_overrides:
                m.canonical_field = column_overrides[m.source_column]
                m.confidence = 1.0
                m.reason = "User override"

    # If user remapped columns, remap the rows to match what alert_mapper expects
    remapped_rows = rows
    if column_overrides:
        remapped_rows = [_apply_column_overrides(row, column_overrides) for row in rows]

    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Enrich every alert individually
    # ══════════════════════════════════════════════════════════════════════
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    enriched_alerts: list[EnrichedAlert] = []
    skipped = 0
    score_sum = 0
    label_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    unknown_types = 0
    missing_context = 0

    # Extract customer name from first few rows
    _CUSTOMER_FIELDS = {"customer", "customer_name", "account_name", "organization", "tenant_name", "company", "org_name"}
    extracted_customer = "Upload Customer"  # default fallback
    for row in remapped_rows[:5]:  # scan first 5 rows
        flat = {k.lower().replace(".", "_"): v for k, v in row.items()}
        for field in _CUSTOMER_FIELDS:
            val = flat.get(field) or ""
            if isinstance(val, str) and val.strip() and val.strip().lower() not in ("unknown", "n/a", ""):
                extracted_customer = val.strip()
                break
        if extracted_customer != "Upload Customer":
            break

    # ── Host/IP to user resolution ────────────────────────────────────
    # Pre-scan all rows to build hostname→user and IP→user maps from
    # alerts that have both fields. Then backfill alerts that only have
    # hostname/IP but no user. This connects network-level alerts (DNS,
    # firewall) to user-level context from endpoint agents.
    #
    # WHY: Network sensors (Infoblox, Darktrace, Zscaler) see traffic
    # by IP/hostname but not user. Endpoint agents (CrowdStrike, Sentinel)
    # see the same host with user context. Cross-referencing lets Vigilis
    # attribute network alerts to users without requiring a CMDB lookup.
    _host_to_user: dict[str, str] = {}
    _ip_to_user: dict[str, str] = {}
    _identity_fields_lower = {f.lower() for f in _IDENTITY_FIELDS}
    _device_fields_lower = {f.lower() for f in _DEVICE_FIELDS}
    _ip_fields_lower = {f.lower() for f in _IP_FIELDS}

    for row in remapped_rows:
        user_val = None
        host_val = None
        ip_val = None
        for k, v in row.items():
            if not v or str(v).strip() in ("", "null", "none"):
                continue
            kl = k.lower().strip()
            if kl in _identity_fields_lower and not user_val:
                user_val = str(v).strip()
            if kl in _device_fields_lower and not host_val:
                host_val = str(v).strip().lower()
            if kl in _ip_fields_lower and not ip_val:
                ip_val = str(v).strip()
        # Only map if we have a real user (not placeholder)
        if user_val and user_val.lower() not in ("unknown", "[multiple]", "multiple", "system", ""):
            if host_val and host_val != "unknown-host":
                _host_to_user[host_val] = user_val
            if ip_val and not ip_val.startswith("0."):
                _ip_to_user[ip_val] = user_val

    # Backfill: inject user into rows missing identity but having host/IP
    for row in remapped_rows:
        has_user = False
        host_val = None
        ip_val = None
        for k, v in row.items():
            if not v or str(v).strip() in ("", "null", "none"):
                continue
            kl = k.lower().strip()
            if kl in _identity_fields_lower:
                val = str(v).strip().lower()
                if val not in ("unknown", "[multiple]", "multiple", "system", ""):
                    has_user = True
            if kl in _device_fields_lower:
                host_val = str(v).strip().lower()
            if kl in _ip_fields_lower:
                ip_val = str(v).strip()
        if not has_user:
            resolved = _host_to_user.get(host_val or "") or _ip_to_user.get(ip_val or "")
            if resolved:
                row["_resolved_user"] = resolved

    for i, row in enumerate(remapped_rows):
        # Validate with per-row columns for heterogeneous schemas
        row_cols = list(row.keys())
        row_mappings = map_columns(row_cols) if set(row_cols) != set(columns) else column_mappings
        if column_overrides:
            for m in row_mappings:
                if m.source_column in column_overrides:
                    m.canonical_field = column_overrides[m.source_column]
                    m.confidence = 1.0
                    m.reason = "User override"
        validation = validate_row(i, row, row_mappings)

        # Skip rows only if the validator says invalid (lenient validation
        # already accounts for K8s/cloud alerts with device but no user/IP)
        if not validation.valid:
            skipped += 1
            results.append({
                "index": i,
                "status": "skipped",
                "reasons": validation.reasons,
            })
            continue

        if not validation.valid:
            missing_context += 1

        try:
            alert_type, raw_alert = map_row_to_raw_alert(row, alert_type_override)
            severity = parse_severity(row)
            event_time = extract_event_time(row) or datetime.now(timezone.utc)

            # sourceAlertId must be unique across uploads — include filename
            # and event_time so re-uploading the SAME file deduplicates correctly
            # but uploading a DIFFERENT file (e.g., day_04.json vs day_03.json)
            # always creates new cases.
            _src_id = f"upload:{filename}:{i}:{event_time.isoformat()}"

            case = normalize_case_from_request(
                tenant={"tenantId": tenant_id, "name": extracted_customer},
                source={
                    "sourceSystem": "custom",
                    "sourceName": f"upload:{filename}",
                    "sourceAlertId": _src_id,
                    "sourceSeverity": severity,
                },
                alert_type=alert_type,
                title=None,
                description=None,
                severity=severity,
                event_time=event_time,
                raw_alert=raw_alert,
            )

            case_json = case.model_dump(mode="json")
            score = case_json.get("confidence", {}).get("score", 0)
            label = case_json.get("confidence", {}).get("label", "low")
            score_sum += score
            label_counts[label] = label_counts.get(label, 0) + 1
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1

            if alert_type == "identity.suspiciousSignIn" and not alert_type_override:
                searchable = " ".join(str(v).lower() for v in row.values() if isinstance(v, str))
                if not any(kw in searchable for kw in ("sign-in", "signin", "login", "logon", "authentication")):
                    unknown_types += 1

            ready = (case_json.get("enrichment", {}).get("caseReadiness", {}) or {}).get("readyForAction", False)

            # Collect enriched alert for grouping
            enriched_alerts.append(EnrichedAlert(
                index=i,
                row=row,
                alert_type=alert_type,
                severity=severity,
                case_data=case,
                score=score,
                label=label,
                signals_fired=len(case_json.get("confidence", {}).get("explanation", [])),
                ready_for_action=ready,
                validation_warnings=validation.reasons if validation.reasons else [],
            ))

            # In ungrouped mode, persist immediately per alert
            if not grouping and persist:
                with get_session() as session:
                    create_req = CreateCaseRequest(
                        tenantId=tenant_id,
                        customer=Customer(name=extracted_customer),
                        alertType=alert_type,
                        source=Source(
                            sourceSystem="custom",
                            sourceName=f"upload:{filename}",
                            sourceAlertId=_src_id,
                            sourceSeverity=severity,
                        ),
                        rawAlert=raw_alert,
                        severity=severity,
                        eventTime=event_time,
                    )
                    case = create_case(session, create_req)

                    # Evaluate suppression rules
                    suppression = evaluate_suppression(
                        session,
                        tenant_id=tenant_id,
                        alert_type=alert_type,
                        severity=severity,
                        confidence_score=score,
                        entities=case_json.get("entities", {}),
                    )
                    if suppression and suppression["action"] == "auto_close":
                        from backend.app.services.case_service import update_disposition
                        update_disposition(
                            session,
                            case.caseId,
                            {"status": "benign", "setBy": f"rule:{suppression['ruleName']}"},
                            set_by=None,
                        )

            results.append({
                "index": i,
                "status": "enriched",
                "alertType": alert_type,
                "severity": severity,
                "score": score,
                "label": label,
                "signalsFired": len(case_json.get("confidence", {}).get("explanation", [])),
                "readyForAction": ready,
                "caseId": str(case_json.get("caseId")),
                "validationWarnings": validation.reasons if validation.reasons else None,
            })

        except Exception as e:
            errors.append({"index": i, "error": str(e), "reasons": [_translate_error(str(e))]})

    enriched = sum(1 for r in results if r.get("status") == "enriched")
    total_with_scores = enriched

    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Group alerts into incident cases (SOC mode)
    # ══════════════════════════════════════════════════════════════════════
    group_summaries: list[dict[str, Any]] | None = None
    case_count = enriched  # default: 1 alert = 1 case

    if grouping and enriched_alerts:
        groups = group_enriched_alerts(enriched_alerts)
        case_count = len(groups)
        group_summaries = []

        # Map alert index → group info for result annotation
        index_to_group: dict[int, tuple[int, str]] = {}
        for g_idx, group in enumerate(groups):
            for a in group.alerts:
                index_to_group[a.index] = (g_idx, group.key)

        # Annotate individual results with their group
        for r in results:
            if r.get("status") == "enriched" and r["index"] in index_to_group:
                g_idx, g_key = index_to_group[r["index"]]
                r["groupIndex"] = g_idx
                r["groupKey"] = g_key

        # Build and optionally persist grouped cases
        for g_idx, group in enumerate(groups):
            grouped_case = build_grouped_case(group, tenant_id, filename)

            if persist:
                with get_session() as session:
                    persisted = create_grouped_case(
                        session=session,
                        case=grouped_case,
                        tenant_id=tenant_id,
                        alert_count=len(group.alerts),
                        grouping_key=group.key,
                        member_alert_indices=group.member_indices,
                    )
                    grouped_case = persisted

                    # Auto-suppress noise: cases with quality issues.
                    # WHY: Cases with NO_SIGNALS, LOW_CONFIDENCE, or INCOMPLETE_DATA
                    # (with low score) are likely false positives or irrelevant events.
                    # Auto-closing them as benign removes them from the analyst queue.
                    # GUARD: Cases with rich descriptions (>50 chars) are NOT suppressed
                    # even if flagged, because the description may contain actionable
                    # context (e.g., insider threat analyst notes, correlation notes).
                    # This prevents false suppression of alerts like "p.nguyen has
                    # submitted resignation" which have NO_SIGNALS but critical context.
                    q_flags = (grouped_case.enrichment.qualityFlags
                               if hasattr(grouped_case.enrichment, 'qualityFlags')
                               else [])
                    has_rich_context = bool(grouped_case.description and len(grouped_case.description) > 50)
                    _case_sev = getattr(grouped_case, 'severity', '') or ''
                    is_noise = (('NO_SIGNALS' in q_flags or 'LOW_CONFIDENCE' in q_flags
                                or ('INCOMPLETE_DATA' in q_flags and grouped_case.confidence.score < 45))
                                and not has_rich_context
                                and _case_sev not in ('critical', 'high'))  # NEVER auto-close critical/high
                    if is_noise:
                        from backend.app.services.case_service import update_disposition
                        try:
                            update_disposition(
                                session, grouped_case.caseId,
                                {"status": "benign", "setBy": "auto:noise-suppression"},
                                set_by=None,
                            )
                        except Exception:
                            pass

            # Update result rows with grouped case ID
            for r in results:
                if r.get("groupIndex") == g_idx:
                    r["groupCaseId"] = str(grouped_case.caseId)

            time_range = ""
            if group.earliest_time and group.latest_time:
                t0 = group.earliest_time.strftime("%H:%M:%S")
                t1 = group.latest_time.strftime("%H:%M:%S")
                time_range = f"{t0} - {t1}"

            group_summaries.append({
                "groupIndex": g_idx,
                "groupKey": group.key,
                "groupingReason": group.grouping_reason,
                "alertCount": len(group.alerts),
                "alertType": group.primary_alert_type,
                "severity": group.highest_severity,
                "score": group.highest_score,
                "label": group.best_label,
                "entity": group.entity_anchor,
                "timeRange": time_range,
                "memberIndices": group.member_indices,
                "caseId": str(grouped_case.caseId),
            })

    return UploadResult(
        processed=len(rows),
        enriched=enriched,
        skipped=skipped,
        failed=len(errors),
        errors=errors[:20],
        avg_score=round(score_sum / total_with_scores, 1) if total_with_scores else 0,
        label_distribution=label_counts,
        alert_type_distribution=type_counts,
        ready_for_action=sum(1 for r in results if r.get("readyForAction")),
        unknown_alert_types=unknown_types,
        missing_context_count=missing_context,
        results=results + [{"index": e["index"], "status": "failed", **e} for e in errors],
        grouping_enabled=grouping,
        case_count=case_count,
        groups=group_summaries,
        original_row_count=original_row_count,
        truncated=truncated,
    )


def _apply_column_overrides(row: dict[str, Any], overrides: dict[str, str]) -> dict[str, Any]:
    """Create a new row dict with renamed columns based on user overrides.

    Maps user-specified canonical fields to column names the alert_mapper recognizes.
    """
    # Canonical -> preferred column names that alert_mapper looks for
    _CANONICAL_TO_PREFERRED = {
        "identity": "user",
        "ip": "src_ip",
        "dest_ip": "dest_ip",
        "device": "hostname",
        "severity": "severity",
        "alert_name": "alertname",
    }

    result = dict(row)
    for source_col, canonical in overrides.items():
        if source_col in result and canonical in _CANONICAL_TO_PREFERRED:
            preferred = _CANONICAL_TO_PREFERRED[canonical]
            # Only add the preferred-name alias if it doesn't already exist
            if preferred not in result:
                result[preferred] = result[source_col]
    return result
