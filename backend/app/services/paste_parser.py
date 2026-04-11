"""Smart 'Paste Anything' parser.

Accepts any text input and auto-detects its format:
- JSON object or array
- CSV row(s) with header
- Key=value pairs (space or newline separated)
- Syslog-style messages
- Raw unstructured text (keyword extraction)

Returns a normalized dict suitable for the alert mapper.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any


class ParseResult:
    __slots__ = ("format", "data", "confidence", "notes")

    def __init__(
        self,
        fmt: str,
        data: dict[str, Any],
        confidence: str = "high",
        notes: list[str] | None = None,
    ) -> None:
        self.format = fmt
        self.data = data
        self.confidence = confidence
        self.notes = notes or []


_KV_PATTERN = re.compile(
    r"""(?:^|[\s,;|])"""
    r"""([\w.\-]+)"""           # key
    r"""\s*[=:]\s*"""           # separator
    r"""(?:"([^"]*)"|([\S]+))""",  # quoted or unquoted value
    re.MULTILINE,
)

_SYSLOG_HEADER = re.compile(
    r"^(?:<\d+>)?\s*"
    r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)"
    r"([\w.\-]+)\s+"
    r"([\w.\-/\[\]]+):\s*"
)

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_EMAIL_PATTERN = re.compile(r"\b([\w.+-]+@[\w.-]+\.\w{2,})\b")
_TIMESTAMP_PATTERN = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\dZ]*)\b"
)


def parse_any(text: str) -> ParseResult:
    """Parse any text input into a structured dict."""
    stripped = text.strip()
    if not stripped:
        return ParseResult("empty", {}, "low", ["Empty input"])

    result = _try_json(stripped)
    if result:
        return result

    result = _try_csv(stripped)
    if result:
        return result

    result = _try_syslog(stripped)
    if result:
        return result

    result = _try_key_value(stripped)
    if result:
        return result

    return _extract_from_raw_text(stripped)


def _try_json(text: str) -> ParseResult | None:
    """Try parsing as JSON object or array."""
    if not (text.startswith("{") or text.startswith("[")):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None

    if isinstance(parsed, dict):
        return ParseResult("json", parsed, "high", ["Parsed as JSON object"])
    if isinstance(parsed, list) and parsed:
        first = parsed[0] if isinstance(parsed[0], dict) else {"data": parsed[0]}
        notes = [f"Parsed as JSON array ({len(parsed)} items), using first item"]
        return ParseResult("json_array", first, "high", notes)
    return None


def _try_csv(text: str) -> ParseResult | None:
    """Try parsing as CSV (needs header + at least one data row)."""
    lines = text.strip().splitlines()
    if len(lines) < 2:
        return None

    first_line = lines[0]
    comma_count = first_line.count(",")
    tab_count = first_line.count("\t")

    if comma_count < 1 and tab_count < 1:
        return None

    delimiter = "\t" if tab_count > comma_count else ","

    try:
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return None
        fields = reader.fieldnames or []
        if len(fields) < 2:
            return None

        data = rows[0]
        notes = [
            f"Parsed as CSV ({len(rows)} rows, {len(fields)} columns)",
            f"Columns: {', '.join(fields[:8])}{'...' if len(fields) > 8 else ''}",
        ]
        return ParseResult(
            "csv",
            {k: v for k, v in data.items() if v},
            "high",
            notes,
        )
    except Exception:
        return None


def _try_key_value(text: str) -> ParseResult | None:
    """Try parsing as key=value or key:value pairs."""
    matches = _KV_PATTERN.findall(text)
    if len(matches) < 2:
        return None

    data: dict[str, str] = {}
    for key, quoted_val, unquoted_val in matches:
        data[key] = quoted_val if quoted_val else unquoted_val

    total_chars = sum(len(k) + len(v) for k, v in data.items())
    coverage = total_chars / max(len(text), 1)

    if coverage < 0.15:
        return None

    notes = [
        f"Parsed as key=value pairs ({len(data)} fields)",
        f"Fields: {', '.join(list(data.keys())[:8])}{'...' if len(data) > 8 else ''}",
    ]
    return ParseResult("key_value", data, "medium", notes)


def _try_syslog(text: str) -> ParseResult | None:
    """Try parsing as syslog-format message."""
    match = _SYSLOG_HEADER.match(text)
    if not match:
        return None

    hostname = match.group(1)
    process = match.group(2)
    message = text[match.end():]

    data: dict[str, Any] = {
        "hostname": hostname,
        "process": process,
        "message": message,
    }

    kv_result = _try_key_value(message)
    if kv_result and len(kv_result.data) >= 2:
        data.update(kv_result.data)

    ips = _IP_PATTERN.findall(text)
    if ips:
        data["detected_ips"] = ips

    emails = _EMAIL_PATTERN.findall(text)
    if emails:
        data["detected_emails"] = emails

    timestamps = _TIMESTAMP_PATTERN.findall(text)
    if timestamps:
        data["detected_timestamp"] = timestamps[0]

    return ParseResult(
        "syslog",
        data,
        "medium",
        [f"Parsed as syslog from {hostname}/{process}"],
    )


def _extract_from_raw_text(text: str) -> ParseResult:
    """Last resort: extract whatever structure we can from raw text."""
    data: dict[str, Any] = {"raw_log": text}
    notes = ["Could not detect structured format, treating as raw text"]

    ips = _IP_PATTERN.findall(text)
    if ips:
        unique_ips = list(dict.fromkeys(ips))
        data["detected_ips"] = unique_ips
        notes.append(f"Extracted {len(unique_ips)} IP address(es)")

    emails = _EMAIL_PATTERN.findall(text)
    if emails:
        unique_emails = list(dict.fromkeys(emails))
        data["detected_emails"] = unique_emails
        notes.append(f"Extracted {len(unique_emails)} email(s)")

    timestamps = _TIMESTAMP_PATTERN.findall(text)
    if timestamps:
        data["detected_timestamp"] = timestamps[0]
        notes.append(f"Extracted timestamp: {timestamps[0]}")

    kv_result = _try_key_value(text)
    if kv_result and len(kv_result.data) >= 2:
        data.update(kv_result.data)
        notes.append(f"Also extracted {len(kv_result.data)} key=value pairs")

    confidence = "high" if len(data) >= 4 else "medium" if len(data) >= 2 else "low"

    return ParseResult("raw_text", data, confidence, notes)
