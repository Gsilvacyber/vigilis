"""Side-by-side enrichment comparison engine.

Enriches two inputs through the paste pipeline and returns a structured
diff: which signals differ, score delta, entity overlap, playbook diff.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.services.alert_mapper import map_row_to_raw_alert, parse_severity
from backend.app.services.enrichment import enrich_debug
from backend.app.services.normalizer import normalize_case_from_request
from backend.app.services.paste_parser import parse_any


def _enrich_text(text: str, tenant_id: str) -> dict[str, Any]:
    """Parse any text and return full enrichment result."""
    parsed = parse_any(text)
    if parsed.format == "empty":
        return {"error": "empty input"}

    alert_type, raw_alert = map_row_to_raw_alert(parsed.data)
    severity = parse_severity(parsed.data)
    event_time = datetime.now(timezone.utc)

    case = normalize_case_from_request(
        tenant={"tenantId": tenant_id, "name": "Compare"},
        source={
            "sourceSystem": "custom",
            "sourceName": "compare",
            "sourceAlertId": f"cmp:{hash(text) % 100000}",
            "sourceSeverity": severity,
        },
        alert_type=alert_type,
        title=None,
        description=None,
        severity=severity,
        event_time=event_time,
        raw_alert=raw_alert,
    )

    debug = enrich_debug(alert_type, severity, raw_alert, event_time)
    case_json = case.model_dump(mode="json")

    signals = [
        {"signal": s.name, "weight": s.weight, "fired": s.fired, "label": s.label}
        for s in debug.all_signals
    ]

    return {
        "detection": {
            "inputFormat": parsed.format,
            "inputConfidence": parsed.confidence,
            "detectedAlertType": alert_type,
            "detectedSeverity": severity,
            "fieldsExtracted": len(parsed.data),
            "notes": parsed.notes,
        },
        "alertType": alert_type,
        "severity": severity,
        "scoreBreakdown": {
            "severityBase": debug.severity_base,
            "signalBoost": debug.signal_boost,
            "finalScore": debug.result.confidence_score,
            "label": debug.result.confidence_label,
        },
        "derivedSignals": signals,
        "recommendedPlaybook": debug.result.recommended_playbook,
        "recommendedActions": debug.result.recommended_actions,
        "enrichmentNotes": debug.result.enrichment_notes,
        "finalCase": case_json,
    }


def _extract_entity_set(case_json: dict) -> dict[str, list[str]]:
    """Pull out entity identifiers for overlap computation."""
    entities = case_json.get("entities") or {}
    result: dict[str, list[str]] = {"users": [], "ips": [], "hostnames": [], "apps": []}

    for key in ("identity", "actor"):
        sub = entities.get(key) or {}
        if sub.get("upn"):
            result["users"].append(sub["upn"])
        if sub.get("userId"):
            result["users"].append(sub["userId"])

    for ip_ent in entities.get("ips") or []:
        if ip_ent.get("ipAddress"):
            result["ips"].append(ip_ent["ipAddress"])

    device = entities.get("device") or {}
    if device.get("hostname"):
        result["hostnames"].append(device["hostname"])

    app = entities.get("app") or {}
    if app.get("name"):
        result["apps"].append(app["name"])

    for k in result:
        result[k] = list(dict.fromkeys(result[k]))

    return result


def compare_enrichments(
    text_a: str,
    text_b: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Enrich two texts and return a structured comparison."""

    result_a = _enrich_text(text_a, tenant_id)
    result_b = _enrich_text(text_b, tenant_id)

    if "error" in result_a or "error" in result_b:
        return {
            "error": "Both inputs must be non-empty",
            "a": result_a,
            "b": result_b,
        }

    score_a = result_a["scoreBreakdown"]["finalScore"]
    score_b = result_b["scoreBreakdown"]["finalScore"]

    signals_a = {s["signal"]: s for s in result_a["derivedSignals"]}
    signals_b = {s["signal"]: s for s in result_b["derivedSignals"]}
    all_signal_names = sorted(set(signals_a) | set(signals_b))

    signal_comparison = []
    for name in all_signal_names:
        sa = signals_a.get(name)
        sb = signals_b.get(name)
        fired_a = sa["fired"] if sa else False
        fired_b = sb["fired"] if sb else False
        weight_a = sa["weight"] if sa else 0
        weight_b = sb["weight"] if sb else 0

        if fired_a and fired_b:
            status = "both"
        elif fired_a:
            status = "only_a"
        elif fired_b:
            status = "only_b"
        else:
            status = "neither"

        signal_comparison.append({
            "signal": name,
            "firedA": fired_a,
            "firedB": fired_b,
            "weightA": weight_a,
            "weightB": weight_b,
            "status": status,
            "labelA": sa["label"] if sa else "",
            "labelB": sb["label"] if sb else "",
        })

    entities_a = _extract_entity_set(result_a.get("finalCase") or {})
    entities_b = _extract_entity_set(result_b.get("finalCase") or {})

    entity_overlap: dict[str, Any] = {}
    for category in ("users", "ips", "hostnames", "apps"):
        set_a = set(entities_a.get(category, []))
        set_b = set(entities_b.get(category, []))
        shared = sorted(set_a & set_b)
        only_in_a = sorted(set_a - set_b)
        only_in_b = sorted(set_b - set_a)
        entity_overlap[category] = {
            "shared": shared,
            "onlyA": only_in_a,
            "onlyB": only_in_b,
        }

    pb_a = {(p.get("title") or p.get("step", "")): p for p in result_a.get("recommendedPlaybook", [])}
    pb_b = {(p.get("title") or p.get("step", "")): p for p in result_b.get("recommendedPlaybook", [])}
    playbook_shared = sorted(set(pb_a) & set(pb_b))
    playbook_only_a = sorted(set(pb_a) - set(pb_b))
    playbook_only_b = sorted(set(pb_b) - set(pb_a))

    act_a = {(a.get("title") or a.get("action", "")): a for a in result_a.get("recommendedActions", [])}
    act_b = {(a.get("title") or a.get("action", "")): a for a in result_b.get("recommendedActions", [])}
    actions_shared = sorted(set(act_a) & set(act_b))
    actions_only_a = sorted(set(act_a) - set(act_b))
    actions_only_b = sorted(set(act_b) - set(act_a))

    same_type = result_a["alertType"] == result_b["alertType"]
    same_severity = result_a["severity"] == result_b["severity"]
    same_label = result_a["scoreBreakdown"]["label"] == result_b["scoreBreakdown"]["label"]

    signals_fired_a = sum(1 for s in result_a["derivedSignals"] if s["fired"])
    signals_fired_b = sum(1 for s in result_b["derivedSignals"] if s["fired"])

    verdict_parts = []
    if same_type and same_severity and abs(score_a - score_b) < 10:
        verdict_parts.append("These alerts are very similar")
    elif same_type:
        verdict_parts.append("Same alert type but different risk profile")
    else:
        verdict_parts.append("Different alert types")

    if abs(score_a - score_b) >= 20:
        higher = "A" if score_a > score_b else "B"
        verdict_parts.append(f"Alert {higher} is significantly higher risk (+{abs(score_a - score_b)} pts)")

    signals_only_a_count = sum(1 for s in signal_comparison if s["status"] == "only_a")
    signals_only_b_count = sum(1 for s in signal_comparison if s["status"] == "only_b")
    if signals_only_a_count or signals_only_b_count:
        verdict_parts.append(f"{signals_only_a_count} signal(s) unique to A, {signals_only_b_count} unique to B")

    overlap_count = sum(len(v["shared"]) for v in entity_overlap.values())
    if overlap_count:
        verdict_parts.append(f"{overlap_count} shared entit{'y' if overlap_count == 1 else 'ies'} — possibly related")

    return {
        "a": result_a,
        "b": result_b,
        "comparison": {
            "scoreDelta": score_a - score_b,
            "scoreA": score_a,
            "scoreB": score_b,
            "sameAlertType": same_type,
            "sameSeverity": same_severity,
            "sameLabel": same_label,
            "signalsFiredA": signals_fired_a,
            "signalsFiredB": signals_fired_b,
            "signals": signal_comparison,
            "entityOverlap": entity_overlap,
            "playbook": {
                "shared": playbook_shared,
                "onlyA": playbook_only_a,
                "onlyB": playbook_only_b,
            },
            "actions": {
                "shared": actions_shared,
                "onlyA": actions_only_a,
                "onlyB": actions_only_b,
            },
            "verdict": " — ".join(verdict_parts),
        },
    }
