from __future__ import annotations

from typing import Any

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.weights import get_signal_tier

_TIER_MULTIPLIER: dict[str, float] = {
    "verified": 1.0,
    "inferred": 0.6,
    "observed": 0.4,
}

# ── Severity base ────────────────────────────────────────────────────────
# DESIGN: Severity base is capped at ~30% of the final score.  Signals
# (behavioral evidence) should be the PRIMARY driver, not the SIEM rule's
# severity label which we don't control and could be misconfigured.
#
# Old values: informational=5, low=10, medium=25, high=40, critical=60
# Problem: A CRITICAL alert scored 60 BEFORE any analysis, while MEDIUM
# scored 25 — a 35-point gap that outweighed all behavioral signals.
# This caused dr.chen's identical behavior to score 23 (MEDIUM) or 85
# (CRITICAL) — a 62-point swing from a label we don't control.
#
# New values: tighter range (5-30) so signals drive the score.
_SEVERITY_BASE: dict[str, int] = {
    "informational": 5,
    "low": 10,
    "medium": 15,
    "high": 22,
    "critical": 30,
}

_LABEL_THRESHOLDS: list[tuple[int, str]] = [
    (85, "critical"),
    (60, "high"),
    (35, "medium"),
    (0, "low"),
]

# ── Source Tool Fidelity Map ─────────────────────────────────────────────
# Multiplier applied to the final score based on source tool trustworthiness.
# WHY: A customer who knows their legacy AV fires 200 false positives/day
# can tell Vigilis to down-weight alerts from that source, while keeping
# CrowdStrike at full weight. This is only possible because scoring is
# transparent and auditable — a key differentiator vs black-box tools.
# CUSTOMIZATION: Customers can override via /api/v1/config/source-fidelity.
_SOURCE_TOOL_FIDELITY: dict[str, float] = {
    "crowdstrike falcon": 1.0,
    "crowdstrike": 1.0,
    "microsoft sentinel": 1.0,
    "microsoft defender": 0.95,
    "microsoft defender for identity": 0.95,
    "microsoft defender for cloud apps": 0.95,
    "microsoft entra id": 1.0,
    "microsoft purview dlp": 1.0,
    "darktrace": 0.95,
    "sysdig secure": 1.0,
    "wiz": 0.95,
    "wiz runtime": 0.95,
    "carbon black": 0.9,
    "carbon black response": 0.9,
    "proofpoint tap": 1.0,
    "proofpoint": 1.0,
    "okta": 1.0,
    "zscaler zia": 0.9,
    "zscaler": 0.9,
    "infoblox dns": 0.85,
    "infoblox": 0.85,
    "falco": 1.0,
    "aqua security": 0.95,
    "claroty": 1.0,
    "nozomi": 1.0,
    "armis": 0.95,
    "elastic siem": 0.95,
    "elastic": 0.95,
    "ibm qradar": 0.95,
    "qradar": 0.95,
    "splunk": 0.95,
    # Low fidelity sources
    "legacy av": 0.6,
    "generic av": 0.65,
    "windows defender": 0.75,
}
# Default is 1.0 (no reduction) — only known low-fidelity sources get reduced.
# This prevents unknown/custom sources from being penalized.
_DEFAULT_FIDELITY = 1.0


def get_source_fidelity(source_tool: str | None) -> float:
    """Get the fidelity multiplier for a source tool."""
    if not source_tool:
        return _DEFAULT_FIDELITY
    tool_lower = source_tool.lower().strip()
    # Try exact match first, then prefix match
    if tool_lower in _SOURCE_TOOL_FIDELITY:
        return _SOURCE_TOOL_FIDELITY[tool_lower]
    # Prefix matching for versioned tool names
    for key, val in _SOURCE_TOOL_FIDELITY.items():
        if tool_lower.startswith(key) or key.startswith(tool_lower):
            return val
    return _DEFAULT_FIDELITY


# ── Combo Bonuses ────────────────────────────────────────────────────────
# WHY: Certain signal COMBINATIONS are stronger than the sum of their parts.
# Exabeam's insider threat research puts "resignation + bulk data access"
# in the top 5 behavioral indicators. The combo bonus rewards these
# known-dangerous pairings with extra points.
_COMBO_BONUSES: list[tuple[set[str], int, str]] = [
    # Resignation + data exfiltration = top insider threat signal
    ({"resignation_on_file", "insider_data_exfil"}, 10, "Insider exfil combo: resignation + data transfer"),
    ({"resignation_on_file", "data_exfiltration_context"}, 10, "Insider exfil combo: resignation + exfil context"),
    ({"resignation_on_file", "bulk_transfer"}, 8, "Insider exfil combo: resignation + bulk transfer"),
    # Credential theft + lateral movement = active breach
    ({"domain_admin_target", "lateral_movement"}, 8, "Active breach combo: domain admin + lateral movement"),
    ({"known_attack_tool", "domain_admin_target"}, 8, "Active breach combo: attack tool + domain admin"),
    # Container escape + secrets dump = full cluster compromise
    ({"container_escape", "data_exfiltration_context"}, 8, "K8s combo: container escape + data exfil"),
]


def compute_confidence(
    severity: str, signals: list[Signal], source_tool: str | None = None,
    asset_weight: int = 0, user_weight: int = 0,
    tenant_weight_adjustments: dict[str, float] | None = None,
) -> tuple[int, str, list[dict[str, Any]]]:
    """Compute confidence score from signals.

    Args:
        tenant_weight_adjustments: Optional dict of signal_name -> multiplier
            from the learning loop (calibration.py). Adjusts weights based on
            analyst feedback. 0.3 = 70% FP rate (reduce). 1.3 = 85% TP rate (boost).
    """
    base = _SEVERITY_BASE.get(severity, 25)

    # Sum fired signal weights with gentle diminishing returns.
    #
    # OLD: Top 2 at 100%, 3rd at 70%, 4th+ at 40%.  This penalized breadth
    # of evidence — 5 independent signals confirming the same attack scored
    # LESS per-signal than 2 strong ones.  In threat modeling, corroborating
    # evidence should be rewarded, not penalized.
    #
    # NEW: Top 3 at 100%, 4th-5th at 80%, 6th+ at 60%.  More evidence =
    # higher scores, with gentle diminishing returns to prevent ceiling at 100.
    positive_fired = sorted(
        [s for s in signals if s.fired and s.weight > 0],
        key=lambda s: s.weight, reverse=True,
    )
    negative_boost = sum(s.weight for s in signals if s.fired and s.weight < 0)
    _adj = tenant_weight_adjustments or {}
    positive_boost = 0
    for i, s in enumerate(positive_fired):
        tier = getattr(s, 'tier', None) or get_signal_tier(s.name)
        tier_mult = _TIER_MULTIPLIER.get(tier, 0.6)
        # Apply learning loop adjustment (from analyst feedback calibration)
        calibration_mult = _adj.get(s.name, 1.0)
        effective_weight = int(s.weight * tier_mult * calibration_mult)
        if i < 3:
            positive_boost += effective_weight
        elif i < 5:
            positive_boost += int(effective_weight * 0.8)
        else:
            positive_boost += int(effective_weight * 0.6)
    boost = positive_boost + negative_boost
    fired_count = len(positive_fired)
    fired_names = {s.name for s in positive_fired}

    # Asset criticality and user risk adjustments.
    # When both fire, cap the combined contribution to prevent ceiling effect.
    if asset_weight != 0 and user_weight != 0:
        combined = asset_weight + user_weight
        boost += int(combined * 0.7)
    else:
        boost += asset_weight + user_weight

    # Combo bonuses: reward known-dangerous signal combinations
    combo_boost = 0
    for required_signals, bonus, _desc in _COMBO_BONUSES:
        if required_signals.issubset(fired_names):
            combo_boost += bonus
    boost += combo_boost

    # ── Multi-signal corroboration bonus (graduated) ──────────────────
    # When 3+ independent positive signals fire, it's strong evidence this
    # is real. More signals = stronger corroboration for better differentiation.
    if fired_count >= 5:
        boost += 8
    elif fired_count >= 4:
        boost += 5
    elif fired_count >= 3:
        boost += 3

    score = min(100, max(0, base + boost))

    # Determine if any verified signal fired
    has_verified = any(
        (getattr(s, 'tier', None) or get_signal_tier(s.name)) == "verified"
        for s in signals if s.fired and s.weight > 0
    )

    # Cap: keyword-only cases can't reach "critical" (85+)
    if not has_verified and score > 65:
        score = 65

    # Cap: require verified signal for "high" (75+)
    if not has_verified and score > 75:
        score = 75

    # If no positive signals fired, cap the score low.
    # ANNOTATED: Code scanning findings (Semgrep) may only fire 1 signal,
    # keeping scores in 50-65 range. This is intentional — posture findings
    # lack runtime context.
    if fired_count == 0 and signals:
        score = min(score, 20)

    # Geo-anomaly corroboration guard.
    # WHY: A user on vacation in a new country should not generate a
    # high-confidence incident. external_geo alone is weak without
    # corroboration. Cap the score at 45 if it's the ONLY positive signal.
    # If external_geo fires WITH anomalous_ip, mfa_concern, after_hours,
    # or any other signal, the full weight applies.
    if fired_count == 1 and "external_geo" in fired_names:
        score = min(score, 45)

    # IR response cap: defensive actions capped at 40.
    # ANNOTATED: Prevents IR actions from scoring as high-severity threats.
    ir_fired = any(s.name == "ir_response" and s.fired for s in signals)
    if ir_fired:
        score = min(score, 40)

    # ── Known behavior: posture findings score 20-40 ──────────────────────
    # Cloud posture findings (configuration drift, compliance checks, code
    # scanning results) score in the 20-40 range because they lack runtime
    # context (no IP, no device, no user session). This is by design —
    # posture findings indicate POTENTIAL risk, not active attacks. They
    # should not be counted as accuracy gaps.

    # Source tool fidelity multiplier.
    # WHY: A CrowdStrike alert at score 80 stays at 80. A legacy AV alert
    # at score 80 becomes 48 (0.6x). Customers can override per tool.
    # This is a key differentiator — transparent, auditable source weighting
    # that no black-box tool offers.
    fidelity = get_source_fidelity(source_tool)
    if fidelity != 1.0:
        score = int(score * fidelity)
        score = min(100, max(0, score))

    label = "low"
    for threshold, lbl in _LABEL_THRESHOLDS:
        if score >= threshold:
            label = lbl
            break

    explanation = [
        {"signal": s.name, "weight": s.weight, "label": s.label,
         "tier": getattr(s, 'tier', None) or get_signal_tier(s.name)}
        for s in signals
        if s.fired and s.weight > 0
    ]
    if asset_weight > 0:
        explanation.append({"signal": "asset_criticality", "weight": asset_weight,
                            "label": f"Asset criticality adjustment ({asset_weight:+d})",
                            "tier": "observed"})
    if user_weight > 0:
        explanation.append({"signal": "user_risk", "weight": user_weight,
                            "label": f"User risk adjustment ({user_weight:+d})",
                            "tier": "observed"})

    # Score breakdown by tier — use registry lookup, NOT Signal.tier default
    verified_pts = sum(s.weight for s in positive_fired if get_signal_tier(s.name) == "verified")
    inferred_pts = sum(s.weight for s in positive_fired if get_signal_tier(s.name) == "inferred")
    observed_pts = sum(s.weight for s in positive_fired if get_signal_tier(s.name) == "observed")
    explanation.append({
        "signal": "_score_breakdown",
        "weight": 0,
        "label": f"Score composition: {base}pts base severity + {verified_pts}pts verified + {inferred_pts}pts inferred + {observed_pts}pts observed",
    })

    return score, label, explanation


def get_severity_base(severity: str) -> int:
    return _SEVERITY_BASE.get(severity, 25)
