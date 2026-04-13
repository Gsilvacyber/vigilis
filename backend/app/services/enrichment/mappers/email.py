from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.weights import W
from backend.app.services.enrichment.base import (
    Signal,
    has_anomalous_ip,
    has_insider_threat_context,
    has_persistence_context,
    has_ransomware_context,
    has_supply_chain_context,
    is_privileged_identity,
)


def _get_domain(addr: str | None) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.split("@", 1)[1].lower()


def _is_external_forward(raw: dict[str, Any]) -> bool:
    mb = raw.get("mailbox") or {}
    d_primary = _get_domain(mb.get("primaryAddress"))
    d_forward = _get_domain(mb.get("forwardingAddress"))
    if not d_forward:
        return False
    if not d_primary:
        return True
    return d_primary != d_forward


def _rule_obfuscation(raw: dict[str, Any]) -> bool:
    mb = raw.get("mailbox") or {}
    name = (mb.get("ruleName") or "").strip()
    if not name or len(name) <= 2:
        return True
    suspicious = {"forward", "fwd", "redirect", "auto", ".", "hidden"}
    lower = name.lower()
    return any(s in lower for s in suspicious)


_SUSPICIOUS_DOMAINS = frozenset({
    "proton.me", "protonmail.com", "tutanota.com", "guerrillamail.com",
    "mailinator.com", "tempmail.com", "yopmail.com", "10minutemail.com",
})


def _is_suspicious_drop(raw: dict[str, Any]) -> bool:
    mb = raw.get("mailbox") or {}
    fwd = mb.get("forwardingAddress") or ""
    domain = _get_domain(fwd)
    return domain in _SUSPICIOUS_DOMAINS


def extract_forwarding_rule(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    mb = raw.get("mailbox") or {}
    fwd_addr = mb.get("forwardingAddress") or ""
    fwd_domain = _get_domain(fwd_addr)
    return [
        Signal("external_forward", W["external_forward"], _is_external_forward(raw),
               f"Forwarding to external domain ({fwd_domain})" if fwd_domain else "Forwarding to external email domain"),
        Signal("suspicious_drop_target", W["suspicious_drop_target"], _is_suspicious_drop(raw),
               f"Forwarding to known anonymous/disposable provider ({fwd_domain})"),
        Signal("privileged_mailbox", W["privileged_mailbox"], is_privileged_identity(raw),
               "Forwarding rule on privileged mailbox"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Rule created from external anomalous IP"),
        Signal("rule_obfuscation", W["rule_obfuscation"], _rule_obfuscation(raw),
               "Rule name suggests obfuscation or automated creation"),
        Signal("phishing_context", W["phishing_context"],
               _has_phishing_context(raw),
               "Alert context indicates phishing or social engineering"),
        Signal("targets_executive", W["targets_executive"],
               _targets_executive(raw),
               "Phishing targeting executive or high-value account"),
        Signal("insider_persistence", W["insider_persistence"], has_persistence_context(raw),
               "Hidden forwarding rule creating persistent exfiltration channel"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators — resignation or unauthorized rule creation"),
        Signal("hidden_rule_flag", W["hidden_rule_flag"], raw.get("_ruleHidden") is True,
               "Inbox rule is explicitly hidden — persistence mechanism"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — forwarding rule may be exfiltration channel"),
        Signal("lookalike_domain", W["lookalike_domain"],
               (raw.get("_lookalikeScore") or 0) > 0.8,
               f"Lookalike domain detected (similarity: {raw.get('_lookalikeScore',0)})"),
        Signal("new_domain", W["new_domain"],
               (raw.get("_domainAgeDays") or 999) < 30,
               f"Domain registered {raw.get('_domainAgeDays',0)} days ago"),
        Signal("financial_fraud", W["financial_fraud"],
               (raw.get("_financialImpact") or 0) > 0,
               f"Financial impact confirmed: ${raw.get('_financialImpact',0):,.0f}"),
        Signal("wire_transfer_context", W["wire_transfer_context"],
               _has_wire_context(raw),
               "Wire transfer or payment fraud indicators detected"),
        Signal("source_high_risk", W["source_high_risk"], (raw.get("_sourceRiskScore") or 0) >= 80,
               f"Source system risk score: {raw.get('_sourceRiskScore',0)}"),
        Signal("supply_chain_attack", W["supply_chain_attack"], has_supply_chain_context(raw),
               "Supply chain attack — CI/CD pipeline or distribution compromise"),
        Signal("targets_finance", W["targets_finance"], _targets_finance(raw),
               "Phishing targeting finance, accounts payable, or billing"),
        Signal("urgency_pressure", W["urgency_pressure"], _has_urgency_pressure(raw),
               "Social engineering using urgency, secrecy, or authority"),
        Signal("ransomware_extortion", W["ransomware_extortion"], has_ransomware_context(raw),
               "Ransomware extortion — ransom demand, data exfil threat, or payment deadline"),
        # Catch-all: ensures every forwardingRule/phishingDetected case has at least 1 signal
        Signal("email_activity", W.get("email_activity", 1),
               True,
               "Email event detected"),
    ]


def _targets_finance(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    identity = raw.get("identity") or {}
    upn = (identity.get("upn") or "").lower()
    combined = f"{ctx} {upn}"
    return any(kw in combined for kw in [
        "finance", "accounts payable", "ap_", "billing",
        "treasury", "payment", "wire", "invoice",
    ])


def _has_urgency_pressure(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    return any(kw in combined for kw in [
        "urgent", "immediately", "time-sensitive", "do not discuss",
        "nda required", "board approval", "deadline",
        "impersonat", "spoofed", "lookalike",
    ])


def _has_wire_context(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    return any(kw in combined for kw in ["wire transfer", "wire request", "wire confirm",
                                          "payment fraud", "banking details", "invoice fraud",
                                          "urgent wire", "ceo fraud", "cfo fraud"])


def _has_phishing_context(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    return any(kw in combined for kw in ["phish", "impersonat", "spearphish", "social engineer", "malicious email", "credential harvest"])


def _targets_executive(raw: dict[str, Any]) -> bool:
    ctx = (raw.get("_additionalContext") or "").lower()
    identity = raw.get("identity") or {}
    upn = (identity.get("upn") or "").lower()
    combined = f"{ctx} {upn}"
    return any(kw in combined for kw in ["ceo", "cfo", "cto", "ciso", "coo", "executive", "director", "vp ", "vice president"])


# ---------------------------------------------------------------------------
# email.businessEmailCompromise
# ---------------------------------------------------------------------------

def extract_business_email_compromise(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    mb = raw.get("mailbox") or {}
    fwd_domain = _get_domain(mb.get("forwardingAddress"))
    return [
        Signal("executive_impersonation", W["executive_impersonation"],
               _targets_executive(raw),
               "BEC targeting executive — CEO/CFO impersonation detected"),
        Signal("wire_transfer_context", W["wire_transfer_context"], _has_wire_context(raw),
               "Wire transfer or payment fraud indicators in BEC"),
        Signal("lookalike_domain", W["lookalike_domain"],
               (raw.get("_lookalikeScore") or 0) > 0.8,
               f"Lookalike sender domain (similarity: {raw.get('_lookalikeScore', 0)})"),
        Signal("new_domain", W["new_domain"],
               (raw.get("_domainAgeDays") or 999) < 30,
               f"Sender domain registered {raw.get('_domainAgeDays', 0)} days ago"),
        Signal("urgency_pressure", W["urgency_pressure"], _has_urgency_pressure(raw),
               "Social engineering using urgency, secrecy, or authority pressure"),
        Signal("targets_finance", W["targets_finance"], _targets_finance(raw),
               "BEC targeting finance, accounts payable, or billing personnel"),
        Signal("financial_fraud", W["financial_fraud"],
               (raw.get("_financialImpact") or 0) > 0,
               f"Financial impact confirmed: ${raw.get('_financialImpact', 0):,.0f}"),
        Signal("phishing_context", W["phishing_context"], _has_phishing_context(raw),
               "Phishing or social engineering context in BEC"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "BEC email sent from anomalous IP"),
        Signal("privileged_mailbox", W["privileged_mailbox"], is_privileged_identity(raw),
               "BEC targeting privileged mailbox"),
        Signal("external_forward", W["external_forward"], _is_external_forward(raw),
               f"Auto-forwarding to external domain ({fwd_domain})" if fwd_domain else "External forwarding detected"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators in BEC context"),
        # Catch-all: ensures every businessEmailCompromise case has at least 1 signal
        Signal("email_activity", W.get("email_activity", 1),
               True,
               "Email event detected"),
    ]


# ---------------------------------------------------------------------------
# email.maliciousAttachment
# ---------------------------------------------------------------------------

def extract_malicious_attachment(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    file_data = raw.get("file") or {}
    return [
        Signal("malicious_attachment", W["malicious_attachment"],
               bool(file_data.get("sha256") or raw.get("_fileHash")),
               "Malicious attachment detected with known hash"),
        Signal("macro_enabled", W["macro_enabled"],
               bool(raw.get("_macroEnabled")),
               "Attachment contains enabled macros — execution risk"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Malicious email from anomalous IP"),
        Signal("phishing_context", W["phishing_context"], _has_phishing_context(raw),
               "Phishing context associated with malicious attachment"),
        Signal("targets_executive", W["targets_executive"], _targets_executive(raw),
               "Malicious attachment targeting executive account"),
        Signal("privileged_mailbox", W["privileged_mailbox"], is_privileged_identity(raw),
               "Malicious attachment sent to privileged mailbox"),
        Signal("ransomware_context", W["ransomware_context"], has_ransomware_context(raw),
               "Ransomware indicators in attachment context"),
        Signal("supply_chain_attack", W["supply_chain_attack"], has_supply_chain_context(raw),
               "Supply chain attack via malicious attachment"),
        Signal("urgency_pressure", W["urgency_pressure"], _has_urgency_pressure(raw),
               "Social engineering pressure to open attachment"),
        Signal("source_high_risk", W["source_high_risk"], (raw.get("_sourceRiskScore") or 0) >= 80,
               f"Source system risk score: {raw.get('_sourceRiskScore', 0)}"),
        Signal("new_domain", W["new_domain"],
               (raw.get("_domainAgeDays") or 999) < 30,
               f"Sender domain registered {raw.get('_domainAgeDays', 0)} days ago"),
        Signal("insider_persistence", W["insider_persistence"], has_persistence_context(raw),
               "Attachment may establish persistence mechanism"),
        # Catch-all: ensures every maliciousAttachment case has at least 1 signal
        Signal("email_activity", W.get("email_activity", 1),
               True,
               "Email event detected"),
    ]


EMAIL_EXTRACTORS = {
    "email.forwardingRule": extract_forwarding_rule,
    "email.phishingDetected": extract_forwarding_rule,  # Reuse — shares same signal extraction logic
    "email.businessEmailCompromise": extract_business_email_compromise,
    "email.maliciousAttachment": extract_malicious_attachment,
}
