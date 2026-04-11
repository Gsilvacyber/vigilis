# Vigilis Integration Example

Copy-paste-friendly integration guide. Connect your alert pipeline to Vigilis in under 1 day.

## Requirements

| What | Details |
|------|---------|
| **Input** | JSON payload (any raw alert format) |
| **Output** | Normalized `case.v0.2` with enrichment, scoring, playbooks, actions |
| **Webhook** | 1 webhook endpoint on your SOAR/ticketing system |
| **Auth** | 1 API key (coming soon — not required for MVP) |
| **Integration time** | < 1 day |

---

## Step 1: Send a raw alert

```bash
curl -X POST http://your-vigilis-host:8000/api/v1/demo/enrich-raw \
  -H "Content-Type: application/json" \
  -d '{
    "alertType": "identity.suspiciousSignIn",
    "tenantId": "acme-corp",
    "persist": true,
    "rawAlert": {
      "identity": {
        "identityType": "user",
        "userId": "u-12345",
        "upn": "jdoe@acme.com",
        "displayName": "John Doe",
        "privilegeTier": "admin",
        "mfaStatus": "disabled",
        "riskLevel": "high"
      },
      "ips": [
        {
          "role": "anomalous",
          "ipAddress": "203.0.113.42",
          "geo": { "country": "RU", "city": "Moscow" }
        },
        {
          "role": "legitimate",
          "ipAddress": "10.0.0.55",
          "geo": { "country": "US", "city": "Seattle" }
        }
      ],
      "device": {
        "deviceId": "d-unknown",
        "hostname": "UNMANAGED-PC",
        "managed": false,
        "os": "Linux"
      }
    }
  }'
```

## Step 2: Receive enriched case

Response (trimmed for clarity):

```json
{
  "schemaVersion": "case.v0.2",
  "caseId": "a1b2c3d4-...",
  "alertType": "identity.suspiciousSignIn",
  "severity": "medium",

  "confidence": {
    "score": 85,
    "label": "critical",
    "explanation": [
      { "signal": "anomalous_ip", "weight": 10 },
      { "signal": "impossible_travel", "weight": 15 },
      { "signal": "unmanaged_device", "weight": 8 },
      { "signal": "mfa_concern", "weight": 10 },
      { "signal": "high_risk_level", "weight": 12 }
    ]
  },

  "enrichment": {
    "riskScore": 85,
    "impactSummary": {
      "risk": "Account takeover likely — active unauthorized session detected",
      "timeSavedMinutes": 34,
      "manualStepsReplaced": [
        "Correlate sign-in logs across IdP and SIEM",
        "Check IP reputation via threat intel feeds",
        "Verify MFA enrollment and recent challenges",
        "Review device compliance and registration",
        "Contact user to confirm activity"
      ]
    },
    "caseReadiness": {
      "readyForAction": true,
      "missingContext": [],
      "confidenceLevel": "critical"
    }
  },

  "recommendedPlaybook": [
    { "step": 1, "title": "Review sign-in logs", "description": "Check recent authentication events..." },
    { "step": 2, "title": "Correlate IP geolocation", "description": "Map source IPs to known locations..." },
    { "step": 3, "title": "Validate device compliance", "description": "Verify device registration..." },
    { "step": 4, "title": "Contact user for verification", "description": "Reach out to account owner..." },
    { "step": 5, "title": "Revoke sessions if malicious", "description": "Terminate all sessions..." }
  ],

  "recommendedActions": [
    { "action": "review_sign_in_logs", "title": "Review Sign-in Logs", "priority": "high" },
    { "action": "validate_user", "title": "Validate User Identity", "priority": "high" },
    { "action": "block_ip", "title": "Block Anomalous IP", "priority": "high" },
    { "action": "revoke_sessions", "title": "Revoke Active Sessions", "priority": "critical" }
  ]
}
```

## Step 3: Configure webhook delivery

Register your SOAR endpoint:

```bash
curl -X POST http://your-vigilis-host:8000/api/v1/config/webhooks \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme SOAR", "url": "https://soar.acme.com/api/ingest", "enabled": true}'
```

## Step 4: Deliver case to SOAR

```bash
curl -X POST http://your-vigilis-host:8000/api/v1/cases/{caseId}/deliver-webhook \
  -H "Content-Type: application/json" \
  -d '{"webhookUrl": "https://soar.acme.com/api/ingest"}'
```

The webhook payload is the full `case.v0.2` JSON — your SOAR receives a fully enriched, scored case with playbook and actions attached.

## Step 5: Export for external systems

```bash
curl http://your-vigilis-host:8000/api/v1/cases/{caseId}/export
```

Returns:

```json
{
  "exportVersion": "1.0",
  "exportedAt": "2026-03-26T12:00:00Z",
  "format": "case.v0.2",
  "case": { "...full case.v0.2 payload..." }
}
```

---

## Integration Architecture

```
Your Alert Source          Vigilis                      Your SOAR/Ticketing
(SIEM, EDR, IdP)    ┌──────────────────┐
       │             │  Normalize        │
  raw JSON ────────> │  Enrich (rules)   │ ────── webhook ────> Create ticket
       │             │  Score confidence  │                     Run playbook
       │             │  Generate playbook │                     Assign analyst
       │             └──────────────────┘
                            │
                     Persist case.v0.2
                     Track disposition
                     Measure TTFD
```

## Supported Alert Types

| Type | Source System | Example |
|------|-------------|---------|
| `identity.suspiciousSignIn` | IdP (Entra ID, Okta) | Impossible travel, anomalous IP |
| `identity.passwordSpray` | IdP | Bulk failed logins, eventual success |
| `identity.mfaFatigue` | IdP | Repeated MFA prompts, acceptance |
| `identity.oauthConsentRisk` | IdP | Unknown app, broad scopes |
| `identity.privilegeElevation` | IdP | Admin role grant, unusual actor |
| `endpoint.malwareDetection` | EDR | Rare binary, suspicious path |
| `endpoint.suspiciousProcess` | EDR | Encoded PowerShell, LOLBin chain |
| `email.forwardingRule` | Email gateway | External forwarding, exec mailbox |
| `cloud.secretStoreAccessAnomaly` | Cloud (Azure, AWS) | New app accessing secrets |
| `network.impossibleGeoAccess` | Network/IdP | Multi-country simultaneous auth |

## What Vigilis Replaces

For each alert, Vigilis eliminates 4-5 manual analyst steps:

| Manual Step | Vigilis Equivalent |
|-------------|-----------------|
| Correlate logs across tools | Automatic signal extraction |
| Check IP reputation | Built-in anomalous IP detection |
| Assess severity | Confidence scoring (0-100) |
| Write investigation notes | Auto-generated enrichment notes |
| Decide investigation path | Recommended playbook + actions |
| Document in ticket | Structured case.v0.2 delivered via webhook |
