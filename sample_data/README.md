# Sample SIEM Export Files

These files are synthetic test fixtures for the Vigilis upload pipeline. They exercise the `alert_mapper.py` field-detection heuristics, CSV parsing, and normalizer edge cases.

---

## splunk_export.csv

Mimics a Splunk security alert export. Columns match common Splunk field names that are already in the mapper's candidate sets (`src_user`, `src_ip`, `dest_ip`, `host`, `severity`, `signature`, `category`, `action`).

**What it tests:**

- Standard happy-path field mapping via `_IDENTITY_FIELDS` (`src_user`), `_IP_FIELDS` (`src_ip`), `_DEST_IP_FIELDS` (`dest_ip`), `_DEVICE_FIELDS` (`host`), `_SEVERITY_FIELDS` (`severity`).
- Alert-type classification via keyword matching in `signature` and `category` fields (suspicious login, password spray, malware, suspicious process).
- **Row 5 (`lchen`)** — missing `severity` field (empty string). `parse_severity()` should fall back to `"medium"`.
- **Row 3 (`bwilliams`)** — source IP `185.220.101.45`, a non-RFC1918 address associated with Tor exit nodes. Tests that anomalous external IPs pass through without being rejected.
- **Row 9 (`fmartinez`)** — `signature` value contains a comma inside a quoted field (`"Password Spray, Multiple Accounts Targeted"`). Tests that the CSV parser handles RFC 4180 quoting correctly.

---

## sentinel_export.csv

Mimics a Microsoft Sentinel alert export. Columns use Azure/Sentinel naming conventions (`TimeGenerated`, `UserPrincipalName`, `IPAddress`, `ComputerName`, `AlertSeverity`, `AlertName`, `TenantId`).

**What it tests:**

- Sentinel-style field names that are present in the mapper's candidate sets: `UserPrincipalName` → `_IDENTITY_FIELDS`, `IPAddress` → `_IP_FIELDS`, `ComputerName` → `_DEVICE_FIELDS`, `AlertSeverity` → `_SEVERITY_FIELDS`, `AlertName` → `_ALERT_NAME_FIELDS`.
- Azure-format UPNs (`user@contoso.com`, `user@fabrikam.com`) and GUID-format tenant IDs.
- Alert-type keyword coverage: MFA fatigue (`mfa`, `push fatigue`), impossible travel (`impossible travel`, `atypical travel`), OAuth consent risk (`oauth`, `consent`, `app permission`), suspicious sign-in (`sign-in`, `suspicious login`, `anonymous`).
- Two distinct tenant IDs to confirm tenant isolation is not broken by the mapper.
- Row 6 (`frank.wolfe`) — `AlertSeverity=Critical`, tests the critical severity path in `parse_severity()`.

---

## mixed_edge_cases.csv

A deliberately adversarial file. Column names are intentionally chosen to fall **outside** the mapper's current candidate sets, or to use variant formats the mapper has not seen:

| Column | Why it is tricky |
|---|---|
| `SourceIP` | Not in `_IP_FIELDS` (`sourceip` without separator is covered, but `SourceIP` camelCase variant may not normalise cleanly depending on the `.lower().strip()` path) |
| `Computer_Name` | Not in `_DEVICE_FIELDS` (covered: `computername`, but `computer_name` with underscore is absent) |
| `EventSeverity` | Not in `_SEVERITY_FIELDS` (covered values: `severity`, `alertseverity`, `threat_level`, `risk_level` — but not `eventseverity`) |
| `AlertTitle` | Not in `_ALERT_NAME_FIELDS` (covered: `alertname`, `alert_name`, `title` — but not `alerttitle` as one token) |
| `UserDisplay` | Not in `_IDENTITY_FIELDS` — should cause the mapper to fall back to `unknown@upload` for the UPN |

**What it tests:**

- **Row 3** — both `UserDisplay` and `EventSeverity` are empty. The mapper must not crash; it should produce `upn=unknown@upload` and severity `"medium"`.
- **Row 2** — `EventSeverity="10"`. An unrecognised numeric severity that does not match any label in `parse_severity()`. Should fall back to `"medium"`.
- **Row 4** — `UserDisplay` contains a non-English display name with CJK characters and a parenthetical (`佐藤 健太 (Kenta Sato)`). No `@` in the value. Tests that `displayName` extraction and the `upn.split("@")[0]` guard do not raise.
- **Row 4** also carries `AlertTitle="Impossible Geo Access Detected"` and `SourceIP=203.0.113.55` — tests that `guess_alert_type()` still classifies this as `network.impossibleGeoAccess` from keyword matching alone, even when the IP and device fields are not recognised by the mapper.
- **Row 8** — `UserDisplay="unknown_service_acct"` (no `@`). Tests the `upn.split("@")[0]` fallback path where the value has no domain component.
