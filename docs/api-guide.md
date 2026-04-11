# Vigilis API Reference

## Authentication

All API requests require the `X-API-Key` header:

```
X-API-Key: <your-api-key>
```

### RBAC Roles

| Role | Permissions |
|------|-------------|
| `analyst` | Read/write cases, incidents, metrics, webhooks, upload alerts |
| `admin` | All analyst permissions + API key management + audit log access |

## Key Endpoints

### Alert Ingestion

**Single alert:**
```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {"event_type": "suspicious_signin", "event_timestamp": "2026-04-10T10:00:00Z"},
    "principal": {"user": {"userid": "jdoe@corp.com"}, "ip": "203.0.113.42"},
    "security_result": {"severity": "HIGH"}
  }'
```

**Batch upload (JSON file):**
```bash
curl -X POST http://localhost:8000/api/v1/demo/upload?grouping=true&persist=true \
  -H "X-API-Key: $API_KEY" \
  -F "file=@alerts.json"
```

**Batch upload (CSV file):**
```bash
curl -X POST http://localhost:8000/api/v1/demo/upload?grouping=true&persist=true \
  -H "X-API-Key: $API_KEY" \
  -F "file=@alerts.csv"
```

### Cases

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/cases?limit=50&offset=0` | List cases (paginated) |
| `GET` | `/api/v1/cases/{caseId}` | Get case detail with enrichment |
| `PATCH` | `/api/v1/cases/{caseId}/disposition` | Set case disposition |
| `DELETE` | `/api/v1/cases/{caseId}` | Delete a case |
| `POST` | `/api/v1/cases/bulk-disposition` | Bulk update dispositions |
| `POST` | `/api/v1/cases/bulk-delete` | Bulk delete cases |

### Incidents

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/incidents` | List correlated incidents |
| `GET` | `/api/v1/incidents/{id}` | Get incident detail with timeline |

### Jobs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/jobs` | List background jobs |
| `GET` | `/api/v1/jobs/{id}` | Get job status and progress |

### Metrics

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/metrics/summary` | Aggregate case statistics |
| `GET` | `/api/v1/metrics/ttfd` | Time-to-first-decision breakdown |
| `GET` | `/api/v1/metrics/by-alert-type` | Per-alert-type metrics |

### Admin (requires admin role)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/api-keys` | List API keys (masked) |
| `POST` | `/api/v1/admin/api-keys` | Create a new API key |
| `GET` | `/api/v1/admin/audit-log` | Query audit events |

## Webhook Integration

Configure a default webhook URL via the `WEBHOOK_DEFAULT_URL` environment variable, then trigger delivery:

```bash
# Deliver a case to the configured SOAR endpoint
curl -X POST http://localhost:8000/api/v1/cases/{caseId}/deliver-webhook \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

The webhook payload includes the full enriched case with confidence scoring, entity data, and kill-chain classification.

## Error Handling

All errors follow a standard format:

```json
{
  "detail": "Human-readable error description"
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request — invalid input data |
| `401` | Unauthorized — missing or invalid API key |
| `403` | Forbidden — insufficient role permissions |
| `404` | Not found — resource does not exist |
| `422` | Validation error — request body failed schema validation |
| `429` | Rate limited — too many requests (when Redis is configured) |
| `500` | Internal server error |

## Interactive Documentation

Full OpenAPI documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
