# SOCAI Deployment Guide

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2+
- 2 GB RAM minimum (4 GB recommended)
- Port 8000 available (configurable)

## Quick Start

```bash
git clone <repository-url> && cd socaibuild
docker compose up -d
```

The API will be available at `http://localhost:8000`. Open `http://localhost:8000/demo/ui/` for the web dashboard.

Verify the deployment:

```bash
curl http://localhost:8000/health
# {"status":"ok","database":"connected"}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `local` | Environment mode: `local`, `staging`, `prod` |
| `APP_PORT` | `8000` | HTTP server port |
| `DATABASE_URL` | `postgresql+psycopg2://socai:socai@localhost:5432/socai` | PostgreSQL connection string |
| `DEMO_API_KEY` | `socai-demo-key-do-not-use-in-production` | Primary API key (change in production) |
| `APP_CREATE_TABLES` | `true` | Auto-create database tables on startup |
| `WEBHOOK_DEFAULT_URL` | *(empty)* | Default webhook delivery URL for SOAR integration |
| `GROUPING_WINDOW_MINUTES` | `60` | Time window for alert deduplication grouping |
| `CORRELATION_WINDOW_HOURS` | `24` | Time window for incident correlation |
| `REDIS_URL` | *(empty)* | Redis connection URL for caching (optional) |
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal API key for threat intel enrichment |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key for IP reputation lookups |
| `POSTGRES_USER` | `socai` | PostgreSQL user (Docker Compose) |
| `POSTGRES_PASSWORD` | `socai` | PostgreSQL password (Docker Compose) |
| `POSTGRES_DB` | `socai` | PostgreSQL database name (Docker Compose) |

## Production Checklist

1. **Change the API key** — Set `DEMO_API_KEY` to a strong random value:
   ```bash
   export DEMO_API_KEY=$(openssl rand -base64 32)
   ```

2. **Set a strong database password** — Update `POSTGRES_PASSWORD` and the password in `DATABASE_URL`.

3. **Configure CORS** — Restrict allowed origins to your domain if exposing the API externally.

4. **Enable TLS** — Place a reverse proxy (Caddy, Nginx, or Traefik) in front of the API:
   ```
   # Example Caddyfile
   socai.example.com {
       reverse_proxy localhost:8000
   }
   ```

5. **Disable auto-table creation** — Set `APP_CREATE_TABLES=false` and use Alembic migrations for controlled schema changes.

6. **Set `APP_ENV=prod`** — Enables startup validation warnings for unsafe defaults.

7. **Configure threat intel keys** — Set `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` for full enrichment.

## Monitoring

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness check — returns API and database status |
| `GET /api/v1/jobs` | Background job queue status |
| `GET /api/v1/metrics/summary` | Case volume, triage rates, TTFD |
| `GET /api/v1/admin/audit-log` | Security audit trail (admin role required) |
| `GET /api/v1/cache/stats` | Cache hit rates and entry counts (when Redis enabled) |

## Backup

PostgreSQL data is stored in a Docker volume. Back up with:

```bash
docker compose exec db pg_dump -U socai socai > backup_$(date +%Y%m%d).sql
```
