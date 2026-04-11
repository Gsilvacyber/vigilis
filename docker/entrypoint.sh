#!/bin/sh
set -e

echo "[entrypoint] Waiting for Postgres..."
python -c "
import os, time, sys
from sqlalchemy import create_engine
url = os.environ['DATABASE_URL']
for i in range(30):
    try:
        create_engine(url).connect().close()
        print('[entrypoint] Postgres is ready')
        sys.exit(0)
    except Exception as e:
        time.sleep(1)
sys.exit('[entrypoint] Postgres did not come up in 30s')
"

echo "[entrypoint] Checking Alembic state vs existing schema..."
python <<'PY'
import os
from sqlalchemy import create_engine, inspect
try:
    engine = create_engine(os.environ["DATABASE_URL"])
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    schema_exists = "cases" in tables
    has_version = "alembic_version" in tables
    if schema_exists and not has_version:
        print("[entrypoint] Schema exists but alembic_version missing — will stamp head")
        import subprocess
        result = subprocess.run(["alembic", "stamp", "head"], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print("[entrypoint] WARNING: alembic stamp failed:", result.stderr)
        else:
            print("[entrypoint] Stamped to head successfully")
    else:
        print(f"[entrypoint] Alembic state consistent (schema={schema_exists}, version_table={has_version})")
except Exception as e:
    print(f"[entrypoint] WARNING: could not check alembic state: {e}")
PY

echo "[entrypoint] Running Alembic migrations..."
alembic upgrade head || echo "[entrypoint] Alembic upgrade failed (will fall back to create_all)"

echo "[entrypoint] Ensuring schema is current (create_all fallback for models not in migrations)..."
python -c "
from backend.app.core.db import engine
from sqlmodel import SQLModel
from backend.app.db import models  # noqa: F401
SQLModel.metadata.create_all(engine)
print('[entrypoint] Schema ready')
"

echo "[entrypoint] Starting uvicorn..."
exec uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
