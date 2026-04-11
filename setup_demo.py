"""Clean demo setup: reset DB, upload CSV, correlate incidents.

Usage:
    python setup_demo.py [path/to/demo.csv]

If no path is provided, looks for `vigilis_demo_dataset.csv` in the current
working directory, then in sample_data/.
"""
import os
import sys
import requests

AK = os.getenv("DEMO_API_KEY", "socai-demo-key-do-not-use-in-production")
BASE = os.getenv("VIGILIS_URL", "http://localhost:8000")
h = {"X-API-Key": AK}


def _find_csv() -> str:
    """Locate the demo CSV from CLI arg, CWD, or sample_data/."""
    if len(sys.argv) > 1:
        return sys.argv[1]
    for candidate in (
        "vigilis_demo_dataset.csv",
        os.path.join("sample_data", "vigilis_demo_dataset.csv"),
        os.path.join("sample_data", "sentinel_export.csv"),
    ):
        if os.path.isfile(candidate):
            return candidate
    print("ERROR: No demo CSV found. Pass one as an argument:")
    print("  python setup_demo.py path/to/demo.csv")
    sys.exit(1)


csv_path = _find_csv()
print(f"Using demo CSV: {csv_path}")

print("1. Resetting database...")
r = requests.post(f"{BASE}/api/v1/demo/reset", headers=h)
print(f"   {r.json()}")

print("2. Uploading demo dataset...")
with open(csv_path, "rb") as f:
    r = requests.post(f"{BASE}/api/v1/demo/upload?persist=true", headers=h,
                       files={"file": ("demo.csv", f, "text/csv")})
data = r.json()
print(f"   {data['processed']} cases, {data['errors']} errors")
scores = [x["score"] for x in data["results"]]
print(f"   Scores: {scores}")

print("3. Correlating incidents...")
r = requests.post(f"{BASE}/api/v1/incidents/correlate", headers=h)
print(f"   Status: {r.status_code}")

print("4. Checking results...")
r = requests.get(f"{BASE}/api/v1/incidents", headers=h)
incs = r.json()
print(f"   {len(incs)} incidents:")
for inc in incs:
    print(f"   - {inc['title']} (score={inc['confidenceScore']})")

r = requests.get(f"{BASE}/api/v1/cases?tenantId=demo-tenant&limit=50", headers=h)
cases = r.json()
print(f"   {len(cases)} total cases")

print(f"\nDone! Open {BASE}/demo/ui/cases")
