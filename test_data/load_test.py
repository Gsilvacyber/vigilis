"""Simple load test for SOCAI API performance baseline."""
import time
import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

BASE_URL = "http://localhost:8000"
API_KEY = "socai-demo-key-do-not-use-in-production"
HEADERS = {"X-API-Key": API_KEY}


# Generate a small test alert batch
def make_alerts(n: int) -> list[dict]:
    return [
        {
            "metadata": {"event_type": "suspicious_signin", "event_timestamp": f"2026-04-10T{8+i%12}:{i%60:02d}:00Z"},
            "principal": {"user": {"userid": f"user{i}@test.com"}, "ip": f"10.0.{i//256}.{i%256}"},
            "security_result": {"severity": "HIGH"},
        }
        for i in range(n)
    ]


def upload_batch(alerts: list[dict]) -> tuple[float, int]:
    """Upload a batch and return (duration_seconds, status_code)."""
    content = json.dumps(alerts)
    start = time.monotonic()
    with httpx.Client(timeout=60) as client:
        resp = client.post(
            f"{BASE_URL}/api/v1/demo/upload?grouping=true&persist=true",
            headers={**HEADERS, "Content-Type": "multipart/form-data"},
            files={"file": ("test.json", content.encode(), "application/json")},
        )
    duration = time.monotonic() - start
    return duration, resp.status_code


def run_load_test():
    print("=== SOCAI Load Test ===\n")

    # Reset first
    httpx.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)

    # Test 1: Sequential uploads of increasing size
    print("--- Sequential Upload Performance ---")
    for size in [10, 50, 100, 200]:
        alerts = make_alerts(size)
        httpx.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
        duration, status = upload_batch(alerts)
        rate = size / duration if duration > 0 else 0
        print(f"  {size:4d} alerts: {duration:.2f}s ({rate:.0f} alerts/sec) HTTP {status}")

    # Test 2: Concurrent uploads
    print("\n--- Concurrent Upload Performance (5 threads x 50 alerts) ---")
    httpx.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
    batches = [make_alerts(50) for _ in range(5)]
    durations = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(upload_batch, b) for b in batches]
        for f in as_completed(futures):
            d, s = f.result()
            durations.append(d)
            print(f"  Thread completed: {d:.2f}s HTTP {s}")

    print(f"\n  p50: {statistics.median(durations):.2f}s")
    if len(durations) > 1:
        print(f"  p95: {sorted(durations)[int(len(durations)*0.95)]:.2f}s")
    print(f"  Total throughput: {250 / max(durations):.0f} alerts/sec")

    # Test 3: API response times
    print("\n--- API Response Times (10 requests each) ---")
    endpoints = [
        ("GET", "/health"),
        ("GET", "/api/v1/cases?limit=10"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/metrics/summary"),
    ]
    for method, path in endpoints:
        times = []
        for _ in range(10):
            start = time.monotonic()
            httpx.request(method, f"{BASE_URL}{path}", headers=HEADERS)
            times.append((time.monotonic() - start) * 1000)
        avg = statistics.mean(times)
        p95 = sorted(times)[8]
        print(f"  {method} {path}: avg={avg:.0f}ms p95={p95:.0f}ms")


if __name__ == "__main__":
    run_load_test()
