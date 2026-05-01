"""Print a score histogram for cases currently in the engine.

Usage:
    python tools/score_histogram.py
    python tools/score_histogram.py --base http://localhost:8000 --key socai-demo-key-do-not-use-in-production

Same buckets as the README's "Tested on public data" section, so you can
reproduce the headline finding on your own upload:

    21-40  41-60  61-65  66-80  81-100

Stdlib-only by design. Drop into any Python 3.11+ environment.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib import error, request

DEFAULT_BASE = os.environ.get("VIGILIS_URL", "http://localhost:8000")
DEFAULT_KEY = os.environ.get(
    "VIGILIS_API_KEY", "socai-demo-key-do-not-use-in-production"
)

BUCKETS: list[tuple[str, int, int]] = [
    ("00-20", 0, 20),
    ("21-40", 21, 40),
    ("41-60", 41, 60),
    ("61-65", 61, 65),
    ("66-80", 66, 80),
    ("81-100", 81, 100),
]


def fetch_all_cases(base: str, key: str, page_size: int = 100) -> list[dict]:
    """Paginate through GET /api/v1/cases and return every case."""
    cases: list[dict] = []
    offset = 0
    while True:
        url = f"{base}/api/v1/cases?limit={page_size}&offset={offset}"
        req = request.Request(url, headers={"X-API-Key": key})
        try:
            with request.urlopen(req, timeout=15) as resp:
                page = json.loads(resp.read())
        except error.HTTPError as e:
            sys.exit(f"HTTP {e.code} from {url}: {e.read().decode(errors='replace')}")
        except error.URLError as e:
            sys.exit(f"Could not reach {url}: {e.reason}")

        if not page:
            break
        cases.extend(page)
        if len(page) < page_size:
            break
        offset += page_size
    return cases


def histogram(scores: list[int]) -> None:
    counts = {label: 0 for label, _, _ in BUCKETS}
    for s in scores:
        for label, lo, hi in BUCKETS:
            if lo <= s <= hi:
                counts[label] += 1
                break

    total = sum(counts.values())
    if total == 0:
        print("No cases in the engine yet. Upload some alerts first.")
        return

    width = 50
    peak = max(counts.values()) or 1
    print(f"\nScore histogram ({total} cases):\n")
    for label, _, _ in BUCKETS:
        n = counts[label]
        bar = "#" * round(n / peak * width)
        marker = "  <- cap zone" if label == "61-65" else ""
        print(f"  {label:>6} | {n:>4}  {bar}{marker}")

    crossed_cap = sum(counts[label] for label in ("66-80", "81-100"))
    print()
    if crossed_cap == 0:
        print(f"Zero of {total} cases crossed the 65 cap.")
    else:
        print(f"{crossed_cap} of {total} cases crossed the 65 cap.")
        print("Cases above 65 must have at least one verified-tier signal.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE, help="Engine base URL")
    parser.add_argument("--key", default=DEFAULT_KEY, help="X-API-Key value")
    args = parser.parse_args()

    cases = fetch_all_cases(args.base, args.key)
    scores = [c.get("confidence", {}).get("score", 0) for c in cases]
    histogram(scores)


if __name__ == "__main__":
    main()
