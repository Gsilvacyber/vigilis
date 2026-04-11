"""Prometheus metrics -- optional runtime observability.

If prometheus_client is not installed, all metric objects become no-op stubs
so instrumented code doesn't need try/except guards.  Install with:
    pip install prometheus_client

Metrics are served at GET /metrics in Prometheus text exposition format.
"""
from __future__ import annotations

_ENABLED = False

try:
    from prometheus_client import (  # type: ignore[import-untyped]
        CONTENT_TYPE_LATEST,
        Counter,
        Histogram,
        generate_latest,
    )

    _ENABLED = True
except ImportError:

    class _Noop:
        """Silent stub for when prometheus_client is not installed."""

        def labels(self, **kw):  # type: ignore[no-untyped-def]
            return self

        def inc(self, amount: float = 1) -> None:
            pass

        def observe(self, amount: float) -> None:
            pass

    def _make_noop(*a, **kw):  # type: ignore[no-untyped-def]
        return _Noop()

    Counter = _make_noop  # type: ignore[assignment,misc]
    Histogram = _make_noop  # type: ignore[assignment,misc]
    generate_latest = lambda: b""  # type: ignore[assignment]  # noqa: E731
    CONTENT_TYPE_LATEST = "text/plain"


# ── Metric definitions ──────────────────────────────────────────────────

enrichment_latency = Histogram(
    "vigilis_enrichment_latency_seconds",
    "Time to enrich a single alert",
    ["alert_type"],
)

alerts_ingested = Counter(
    "vigilis_alerts_ingested_total",
    "Total alerts ingested",
    ["source_system"],
)

cases_created = Counter(
    "vigilis_cases_created_total",
    "Total cases created",
)

incidents_created = Counter(
    "vigilis_incidents_created_total",
    "Total incidents created",
)

threat_intel_lookups = Counter(
    "vigilis_threat_intel_lookups_total",
    "Threat intel provider lookups",
    ["provider", "indicator_type", "result"],
)

signals_fired = Counter(
    "vigilis_signals_fired_total",
    "Enrichment signals that fired",
    ["signal_name", "tier"],
)


def is_enabled() -> bool:
    """True if prometheus_client is installed and metrics are active."""
    return _ENABLED
