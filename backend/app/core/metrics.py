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
        Gauge,
        Histogram,
        generate_latest,
    )

    _ENABLED = True
except ImportError:

    class _Noop:
        """Silent stub for when prometheus_client is not installed."""

        def labels(self, *a, **kw):  # type: ignore[no-untyped-def]
            return self

        def inc(self, amount: float = 1) -> None:
            pass

        def observe(self, amount: float) -> None:
            pass

        def set(self, amount: float) -> None:
            pass

        def time(self):  # type: ignore[no-untyped-def]
            class _TimerCtx:
                def __enter__(self_inner):  # noqa: N805
                    return self_inner
                def __exit__(self_inner, *a):  # noqa: N805
                    pass
            return _TimerCtx()

    def _make_noop(*a, **kw):  # type: ignore[no-untyped-def]
        return _Noop()

    Counter = _make_noop  # type: ignore[assignment,misc]
    Gauge = _make_noop  # type: ignore[assignment,misc]
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


# ── Days 1-3 Quality Uplift metrics ─────────────────────────────────────
# Observability for detection pipeline: translator coverage, entity graph
# health, learning-loop visibility, feed freshness, exporter heartbeat.

sysmon_pattern_hits = Counter(
    "vigilis_sysmon_pattern_hits_total",
    "MITRE pattern matches in sysmon_translator",
    ["pattern", "tenant"],
)

sysmon_eid_fork_hits = Counter(
    "vigilis_sysmon_eid_fork_hits_total",
    "Event-ID fork branches taken in sysmon_translator",
    ["event_id", "branch"],
)

entity_graph_query_latency = Histogram(
    "vigilis_entity_graph_query_duration_seconds",
    "Latency of entity-graph relationship queries",
    ["operation"],
)

entity_graph_size = Gauge(
    "vigilis_entity_graph_relationships",
    "Current count of stored EntityRelationship rows",
    ["relationship_type"],
)

calibration_runs_total = Counter(
    "vigilis_calibration_runs_total",
    "Calibration engine executions",
)

calibration_adjusted_signals = Gauge(
    "vigilis_calibration_adjusted_signals",
    "Number of signals currently under calibration adjustment",
)

feed_age_seconds = Gauge(
    "vigilis_feed_age_seconds",
    "Seconds since last successful feed fetch",
    ["feed"],
)

feed_ingestion_total = Counter(
    "vigilis_feed_ingestion_total",
    "Feed fetch attempts",
    ["feed", "status"],
)

exporter_last_seen_seconds = Gauge(
    "vigilis_exporter_last_seen_seconds",
    "Seconds since last heartbeat from this exporter",
    ["exporter", "hostname"],
)


def is_enabled() -> bool:
    """True if prometheus_client is installed and metrics are active."""
    return _ENABLED
