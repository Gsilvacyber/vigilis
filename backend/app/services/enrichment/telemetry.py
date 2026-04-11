"""Signal telemetry: DB-persisted enrichment analytics for the Vigilis engine.

WHY THIS EXISTS: Without telemetry, there's no way to know which signals
actually predict real threats vs which generate noise. This module records
every enrichment run and provides analytics methods for signal frequency,
effectiveness, and weight impact. The data powers the telemetry dashboard
that tells a CISO: "Our false positive rate is 8%, down from 46% industry avg."

ARCHITECTURE:
  - TelemetryCollector: singleton that records enrichment runs to DB
  - Also maintains in-memory buffer (fast reads, capped at 10K)
  - Analytics methods query DB for windowed aggregations
  - Dashboard endpoint in calibration.py consumes this
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.services.enrichment.base import Signal

logger = logging.getLogger("vigilis.telemetry")

# In-memory buffer for fast reads (also written to DB when available)
_TELEMETRY: list[dict[str, Any]] = []
_TELEMETRY_MAX = 10_000


class TelemetryCollector:
    """Records enrichment telemetry to both in-memory buffer and DB."""

    def record(
        self,
        alert_type: str,
        severity: str,
        signals: list[Signal],
        score: int,
        source_tool: str | None,
        *,
        asset_tier: str = "standard",
        user_risk_tier: str = "standard_user",
        cross_alert_flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record a single enrichment run. Persists to DB and in-memory buffer."""
        fired = [s.name for s in signals if s.fired and s.weight > 0]
        entry = {
            "alert_type": alert_type,
            "severity": severity,
            "signals_fired": fired,
            "signal_count": len(fired),
            "confidence_score": score,
            "source_tool": source_tool or "unknown",
            "asset_tier": asset_tier,
            "user_risk_tier": user_risk_tier,
            "cross_alert_flags": cross_alert_flags or [],
        }

        # In-memory buffer
        _TELEMETRY.append(entry)
        if len(_TELEMETRY) > _TELEMETRY_MAX:
            _TELEMETRY.pop(0)

        # Persist to DB (best-effort, don't block enrichment on DB failures)
        try:
            self._persist(entry)
        except Exception:
            logger.warning("Failed to persist telemetry to DB", exc_info=True)

        return entry

    def _persist(self, entry: dict[str, Any]) -> None:
        from backend.app.core.db import get_session
        from backend.app.db.models import SignalTelemetry

        with get_session() as session:
            record = SignalTelemetry(
                alert_type=entry["alert_type"],
                severity=entry["severity"],
                signals_fired=entry["signals_fired"],
                signal_count=entry["signal_count"],
                confidence_score=entry["confidence_score"],
                source_tool=entry["source_tool"],
                asset_tier=entry["asset_tier"],
                user_risk_tier=entry["user_risk_tier"],
                cross_alert_flags=entry["cross_alert_flags"],
            )
            session.add(record)
            session.commit()

    def get_buffer(self) -> list[dict[str, Any]]:
        """Return the in-memory telemetry buffer (read-only copy)."""
        return list(_TELEMETRY)

    def clear_buffer(self) -> None:
        """Clear the in-memory buffer (for tests)."""
        _TELEMETRY.clear()

    def signal_frequency(self, window_hours: int = 24) -> dict[str, int]:
        """How often each signal fires within a time window (from DB)."""
        from backend.app.core.db import get_session
        from backend.app.db.models import SignalTelemetry
        from sqlmodel import select

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        freq: dict[str, int] = defaultdict(int)

        with get_session() as session:
            stmt = select(SignalTelemetry).where(SignalTelemetry.created_at >= cutoff)
            for record in session.exec(stmt).all():
                for sig in record.signals_fired or []:
                    freq[sig] += 1

        return dict(sorted(freq.items(), key=lambda x: -x[1]))

    def signal_effectiveness(self) -> dict[str, dict[str, Any]]:
        """Precision per signal (requires calibration feedback data)."""
        from backend.app.core.db import get_session
        from backend.app.db.models import CalibrationFeedback
        from sqlmodel import select

        signal_tp: dict[str, int] = defaultdict(int)
        signal_fp: dict[str, int] = defaultdict(int)

        with get_session() as session:
            for fb in session.exec(select(CalibrationFeedback)).all():
                for sig in fb.signals_fired or []:
                    if fb.analyst_verdict == "true_positive":
                        signal_tp[sig] += 1
                    elif fb.analyst_verdict == "false_positive":
                        signal_fp[sig] += 1

        all_signals = set(signal_tp.keys()) | set(signal_fp.keys())
        result: dict[str, dict[str, Any]] = {}
        for sig in sorted(all_signals):
            tp = signal_tp.get(sig, 0)
            fp = signal_fp.get(sig, 0)
            total = tp + fp
            result[sig] = {
                "tp_count": tp,
                "fp_count": fp,
                "total": total,
                "precision": round(tp / total, 4) if total > 0 else None,
            }
        return result

    def weight_impact_analysis(self, window_hours: int = 24) -> list[dict[str, Any]]:
        """Which signals have the most cumulative score impact."""
        from backend.app.services.enrichment.weights import get_weight

        freq = self.signal_frequency(window_hours)
        impacts = []
        for sig_name, count in freq.items():
            w = get_weight(sig_name)
            impacts.append({
                "signal": sig_name,
                "weight": w,
                "fire_count": count,
                "total_impact": w * count,
            })
        return sorted(impacts, key=lambda x: abs(x["total_impact"]), reverse=True)

    def false_positive_rate(self, window_hours: int = 24) -> float | None:
        """Overall FP rate from calibration feedback."""
        from backend.app.core.db import get_session
        from backend.app.db.models import CalibrationFeedback
        from sqlmodel import select

        with get_session() as session:
            feedbacks = session.exec(select(CalibrationFeedback)).all()

        if not feedbacks:
            return None

        total = len(feedbacks)
        fp = sum(1 for f in feedbacks if f.analyst_verdict == "false_positive")
        return round(fp / total, 4) if total > 0 else None


# Module-level singleton
_collector = TelemetryCollector()


def get_collector() -> TelemetryCollector:
    return _collector
