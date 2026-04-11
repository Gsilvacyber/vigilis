"""Correlation sub-package — incident correlation engine internals.

Re-exports the public API so callers can import from the package directly.
"""
from backend.app.services.correlation.clustering import (
    ClusterResult,
    cluster_cases,
    extract_entities,
    merge_entities,
    build_linkage_reasons,
    build_link_strength_summary,
    CORRELATION_WINDOW_HOURS,
    _LINK_THRESHOLD,
)
from backend.app.services.correlation.kill_chain import (
    KILL_CHAIN_STAGES,
    _ALERT_TYPE_TO_STAGE,
    _STAGE_LABELS,
    _STAGE_ORDER,
    get_stage,
    refine_cloud_stage,
    stage_order,
    analyze_kill_chain_gaps,
)
from backend.app.services.correlation.scoring import (
    _SEVERITY_RANK,
    compute_confidence,
    compute_severity,
    compute_risk,
)
from backend.app.services.correlation.narrative import (
    generate_title,
    generate_summary,
    build_narrative,
    generate_recommended_actions,
    predict_workflow,
)

__all__ = [
    "ClusterResult",
    "cluster_cases",
    "extract_entities",
    "merge_entities",
    "build_linkage_reasons",
    "build_link_strength_summary",
    "CORRELATION_WINDOW_HOURS",
    "KILL_CHAIN_STAGES",
    "_ALERT_TYPE_TO_STAGE",
    "_STAGE_LABELS",
    "_STAGE_ORDER",
    "get_stage",
    "refine_cloud_stage",
    "stage_order",
    "analyze_kill_chain_gaps",
    "compute_confidence",
    "compute_severity",
    "compute_risk",
    "generate_title",
    "generate_summary",
    "build_narrative",
    "generate_recommended_actions",
    "predict_workflow",
    "_SEVERITY_RANK",
    "_LINK_THRESHOLD",
]
