# SPDX-License-Identifier: Apache-2.0
"""Re-run recorded findings on a model and report an honest answer.

``sova rerun`` runs one finding capsule's AgentDojo episode again on a chosen
model and reports how often the attack worked (Wilson 95% interval), how many
runs could not be judged and why, and whether the recorded outcome was
reproduced. ``sova matrix`` does the same for findings x models x trials and can
classify findings across a model upgrade. Opening or inspecting a capsule runs
nothing; model calls need ``--authorize``.
"""

from __future__ import annotations

from sova.rerun.decision import (
    ContextMode,
    ContextRule,
    OutcomePredicate,
    PredicateOperator,
    SemanticOutcome,
    decide_reproduction,
    estimate_reproduction,
)
from sova.rerun.engine import DEFAULT_ENVELOPE, RerunOptions, RerunReport, rerun_finding
from sova.rerun.findings import Finding, load_finding
from sova.rerun.matrix import MatrixOptions, MatrixReport, classify_upgrade, run_matrix
from sova.rerun.records import OutcomeJudge, RunRecord, Verdict, benchmark_security_judge

__all__ = [
    "DEFAULT_ENVELOPE",
    "ContextMode",
    "ContextRule",
    "Finding",
    "MatrixOptions",
    "MatrixReport",
    "OutcomeJudge",
    "OutcomePredicate",
    "PredicateOperator",
    "RerunOptions",
    "RerunReport",
    "RunRecord",
    "SemanticOutcome",
    "Verdict",
    "benchmark_security_judge",
    "classify_upgrade",
    "decide_reproduction",
    "estimate_reproduction",
    "load_finding",
    "rerun_finding",
    "run_matrix",
]
