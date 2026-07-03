from dataclasses import dataclass
from typing import Dict, Any

@dataclass(frozen=True)
class BehaviorConfig:
    """
    Decoupled configuration parameters for behavior monitor.
    Satisfies Section 5.6 & 8.
    """
    accuracy_flag_threshold: float
    accuracy_halt_threshold: float
    overconfidence_flag_threshold: float
    overconfidence_halt_threshold: float
    guardrail_hit_flag_threshold: float
    guardrail_hit_halt_threshold: float
    latency_drift_flag_multiplier: float
    latency_drift_halt_multiplier: float

@dataclass(frozen=True)
class BehaviorReport:
    """
    Graded behavioral analysis report.
    Satisfies Section 6 (Watching Conduct Table: OK / FLAG / HALT).
    """
    agent_code: str
    status: str                       # 'OK' | 'FLAG' | 'HALT'
    metrics: Dict[str, Any]
    reason: str
