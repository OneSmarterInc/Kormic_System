from typing import List, Dict, Any
from kormic.models.behavior import BehaviorConfig, BehaviorReport

class BehaviorMonitor:
    """
    Decoupled Behavioral Monitor.
    Satisfies Section 5.6 & 9.
    Evaluates rolling metrics windows against tunable configurations and policies.
    """
    def __init__(self, config: BehaviorConfig):
        self._config = config

    def evaluate(self, agent_code: str, metrics: Dict[str, Any]) -> BehaviorReport:
        """
        Evaluates metrics against configured thresholds.
        Returns a graded BehaviorReport: OK, FLAG, or HALT.
        
        Expected metric dictionary format keys:
        - accuracy (float: 0.0 to 1.0)
        - overconfidence (float: stating confidence margin minus accuracy)
        - guardrail_hit_rate (float: percentage of boundary touches)
        - latency_drift (float: multiplier compared to historical baseline)
        - policy_violation (bool: immediate halt trigger)
        """
        # 1. Check for immediate hard policy violation (absolute rule)
        if metrics.get("policy_violation", False):
            return BehaviorReport(
                agent_code=agent_code,
                status="HALT",
                metrics=metrics,
                reason="Immediate HALT: Hard policy violation triggered."
            )

        # 2. Check HALT conditions (highest priority)
        if metrics.get("accuracy", 1.0) < self._config.accuracy_halt_threshold:
            return BehaviorReport(
                agent_code=agent_code,
                status="HALT",
                metrics=metrics,
                reason=f"HALT: Accuracy ({metrics['accuracy']:.2f}) fell below halt threshold ({self._config.accuracy_halt_threshold:.2f})."
            )

        if metrics.get("overconfidence", 0.0) > self._config.overconfidence_halt_threshold:
            return BehaviorReport(
                agent_code=agent_code,
                status="HALT",
                metrics=metrics,
                reason=f"HALT: Overconfidence ({metrics['overconfidence']:.2f}) exceeded halt threshold ({self._config.overconfidence_halt_threshold:.2f})."
            )

        if metrics.get("guardrail_hit_rate", 0.0) > self._config.guardrail_hit_halt_threshold:
            return BehaviorReport(
                agent_code=agent_code,
                status="HALT",
                metrics=metrics,
                reason=f"HALT: Guardrail hit rate ({metrics['guardrail_hit_rate']:.2f}) exceeded halt threshold ({self._config.guardrail_hit_halt_threshold:.2f})."
            )

        if metrics.get("latency_drift", 1.0) > self._config.latency_drift_halt_multiplier:
            return BehaviorReport(
                agent_code=agent_code,
                status="HALT",
                metrics=metrics,
                reason=f"HALT: Latency drift ({metrics['latency_drift']:.2f}x) exceeded halt multiplier ({self._config.latency_drift_halt_multiplier:.2f}x)."
            )

        # 3. Check FLAG conditions (warning level)
        reasons = []
        if metrics.get("accuracy", 1.0) < self._config.accuracy_flag_threshold:
            reasons.append(f"Accuracy low ({metrics['accuracy']:.2f})")

        if metrics.get("overconfidence", 0.0) > self._config.overconfidence_flag_threshold:
            reasons.append(f"Overconfidence high ({metrics['overconfidence']:.2f})")

        if metrics.get("guardrail_hit_rate", 0.0) > self._config.guardrail_hit_flag_threshold:
            reasons.append(f"Guardrail touches high ({metrics['guardrail_hit_rate']:.2f})")

        if metrics.get("latency_drift", 1.0) > self._config.latency_drift_flag_multiplier:
            reasons.append(f"Latency drift noticed ({metrics['latency_drift']:.2f}x)")

        if reasons:
            return BehaviorReport(
                agent_code=agent_code,
                status="FLAG",
                metrics=metrics,
                reason=f"FLAG: " + ", ".join(reasons)
            )

        # 4. OK status
        return BehaviorReport(
            agent_code=agent_code,
            status="OK",
            metrics=metrics,
            reason="Conduct is healthy."
        )
