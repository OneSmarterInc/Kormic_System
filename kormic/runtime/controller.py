from kormic.runtime.sandbox import Sandbox
from kormic.behavior.monitor import BehaviorMonitor
from kormic.registry.distributed import CentralRegistryAuthority
from kormic.pedigree.builder import append_history_event
from kormic.models.pedigree import Pedigree
from kormic.manager import AgentManager
from kormic.behavior.alerting import AlertDispatcher

class SessionController:
    """
    Wires the Sandbox (C1), Behavior Monitor, and Central Registry together.
    If the Sandbox blocks an action (Drift), this controller:
      1. Logs a MANIFEST_BREACH to the tamper-evident History Chain.
      2. Feeds the drift signal into the Behavior Monitor.
      3. If the Monitor issues a HALT, instantly globally revokes the agent and triggers alerts.
    """
    def __init__(
        self, 
        sandbox: Sandbox, 
        monitor: BehaviorMonitor, 
        registry: CentralRegistryAuthority, 
        manager: AgentManager,
        alerter: AlertDispatcher = None
    ):
        self.sandbox = sandbox
        self.monitor = monitor
        self.registry = registry
        self.manager = manager
        self.alerter = alerter or AlertDispatcher()
        self.ain = self.sandbox.token.agent_code

    def execute_tool(self, tool: str) -> str:
        try:
            return self.sandbox.use_tool(tool)
        except PermissionError as e:
            self._handle_violation("MANIFEST_BREACH: TOOL", str(e))
            raise

    def call_endpoint(self, endpoint: str) -> str:
        try:
            return self.sandbox.call_endpoint(endpoint)
        except PermissionError as e:
            self._handle_violation("MANIFEST_BREACH: ENDPOINT", str(e))
            raise

    def _handle_violation(self, event_type: str, reason: str):
        from kormic.logger import kormic_logger
        # 1. Append Drift to History Chain
        kormic_logger.warning("INTERACT", self.ain, f"Drift Detected: {event_type} - {reason}")
        ped_dict = self.manager.record_store.get(self.ain)
        if ped_dict:
            ped = Pedigree.from_dict(ped_dict)
            ped = append_history_event(ped, event_type)
            self.manager.record_store.put(self.ain, ped.to_dict())

        # 2. Feed Binary Drift Signal to Behavior Monitor
        metrics = {"policy_violation": True, "reason": reason}
        report = self.monitor.evaluate(self.ain, metrics)

        # 3. If HALT, globally revoke via Central Authority and send Enterprise Alert
        if report.status == "HALT":
            kormic_logger.error("MONITOR", self.ain, f"Behavior HALT Issued. Triggering Global Revocation. Reason: {report.reason}")
            self.registry.revoke_agent(self.ain)
            self.alerter.dispatch_halt_alert(self.ain, report.reason)
            
            # Note: The CentralRegistryAuthority will include this agent in its next snapshot.
            # Regional Replicas will sync and update their Bloom Filters, instantly 
            # blocking the agent globally.

    def self_isolate(self, reason: str):
        """
        Phase 3: Self-Defense.
        Agents may voluntarily and reversibly isolate themselves if they detect compromise.
        They may NEVER self-destruct (existential destruction requires human quorum).
        """
        # Append isolation event
        ped_dict = self.manager.record_store.get(self.ain)
        if ped_dict:
            ped = Pedigree.from_dict(ped_dict)
            ped = append_history_event(ped, f"SELF_ISOLATION: {reason}")
            self.manager.record_store.put(self.ain, ped.to_dict())
            
        # Reversible revocation
        self.registry.revoke_agent(self.ain)
        self.alerter.dispatch_halt_alert(self.ain, f"Agent self-isolated: {reason}")
