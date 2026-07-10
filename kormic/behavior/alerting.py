import json
import logging

class AlertDispatcher:
    """
    Simulates sending enterprise emergency webhooks (e.g. to PagerDuty or Slack)
    when a rogue agent is globally revoked.
    """
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url
        self.logger = logging.getLogger("AlertDispatcher")

    def dispatch_halt_alert(self, agent_code: str, reason: str):
        payload = {
            "alert_type": "EMERGENCY_HALT",
            "severity": "CRITICAL",
            "agent_code": agent_code,
            "reason": reason,
            "action_taken": "Agent globally revoked across all Regional Replicas."
        }
        
        # Output beautifully to the console to prove the alerting system triggers
        print("\n[EMERGENCY] KORMIC ALERT DISPATCHED")
        print(json.dumps(payload, indent=4) + "\n")
        
        if self.webhook_url:
            pass # Real HTTP POST logic would go here
