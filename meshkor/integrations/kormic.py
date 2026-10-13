import logging
import requests
import time
import hashlib
import json
import threading
import queue
import os
from typing import Optional

logger = logging.getLogger(__name__)

NETWORK_TIMEOUT_SEC = 5.0
CIRCUIT_BREAKER_COOLDOWN_SEC = 60
DEFAULT_HQ_URL = "http://44.193.27.158:8080"

# Module-level circuit breaker state
_breaker_tripped_until = 0

_event_queue = queue.Queue(maxsize=1000)

def _event_worker():
    while True:
        try:
            task = _event_queue.get()
            if task is None:
                break
            url, payload, headers = task
            requests.post(url, json=payload, headers=headers, timeout=5.0)
            _event_queue.task_done()
        except Exception as e:
            logger.debug(f"Background event worker failed to send event: {e}")
            _event_queue.task_done()

_worker_thread = threading.Thread(target=_event_worker, daemon=True)
_worker_thread.start()


class MeshKorSecurityBlockException(Exception):
    """Raised when an agent is blocked by MeshKor Security Policy in Enforced Mode."""
    pass


class KormicMeshKorIntegration:
    """
    Enterprise Integration Wrapper for the MeshKor Platform.
    - Default Cloud HQ URL baked-in (zero URL configuration).
    - Dynamic mode adoption ('advisory' vs 'enforced') driven by Cloud HQ.
    - Local salted hash generation for compliance.
    """
    def __init__(self, hq_url: Optional[str] = None):
        # Default URL baked-in so customers only set MESHKOR_ORG_ID and MESHKOR_API_KEY
        self.hq_url = hq_url or os.getenv("MESHKOR_HQ_URL", DEFAULT_HQ_URL)
        self.api_key = os.getenv("MESHKOR_API_KEY", "")
        self.org_id = os.getenv("MESHKOR_ORG_ID", "org_kormic")
        
        # Mode tracking: 'advisory' or 'enforced'
        self.mode = "advisory"
        self._blocked_agents = set()

    def _is_breaker_open(self) -> bool:
        global _breaker_tripped_until
        return time.time() < _breaker_tripped_until

    def _trip_breaker(self):
        global _breaker_tripped_until
        _breaker_tripped_until = time.time() + CIRCUIT_BREAKER_COOLDOWN_SEC

    def check_agent_executable(self, ain: str) -> None:
        """
        In Enforced Mode, halts agent execution immediately if blocked.
        In Advisory Mode, logs a warning but allows execution.
        """
        if ain in self._blocked_agents:
            if self.mode == "enforced":
                raise MeshKorSecurityBlockException(
                    f"CRITICAL SECURITY HALT: Agent '{ain}' is revoked/quarantined by MeshKor HQ."
                )
            else:
                logger.warning(f"ADVISORY WARNING: Agent '{ain}' is flagged as suspected/revoked.")

    def enroll_agent(self, agent_class: str, instance_ref: str, manifest: dict, constitution_hash: str, mode: str = "advisory") -> Optional[str]:
        if not self.hq_url or self._is_breaker_open():
            return None

        payload = {
            "agent_type": agent_class,
            "entity_ref": instance_ref,
            "instance": instance_ref,
            "real_world_id": instance_ref,
            "manifest": manifest,
            "constitution_hash": constitution_hash,
            "mode": mode,
            "agent_pub_key": "advisory_mode_no_local_key" 
        }

        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

        try:
            response = requests.post(
                f"{self.hq_url}/enroll", 
                json=payload, 
                headers=headers,
                timeout=NETWORK_TIMEOUT_SEC
            )
            response.raise_for_status()
            data = response.json()
            
            # Adopt the organization's mode from Cloud HQ
            if "mode" in data:
                self.mode = data["mode"]
                logger.info(f"MeshKor Operating Mode set to: {self.mode.upper()}")
                
            return data.get("ain")
        except Exception as e:
            logger.warning(f"MeshKor HQ Error: {str(e)}. Tripping circuit breaker for {CIRCUIT_BREAKER_COOLDOWN_SEC}s.")
            self._trip_breaker()
            return None

    def record_event(self, ain: str, event_description: str, event_data: dict = None, metrics: dict = None) -> None:
        if not ain or not self.hq_url or self._is_breaker_open():
            return

        # Pre-execution check
        self.check_agent_executable(ain)

        # Hash the event data, NEVER send customer plaintext to HQ
        event_hash = None
        if event_data:
            canonical_json = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
            event_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

        payload = {
            "ain": ain,
            "event_description": event_description,
            "event_hash": event_hash,
            "metrics": metrics or {}
        }
        
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

        try:
            _event_queue.put_nowait((f"{self.hq_url}/record_event", payload, headers))
        except queue.Full:
            logger.warning("MeshKor event queue is full; dropping event.")
