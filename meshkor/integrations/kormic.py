import logging
import requests
import time
import hashlib
import json
import threading
import queue
from typing import Optional

logger = logging.getLogger(__name__)

NETWORK_TIMEOUT_SEC = 0.2
CIRCUIT_BREAKER_COOLDOWN_SEC = 60

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


class KormicMeshKorIntegration:
    """
    Fail-Open Integration Wrapper for the Kormic Django Backend.
    Guarantees no private keys are loaded and no student traffic is blocked if HQ is down.
    """
    def __init__(self, hq_url: Optional[str] = None):
        import os
        # Finding B: Remove hardcoded IP, fail if missing.
        self.hq_url = hq_url or os.getenv("MESHKOR_HQ_URL")
        self.api_key = os.getenv("MESHKOR_API_KEY", "")
        
        if not self.hq_url:
            logger.warning("No MESHKOR_HQ_URL provided in env. MeshKor will fail-open automatically.")
        elif self.hq_url.startswith("http://"):
            logger.warning("TRIPWIRE: MeshKor is configured with a plaintext http:// URL. The pilot requires TLS (https://).")

    def _is_breaker_open(self) -> bool:
        global _breaker_tripped_until
        return time.time() < _breaker_tripped_until

    def _trip_breaker(self):
        global _breaker_tripped_until
        _breaker_tripped_until = time.time() + CIRCUIT_BREAKER_COOLDOWN_SEC

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
            return data.get("ain")
        except Exception as e:
            logger.warning(f"MeshKor HQ Error: {str(e)}. Tripping circuit breaker for {CIRCUIT_BREAKER_COOLDOWN_SEC}s.")
            self._trip_breaker()
            return None

    def record_event(self, ain: str, event_description: str, event_data: dict = None) -> None:
        if not ain or not self.hq_url or self._is_breaker_open():
            return

        # Finding A: Hash the event data, NEVER send student plaintext to HQ
        event_hash = None
        if event_data:
            canonical_json = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
            event_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

        payload = {
            "ain": ain,
            "event_description": event_description,
            "event_hash": event_hash  # Sent instead of event_data
        }
        
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

        try:
            _event_queue.put_nowait((f"{self.hq_url}/record_event", payload, headers))
        except queue.Full:
            logger.warning("MeshKor event queue is full; dropping event.")
