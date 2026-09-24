import logging
import requests
from typing import Optional
from kormic.models.pedigree import Pedigree

logger = logging.getLogger(__name__)

# Hardcoded circuit-breaker timeout for Advisory Mode
NETWORK_TIMEOUT_SEC = 0.2

class KormicMeshKorIntegration:
    """
    Fail-Open Integration Wrapper for the Kormic Django Backend.
    Guarantees no private keys are loaded and no student traffic is blocked if HQ is down.
    """
    def __init__(self, hq_url: Optional[str] = None):
        import os
        self.hq_url = hq_url or os.getenv("MESHKOR_HQ_URL", "http://44.193.27.158:8080")
        if not self.hq_url:
            logger.warning("No HQ URL provided. MeshKor will fail-open automatically.")

    def enroll_agent(self, agent_class: str, instance_ref: str, manifest: dict, constitution_hash: str, mode: str = "advisory") -> Optional[str]:
        """
        Enrolls a new agent instance with the HQ server to receive an AIN.
        Fails open (returns None) if the HQ server is unreachable.
        """
        if not self.hq_url:
            return None

        payload = {
            "agent_type": agent_class,
            "entity_ref": instance_ref,
            "instance": instance_ref,
            "real_world_id": instance_ref,
            "manifest": manifest,
            "constitution_hash": constitution_hash,
            "mode": mode,
            "agent_pub_key": "advisory_mode_no_local_key" # In v1 advisory, we defer strict local auth
        }

        try:
            # We use a strict timeout to prevent blocking Django WSGI workers
            response = requests.post(
                f"{self.hq_url}/enroll", 
                json=payload, 
                timeout=NETWORK_TIMEOUT_SEC
            )
            response.raise_for_status()
            data = response.json()
            return data.get("ain")
        except requests.exceptions.Timeout:
            logger.warning(f"MeshKor HQ Timeout ({NETWORK_TIMEOUT_SEC}s). Failing open for agent {agent_class}.")
            return None
        except Exception as e:
            logger.warning(f"MeshKor HQ Error: {str(e)}. Failing open for agent {agent_class}.")
            return None

    def record_event(self, ain: str, event_description: str, event_data: dict = None) -> None:
        """
        Records a tamper-evident event asynchronously (or fire-and-forget).
        """
        if not ain or not self.hq_url:
            return # If AIN is None (failed open), skip recording

        payload = {
            "ain": ain,
            "event_description": event_description,
            "event_data": event_data
        }

        try:
            requests.post(
                f"{self.hq_url}/record_event", 
                json=payload, 
                timeout=NETWORK_TIMEOUT_SEC
            )
        except Exception as e:
            logger.warning(f"MeshKor Event Logging Error: {str(e)}. Ignoring.")
