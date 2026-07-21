from abc import ABC, abstractmethod
from typing import Any

class Authority(ABC):
    """
    Abstract interface representing the Kormic Control Plane.
    This creates a seam so v1 can use local Python objects, and Phase 4 can use HTTP/gRPC.
    """
    @abstractmethod
    def enroll_pubkey(self, agent_type: str, entity_ref: str, instance: str, 
                      real_world_id: str, manifest: dict, agent_pub_key: str) -> str:
        """Registers a new agent and returns the AIN."""
        pass
        
    @abstractmethod
    def get_verifier(self) -> Any:
        """Returns the verifier handle (local Verifier object for v1)."""
        pass

    @abstractmethod
    def get_pedigree(self, ain: str) -> dict:
        """Returns the agent's pedigree dictionary."""
        pass

    @abstractmethod
    def record_event(self, ain: str, event_description: str) -> str:
        """Records an event with the Authority and returns the new head."""
        pass

    @abstractmethod
    def issue_challenge(self) -> str:
        """Returns a cryptographic nonce for challenge-response."""
        pass


class LocalAuthority(Authority):
    """
    v1 implementation that wraps the existing local Kormic engine.
    """
    def __init__(self, manager, verifier, central_registry, regional_replica):
        self._manager = manager
        self._verifier = verifier
        self._central_registry = central_registry
        self._regional_replica = regional_replica
        
    def enroll_pubkey(self, agent_type: str, entity_ref: str, instance: str, 
                      real_world_id: str, manifest: dict, agent_pub_key: str) -> str:
        ain, _ = self._manager.register_new_agent(
            agent_type, entity_ref, instance, real_world_id, manifest, agent_pub_key=agent_pub_key
        )
        # In the local engine, we must apply the snapshot so the regional replica knows about the new agent
        self._regional_replica.apply_snapshot(self._central_registry.snapshot())
        return ain

    def get_pedigree(self, ain: str) -> dict:
        return self._manager.record_store.get(ain)

    def record_event(self, ain: str, event_description: str) -> str:
        self._manager.add_event(ain, event_description)
        # Sync snapshot so verifier has latest history
        self._regional_replica.apply_snapshot(self._central_registry.snapshot())
        ped = self._manager.record_store.get(ain)
        return ped['running_head']

    def get_verifier(self):
        return self._verifier

    def issue_challenge(self) -> str:
        return self._verifier.generate_challenge()
