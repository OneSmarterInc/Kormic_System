from meshkor.remote import RemoteAuthority
from meshkor.agent import MeshKorAgent
import functools

class MeshKorSDK:
    def __init__(self, sidecar_addr="127.0.0.1:5050"):
        self.auth = RemoteAuthority(sidecar_addr)
        self.agent = None

    def enroll(self, agent_type: str, instance: str, manifest: dict):
        self.agent = MeshKorAgent.enroll(
            authority=self.auth,
            agent_type=agent_type,
            entity_ref="sdk_agent",
            instance=instance,
            real_world_id="local_dev",
            manifest=manifest
        )
        return self.agent.ain

    def record_action(self, action: str):
        if not self.agent:
            raise ValueError("Not enrolled")
        self.agent.record_event(action)

    def mint_token(self, challenge=None):
        if not self.agent:
            raise ValueError("Not enrolled")
        return self.agent.mint_token(challenge)

def meshkor_verified(manifest: dict, agent_type: str = "CMP", instance: str = "001", sidecar_addr="127.0.0.1:5050"):
    def decorator(cls):
        original_init = getattr(cls, '__init__', lambda self: None)
        
        @functools.wraps(original_init)
        def new_init(self, *args, **kwargs):
            self.meshkor = MeshKorSDK(sidecar_addr)
            self.meshkor.enroll(agent_type, instance, manifest)
            original_init(self, *args, **kwargs)
            self.meshkor.record_action(f"Agent Initialized: {cls.__name__}")
            
        cls.__init__ = new_init
        return cls
    return decorator
