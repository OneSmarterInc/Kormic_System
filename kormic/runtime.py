from typing import Optional
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.manager import AgentManager
from kormic.interfaces.registry import RegistryReader
from kormic.verify.engine import Verifier
from kormic.verify.cache import TrustCache
from kormic.behavior.monitor import BehaviorMonitor
from kormic.models.behavior import BehaviorConfig
from kormic.logger import kormic_logger

from kormic.utils.bloom import ScalableRevocationFilter

class LocalRegistry(RegistryReader):
    def __init__(self, key_custody: SoftwareKeyCustody):
        self.key_custody = key_custody
        self.revoked_filter = ScalableRevocationFilter()
        
        # Load any existing revoked epochs from key custody into the bloom filter
        # (Assuming key_custody tracks revoked epochs)
        # We prefix epoch numbers with 'EPOCH:' to distinguish them from agent codes
        
    def revoke_agent(self, agent_code: str) -> None:
        """Revokes an agent and adds it to the filter."""
        self.revoked_filter.add(agent_code)
        
    def revoke_epoch(self, epoch_n: int) -> None:
        """Revokes an epoch in key custody and adds it to the filter."""
        self.key_custody.revoke_epoch(epoch_n)
        self.revoked_filter.add(f"EPOCH:{epoch_n}")

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        # Check bloom filter first for scale
        if self.revoked_filter.is_revoked(f"EPOCH:{epoch_n}"):
            return True
        # Fallback to key custody for absolute truth
        return self.key_custody.is_epoch_revoked(epoch_n)

    def is_agent_revoked(self, agent_code: str) -> bool:
        return self.revoked_filter.is_revoked(agent_code)

    def get_epoch_certificate(self, epoch_n: int) -> Optional[bytes]:
        try:
            return self.key_custody.get_epoch_certificate(epoch_n)
        except Exception:
            return None

    def get_epoch_public_key(self, epoch_n: int) -> Optional[bytes]:
        try:
            return self.key_custody.epoch_public(epoch_n)
        except Exception:
            return None

class KormicRuntime:
    """
    Singleton-like wrapper initializing all capabilities required for Phase 1 agents.
    """
    def __init__(self):
        self.logger = kormic_logger
        
        # Initialize capability interfaces
        self.key_custody = SoftwareKeyCustody()
        self.record_store = SQLiteRecordStore("kormic_agents.db")
        
        # Generate initial root & epoch 1 keys
        self.current_epoch = 1
        self.key_custody.generate_epoch_key(self.current_epoch)
        
        # Initialize Registry and Verifier
        self.registry = LocalRegistry(self.key_custody)
        self.trust_cache = TrustCache(ttl_seconds=3600)
        self.verifier = Verifier(registry=self.registry, cache=self.trust_cache)
        
        # Initialize Manager and Behavior Monitor
        self.agent_manager = AgentManager(
            key_custody=self.key_custody, 
            record_store=self.record_store, 
            default_epoch=self.current_epoch
        )
        self.behavior_config = BehaviorConfig(
            accuracy_flag_threshold=0.8,
            accuracy_halt_threshold=0.5,
            overconfidence_flag_threshold=0.2,
            overconfidence_halt_threshold=0.4,
            guardrail_hit_flag_threshold=0.1,
            guardrail_hit_halt_threshold=0.3,
            latency_drift_flag_multiplier=1.5,
            latency_drift_halt_multiplier=3.0
        )
        self.behavior_monitor = BehaviorMonitor(config=self.behavior_config)

# Global Runtime Instance
runtime = KormicRuntime()
