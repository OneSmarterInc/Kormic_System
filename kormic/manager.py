import time
from typing import Dict, Any, Optional
from kormic.models.identity import Identity
from kormic.models.pedigree import Pedigree
from kormic.pedigree.builder import create_birth_record, initialize_pedigree
from kormic.interfaces.keys import KeyCustody
from kormic.interfaces.storage import RecordStore
from kormic.utils.serialize import sha256_hex

# ==============================================================================
# EXTRA UTILITY: AgentManager wrapper to simplify agent creation and storage.
# Handles identity generation, birth record signing, and database commit.
# ==============================================================================

class AgentManager:
    """
    High-level manager to simplify agent creation, tracking, and persistence.
    """
    def __init__(self, key_custody: KeyCustody, record_store: RecordStore, default_epoch: int = 1):
        self.key_custody = key_custody
        self.record_store = record_store
        self.default_epoch = default_epoch

    def register_new_agent(
        self,
        agent_type: str,            # STU, UNI, or CMP
        entity_ref: str,            # Owner identifier, e.g. 'priya7f3a'
        instance_num: str,          # Exactly 4 digits, e.g. '0001'
        real_world_id: str,         # Raw ID/profile text (will be hashed internally)
        guardrails: Dict[str, Any], # Allowed permissions and policies
        agent_pub_key: str = ""     # Hex agent public key for FAST challenge
    ) -> str:
        """
        Creates, signs, initializes, and stores a new agent in the database.
        Returns the unique agent code string.
        """
        # 1. Calculate privacy hash for real-world identity
        realid_hash = sha256_hex(real_world_id)

        # 2. Build structured Identity
        identity = Identity(
            agent_type=agent_type,
            entity_ref=entity_ref,
            instance=instance_num,
            realid_ref=realid_hash
        )
        agent_code = identity.to_string()

        # 3. Create Birth Record (Signed by epoch key)
        birth = create_birth_record(
            identity=identity,
            guardrails=guardrails,
            epoch_number=self.default_epoch,
            sig_alg="ML-DSA-44",
            key_custody=self.key_custody,
            agent_pub_key=agent_pub_key
        )

        # 4. Initialize Pedigree (Creates head_0 summary)
        pedigree = initialize_pedigree(birth)

        # 5. Save the initialized pedigree into RecordStore database (SQLite)
        self.record_store.put(agent_code, pedigree.to_dict())
        
        # 6. Immediately seal the baseline Twin (0 events)
        from kormic.crypto.twin import TwinManager
        sealed_blob, shares = TwinManager.seal_twin(pedigree, self.key_custody)
        self.record_store.put_twin(agent_code, sealed_blob)

        return agent_code, shares

    def add_event(self, agent_code: str, event_data: str, snapshot_k: int = 5) -> Optional[list]:
        """
        Adds a history event. Implements the High-Churn Snapshot Model (Section 6.4).
        Returns new Shamir shares if a Snapshot Twin was sealed on this event, else None.
        """
        import time
        from kormic.pedigree.builder import append_history_event
        from kormic.crypto.twin import TwinManager
        
        # 1. Fetch live pedigree
        ped_dict = self.record_store.get(agent_code)
        if not ped_dict:
            raise ValueError("Agent not found in live database.")
            
        pedigree = Pedigree.from_dict(ped_dict)
        
        # 2. Add Event
        pedigree = append_history_event(pedigree, event_data, time.time())
        seq = len(pedigree.history)
        
        # 3. Update live DB
        self.record_store.put(agent_code, pedigree.to_dict())
        
        # 4. Snapshot Twin Logic (High-Churn optimization)
        # We only encrypt and seal the full twin every K events to save bandwidth.
        # This means on restore, we accept a bounded data loss of up to K-1 events.
        if seq % snapshot_k == 0:
            sealed_blob, new_shares = TwinManager.seal_twin(pedigree, self.key_custody)
            self.record_store.put_twin(agent_code, sealed_blob)
            return new_shares
            
        return None
