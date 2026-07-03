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
        guardrails: Dict[str, Any]  # Allowed permissions and policies
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
            key_custody=self.key_custody
        )

        # 4. Initialize Pedigree (Creates head_0 summary)
        pedigree = initialize_pedigree(birth)

        # 5. Save the initialized pedigree into RecordStore database (SQLite)
        self.record_store.put(agent_code, pedigree.to_dict())

        return agent_code
