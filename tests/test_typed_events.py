import pytest
import time
from kormic.models.identity import Identity
from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
from kormic.crypto.software import SoftwareKeyCustody

class TestTypedEvents:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.identity = Identity("BLD", "acme", "1.0", "a" * 64)
        self.birth = create_birth_record(
            identity=self.identity,
            guardrails={},
            epoch_number=1,
            sig_alg="ML-DSA-87",
            key_custody=self.key_custody
        )
        self.initial_pedigree = initialize_pedigree(self.birth)

    def test_absent_event_data_identical_hash(self):
        # We want to ensure that omitting `event_data` yields the exact same hash
        # We can't strictly compare to "before the change" directly because the change
        # is already loaded, but we CAN verify that passing `event_data=None` 
        # doesn't inject `event_data: null` into the hash.
        
        # Test 1: Record without event_data
        ped1 = append_history_event(self.initial_pedigree, "ActionA", timestamp=100.0)
        
        # If we injected {"event_data": None} into canonical_json, the hash would change.
        # canonical_json of {"seq": 1, "event": "ActionA", "timestamp": 100.0}
        from kormic.utils.serialize import canonical_json, hash_hex
        expected_event_json = canonical_json({"seq": 1, "event": "ActionA", "timestamp": 100.0})
        expected_head = hash_hex(self.birth.hash_alg, self.initial_pedigree.running_head + expected_event_json)
        
        assert ped1.running_head == expected_head, "Hash mechanism drifted when event_data is None!"

    def test_present_event_data_changes_hash_and_roundtrips(self):
        # Record event without data
        ped_no_data = append_history_event(self.initial_pedigree, "ActionA", timestamp=100.0)
        
        # Record event WITH data
        typed_data = {"from": "v1", "to": "v2", "by": "admin"}
        ped_with_data = append_history_event(self.initial_pedigree, "ActionA", timestamp=100.0, event_data=typed_data)
        
        # 1. Heads must differ
        assert ped_no_data.running_head != ped_with_data.running_head
        
        # 2. Round trip intact
        dict_rep = ped_with_data.to_dict()
        assert dict_rep["history"][-1]["event_data"] == typed_data
        
        from kormic.models.pedigree import Pedigree
        restored_ped = Pedigree.from_dict(dict_rep)
        assert restored_ped.history[-1].event_data == typed_data
        assert restored_ped.running_head == ped_with_data.running_head
