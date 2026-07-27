import pytest
import uuid
import os
from kormic.manager import AgentManager
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore

class TestStorageIsolation:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.db_path = f"test_salt_{uuid.uuid4().hex}.db"
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(self.key_custody, self.store, default_epoch=1)

    def teardown_method(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass
        if os.path.exists(self.db_path + "-wal"):
            try:
                os.remove(self.db_path + "-wal")
            except PermissionError:
                pass
        if os.path.exists(self.db_path + "-shm"):
            try:
                os.remove(self.db_path + "-shm")
            except PermissionError:
                pass

    def test_deployment_salt_is_stored_locally(self):
        test_salt = "super_secret_sidecar_salt_123"
        
        dain_code, _ = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital-b",
            instance_num="0002",
            real_world_id="Hospital B",
            guardrails={},
            deployment_salt=test_salt
        )
        
        # Salt should be securely saved locally
        stored_salt = self.store.get_salt(dain_code)
        assert stored_salt == test_salt
        
        # Salt MUST NOT be in the public pedigree
        pedigree_dict = self.store.get(dain_code)
        import json
        pedigree_str = json.dumps(pedigree_dict)
        assert test_salt not in pedigree_str
