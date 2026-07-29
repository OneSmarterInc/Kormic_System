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
        from kormic.crypto.algorithms import MLDSASigner
        self.vendor_priv, self.vendor_pub = MLDSASigner.generate_keypair()
        self.vendor_pub_hex = self.vendor_pub.hex()
        
        self.db_path = f"test_salt_{uuid.uuid4().hex}.db"
        self.store = SQLiteRecordStore(self.db_path)
        self.manager = AgentManager(
            self.key_custody, 
            self.store, 
            default_epoch=1,
            enrolled_vendors={"vendor-multi": self.vendor_pub_hex, "vendor-squat": "true_vendor_pub_key_123"}
        )

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

    def test_sidecar_restart_persists_salt(self):
        # FINDING: Sidecar restart must not accidentally delete the salt
        test_salt = "persistent_salt_999"
        
        dain_code, _ = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital-x",
            instance_num="0001",
            real_world_id="Hospital X",
            guardrails={},
            deployment_salt=test_salt
        )
        
        # Simulate restart by destroying manager and store, then reconnecting to the same DB
        del self.manager
        del self.store
        
        new_store = SQLiteRecordStore(self.db_path)
        new_manager = AgentManager(self.key_custody, new_store, default_epoch=1)
        
        # The salt should still be there
        recovered_salt = new_store.get_salt(dain_code)
        assert recovered_salt == test_salt

    def test_two_dains_share_no_salt(self):
        # FINDING: Two DAINs from the same BAIN definitively share absolutely no salt or storage locus
        from kormic.crypto.algorithms import MLDSASigner
        # 1. Enroll BAIN
        artifact_digest = "sha256_bain_multi"
        bain_code, _ = self.manager.register_new_agent(
            agent_type="BLD",
            entity_ref="vendor-multi",
            instance_num="1.0.0",
            real_world_id="Vendor Multi",
            guardrails={},
            artifact_signature=MLDSASigner.sign(self.vendor_priv, b"vendor-multi1.0.0" + artifact_digest.encode('utf-8')).hex(),
            vendor_pub_key=self.vendor_pub_hex,
            artifact_digest=artifact_digest
        )
        
        # 2. Enroll DAIN 1
        salt_1 = "salt_for_dain_1"
        dain_1, _ = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hosp-1",
            instance_num="0001",
            real_world_id="Hospital 1",
            guardrails={},
            derived_from=bain_code,
            deployment_salt=salt_1
        )
        
        # 3. Enroll DAIN 2
        salt_2 = "salt_for_dain_2"
        dain_2, _ = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hosp-2",
            instance_num="0002",
            real_world_id="Hospital 2",
            guardrails={},
            derived_from=bain_code,
            deployment_salt=salt_2
        )
        
        assert dain_1 != dain_2
        
        # 4. Verify salts are independent
        assert self.store.get_salt(dain_1) == salt_1
        assert self.store.get_salt(dain_2) == salt_2
        assert self.store.get_salt(dain_1) != self.store.get_salt(dain_2)
        
    def test_bain_squatting_controls_reject_invalid_signature(self):
        # FINDING: Enforce Artifact Binding to prevent BAIN Squatting
        from kormic.crypto.algorithms import MLDSASigner
        attacker_priv, attacker_pub = MLDSASigner.generate_keypair()
        
        artifact_digest = "sha256_squat"
        # Attacker correctly signs the payload using their own key (The squat)
        squat_sig = MLDSASigner.sign(attacker_priv, b"vendor-squat1.0.0" + artifact_digest.encode('utf-8')).hex()
        
        with pytest.raises(ValueError) as exc:
            self.manager.register_new_agent(
                agent_type="BLD",
                entity_ref="vendor-squat",
                instance_num="1.0.0",
                real_world_id="Vendor Squat",
                guardrails={},
                artifact_signature=squat_sig,
                vendor_pub_key=attacker_pub.hex(),
                artifact_digest=artifact_digest
            )
        assert "Key does not match enrolled vendor" in str(exc.value)
