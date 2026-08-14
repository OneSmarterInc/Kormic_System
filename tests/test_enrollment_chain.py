import pytest
import uuid
import os
from kormic.manager import AgentManager
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore

class TestEnrollmentChain:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        from kormic.crypto.algorithms import MLDSASigner
        self.vendor_priv, self.vendor_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.vendor_pub_hex = self.vendor_pub.hex()
        
        self.db_path = f"test_enrollment_{uuid.uuid4().hex}.db"
        self.store = SQLiteRecordStore(self.db_path)
        from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
        self.central = CentralRegistryAuthority(self.key_custody)
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:vendorX".encode('utf-8')).hex()
        self.central.enroll_vendor("vendorX", self.vendor_pub_hex, possession_sig, "proof1", challenge_nonce)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody._root_pub, self.central)
        self.replica.apply_snapshot(self.central.snapshot())

        self.manager = AgentManager(
            self.key_custody, 
            self.store, 
            default_epoch=1,
            registry_reader=self.replica
        )

    def teardown_method(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass
        for suffix in ["-wal", "-shm"]:
            if os.path.exists(self.db_path + suffix):
                try:
                    os.remove(self.db_path + suffix)
                except PermissionError:
                    pass

    def test_bain_dain_enrollment_chain(self):
        # FINDING C Fix test: Enroll a BAIN, then pass its result directly to a DAIN enrollment.
        from kormic.crypto.algorithms import MLDSASigner
        # 1. Enroll BAIN
        artifact_digest = "sha256_abcdef123"
        artifact_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, b"vendorX1.0.0" + artifact_digest.encode('utf-8')).hex()
        
        import time
        from kormic.models.approval import DelegationAssertion
        # Enroll a principal for approvals
        principal_priv, principal_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        challenge_p = "nonce-p-1"
        possession_p = MLDSASigner.sign('ML-DSA-87', principal_priv, f"{challenge_p}:alice".encode('utf-8')).hex()
        self.central.enroll_principal("alice", principal_pub.hex(), possession_p, "proof-domain", challenge_p)
        self.replica.apply_snapshot(self.central.snapshot())

        assertion = DelegationAssertion(
            principal_ref="alice", action="release", target=artifact_digest,
            expiry=int(time.time() + 300), nonce="nonce-app-2", sig_alg="ML-DSA-87", fmt_ver=1
        )
        sig_app = MLDSASigner.sign('ML-DSA-87', principal_priv, assertion.signable_payload()).hex()
        approval_assertion = DelegationAssertion(
            principal_ref=assertion.principal_ref, action=assertion.action, target=assertion.target,
            expiry=assertion.expiry, nonce=assertion.nonce, signature=sig_app, sig_alg=assertion.sig_alg, fmt_ver=assertion.fmt_ver
        ).to_dict()

        bain_result = self.manager.register_new_agent(
            agent_type="BLD",
            entity_ref="vendorX",
            instance_num="1.0.0",
            real_world_id="Vendor X",
            guardrails={"tools": ["A", "B"]},
            artifact_signature=artifact_sig,
            vendor_pub_key=self.vendor_pub_hex,
            artifact_digest=artifact_digest,
            approval_assertion=approval_assertion
        )
        
        # Assert it has the named fields
        assert bain_result.agent_code.startswith("KMC.BLD.")
        assert len(bain_result.twin_shares) > 0
        
        # 2. Enroll DAIN using the result object directly (should not throw a tuple error)
        dain_result = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital-b",
            instance_num="0001",
            real_world_id="Hospital B",
            guardrails={"tools": ["A"]},
            derived_from=bain_result  # Passing the tuple/result object directly
        )
        
        assert dain_result.agent_code.startswith("KMC.DPL.")
        
        # Verify the parent reference was extracted correctly
        dain_pedigree = self.store.get(dain_result.agent_code)
        assert dain_pedigree["birth_record"]["derived_from"] == bain_result.agent_code
