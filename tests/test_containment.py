import pytest
import uuid
from kormic.manager import AgentManager
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore

class TestContainment:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        from kormic.crypto.algorithms import MLDSASigner
        self.vendor_priv, self.vendor_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.vendor_pub_hex = self.vendor_pub.hex()
        
        self.db_path = f"test_containment_{uuid.uuid4().hex}.db"
        self.store = SQLiteRecordStore(self.db_path)
        from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
        self.central = CentralRegistryAuthority(self.key_custody)
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof1", challenge_nonce)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody._root_pub, self.central)
        self.replica.apply_snapshot(self.central.snapshot())

        self.manager = AgentManager(
            self.key_custody, 
            self.store, 
            default_epoch=1,
            registry_reader=self.replica
        )

        # Create a BAIN (Vendor Build)
        artifact_digest = "sha256_deadbeef1234"
        artifact_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, b"acme2.1.0" + artifact_digest.encode('utf-8')).hex()

        # Mock an approval assertion for the BLD agent
        principal_priv, principal_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        challenge_p = "nonce-p-1"
        possession_p = MLDSASigner.sign('ML-DSA-87', principal_priv, f"{challenge_p}:alice".encode('utf-8')).hex()
        self.central.enroll_principal("alice", principal_pub.hex(), possession_p, "proof-domain", challenge_p)
        self.replica.apply_snapshot(self.central.snapshot())
        
        import time
        from kormic.models.approval import DelegationAssertion
        assertion = DelegationAssertion(
            principal_ref="alice", action="release", target=artifact_digest,
            expiry=int(time.time() + 300), nonce="nonce-app-1", sig_alg="ML-DSA-87", fmt_ver=1
        )
        sig = MLDSASigner.sign('ML-DSA-87', principal_priv, assertion.signable_payload()).hex()
        approval_assertion = DelegationAssertion(
            principal_ref=assertion.principal_ref, action=assertion.action, target=assertion.target,
            expiry=assertion.expiry, nonce=assertion.nonce, signature=sig, sig_alg=assertion.sig_alg, fmt_ver=assertion.fmt_ver
        ).to_dict()

        self.vendor_guardrails = {
            "allowed_tools": ["toolA", "toolB", "toolC"],
            "allowed_endpoints": ["api.example.com", "api.acme.com"],
            "credential_scopes": ["read", "write"],
            "irreversible_scopes": ["delete"]
        }
        self.bain_code, _ = self.manager.register_new_agent(
            agent_type="BLD",
            entity_ref="acme",
            instance_num="2.1.0",
            real_world_id="Acme Corp",
            guardrails=self.vendor_guardrails,
            artifact_signature=artifact_sig,
            vendor_pub_key=self.vendor_pub_hex,
            artifact_digest=artifact_digest,
            approval_assertion=approval_assertion
        )

    def teardown_method(self):
        import os
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

    def test_containment_works_for_subset(self):
        # A subset of the BAIN guardrails
        hospital_guardrails = {
            "allowed_tools": ["toolA", "toolB"],
            "allowed_endpoints": ["api.acme.com"],
            "credential_scopes": ["read"],
            "irreversible_scopes": []
        }
        
        # Enroll DAIN
        dain_code, _ = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hospital-a",
            instance_num="0001",
            real_world_id="Hospital A",
            guardrails=hospital_guardrails,
            derived_from=self.bain_code
        )
        assert dain_code.startswith("KMC.DPL.hospital-a.0001")
        
        # Verify derived_from is sealed in the DAIN
        pedigree_dict = self.store.get(dain_code)
        assert pedigree_dict["birth_record"]["derived_from"] == self.bain_code

    def test_containment_refusal_for_superset(self):
        # Requesting a tool not in the BAIN
        hospital_guardrails = {
            "allowed_tools": ["toolA", "toolD"], # toolD is illegal
            "allowed_endpoints": ["api.acme.com"],
            "credential_scopes": ["read"],
            "irreversible_scopes": []
        }
        
        with pytest.raises(ValueError) as exc:
            self.manager.register_new_agent(
                agent_type="DPL",
                entity_ref="hospital-a",
                instance_num="0001",
                real_world_id="Hospital A",
                guardrails=hospital_guardrails,
                derived_from=self.bain_code
            )
        assert "Containment violation" in str(exc.value)
        assert "toolD" in str(exc.value)
        assert "allowed_tools" in str(exc.value)
