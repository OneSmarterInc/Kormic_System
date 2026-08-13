import pytest
import time
from kormic.crypto.algorithms import MLDSASigner
from kormic.crypto.software import SoftwareKeyCustody
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.verify.engine import Verifier
from kormic.models.verify import ProofToken
from meshkor.authority import LocalAuthority
from meshkor.receiver import ReceiverClient
from kormic.models.pedigree import Pedigree
from kormic.utils.serialize import hash_hex

class TestReceiverArtifactVerification:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.central = CentralRegistryAuthority(self.key_custody)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody.get_root_public_key(), self.central)
        
        self.store = SQLiteRecordStore(":memory:")
        self.manager = AgentManager(self.key_custody, self.store, default_epoch=1, registry_reader=self.replica)

        self.vendor_priv, self.vendor_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.vendor_pub_hex = self.vendor_pub.hex()
        
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof-domain", challenge_nonce)
        self.replica.apply_snapshot(self.central.snapshot())
        
        self.verifier = Verifier(self.replica)
        self.authority = LocalAuthority(self.manager, self.verifier, self.central, self.replica)
        self.receiver = ReceiverClient(self.authority, enforcement_mode="enforced")

    def _mint_build_ain(self, vendor_name, vendor_priv_key, vendor_pub_hex, artifact_bytes):
        artifact_digest = hash_hex("SHA-256", artifact_bytes)
        payload = (vendor_name + "1" + artifact_digest).encode('utf-8')
        artifact_sig = MLDSASigner.sign('ML-DSA-87', vendor_priv_key, payload).hex()
        
        ain, _ = self.manager.register_new_agent(
            agent_type="BLD",
            entity_ref=vendor_name,
            instance_num="1",
            real_world_id="realid",
            guardrails={},
            artifact_signature=artifact_sig,
            vendor_pub_key=vendor_pub_hex,
            artifact_digest=artifact_digest
        )
        
        ped_dict = self.store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        
        token = ProofToken(
            agent_code=ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            challenge="test-challenge",
            signature="test-sig", # Build-only doesn't strictly check FAST POP in some paths, but let's mock if needed
            sig_alg='ML-DSA-87',
            fmt_ver=1
        )
        return token, artifact_sig

    def test_verify_properly_enrolled_artifact_success(self):
        artifact_bytes = b"real-artifact-code-123"
        token, artifact_sig = self._mint_build_ain("acme", self.vendor_priv, self.vendor_pub_hex, artifact_bytes)
        
        verdict = self.receiver.verify_artifact(artifact_bytes, token, artifact_sig)
        assert verdict.ok is True
        assert verdict.status == "PASS"

    def test_verify_valid_ain_wrong_bytes_digest_mismatch(self):
        # A perfectly valid Build AIN presented over malware
        safe_bytes = b"safe-artifact-code"
        token, artifact_sig = self._mint_build_ain("acme", self.vendor_priv, self.vendor_pub_hex, safe_bytes)
        
        malicious_bytes = b"malware-code"
        
        verdict = self.receiver.verify_artifact(malicious_bytes, token, artifact_sig)
        assert verdict.ok is False
        assert verdict.status == "HALT_HARD"
        assert "Artifact digest mismatch" in verdict.reason

    def test_verify_vendor_not_enrolled(self):
        # Unenrolled vendor (rogue vendor)
        rogue_priv, rogue_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        rogue_pub_hex = rogue_pub.hex()
        
        # We spoof a Build AIN creation directly since manager checks enrollment
        from kormic.models.identity import Identity
        from kormic.pedigree.builder import create_birth_record, initialize_pedigree
        
        artifact_bytes = b"some-code"
        artifact_digest = hash_hex("SHA-256", artifact_bytes)
        payload = ("rogue" + "1" + artifact_digest).encode('utf-8')
        artifact_sig = MLDSASigner.sign('ML-DSA-87', rogue_priv, payload).hex()
        
        identity = Identity("BLD", "rogue", "1", hash_hex("SHA-256", b"realid"))
        br = create_birth_record(
            identity, {}, 1, "ML-DSA-87", self.key_custody, 
            vendor_pub_key=rogue_pub_hex, artifact_digest=artifact_digest
        )
        
        token = ProofToken(
            agent_code=identity.to_string(),
            birth_record=br.to_dict(),
            current_head="head", history_length=0,
            freshness_timestamp=time.time(), authority_reference="test",
            challenge="test-challenge", signature="sig", sig_alg='ML-DSA-87', fmt_ver=1
        )
        
        verdict = self.receiver.verify_artifact(artifact_bytes, token, artifact_sig)
        assert verdict.ok is False
        assert verdict.status == "HALT_HARD"
        assert "Vendor 'rogue' not enrolled" in verdict.reason

    def test_no_build_ain_invalid_ain(self):
        # Standard DAIN (deployment) being used as if it was a Build AIN
        artifact_bytes = b"real-artifact-code-123"
        # We need to mint a regular CMP or DPL
        agent_priv, agent_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        ain, _ = self.manager.register_new_agent(
            agent_type="CMP",
            entity_ref="acme",
            instance_num="1",
            real_world_id="realid",
            guardrails={},
            agent_pub_key=agent_pub.hex()
        )
        ped_dict = self.store.get(ain)
        ped = Pedigree.from_dict(ped_dict)
        token = ProofToken(
            agent_code=ain,
            birth_record=ped.birth_record.to_dict(),
            current_head=ped.running_head,
            history_length=0,
            freshness_timestamp=time.time(), authority_reference="test",
            challenge="test-challenge", signature="sig", sig_alg='ML-DSA-87', fmt_ver=1
        )
        
        verdict = self.receiver.verify_artifact(artifact_bytes, token, "fake-sig")
        assert verdict.ok is False
        # It's an invalid AIN for a build because it lacks artifact_digest
        assert "Build AIN does not seal an artifact_digest" in verdict.reason or verdict.status != "PASS"

    def test_advisory_mode_bypass(self):
        # Switch receiver to advisory
        self.receiver.enforcement_mode = "advisory"
        
        safe_bytes = b"safe-artifact-code"
        token, artifact_sig = self._mint_build_ain("acme", self.vendor_priv, self.vendor_pub_hex, safe_bytes)
        
        malicious_bytes = b"malware-code"
        
        # In advisory mode, it logs the detection but allows execution (ok=True)
        verdict = self.receiver.verify_artifact(malicious_bytes, token, artifact_sig)
        assert verdict.ok is True
        assert verdict.status == "ADVISORY_BYPASS"
        assert "Artifact digest mismatch" in verdict.reason
