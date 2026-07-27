import pytest
import time
from kormic.models.verify import ProofToken
from kormic.models.pedigree import Pedigree
from kormic.verify.engine import Verifier
from kormic.crypto.software import SoftwareKeyCustody
from kormic.registry.distributed import RegionalReplicaRegistry, CentralRegistryAuthority

class TestTwoTierVerify:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.central = CentralRegistryAuthority(self.key_custody)
        self.registry = RegionalReplicaRegistry("test", self.key_custody.get_root_public_key(), local_only=True)
        self.registry.apply_snapshot(self.central.snapshot())
        
        # We need an agent manager to build the real records, but since we just want the birth records,
        # we can build them manually or via the builder.
        from kormic.models.identity import Identity
        from kormic.pedigree.builder import create_birth_record
        
        bain_identity = Identity("BLD", "acme", "2.1.0", "a" * 64)
        self.bain_birth = create_birth_record(
            identity=bain_identity,
            guardrails={"tool": ["A", "B"]},
            epoch_number=1,
            sig_alg="ML-DSA-44",
            key_custody=self.key_custody
        )
        self.bain_code = bain_identity.to_string()
        
        dain_identity = Identity("DPL", "hosp", "0001", "b" * 64)
        self.dain_birth = create_birth_record(
            identity=dain_identity,
            guardrails={"tool": ["A"]},
            epoch_number=1,
            sig_alg="ML-DSA-44",
            key_custody=self.key_custody,
            derived_from=self.bain_code
        )
        self.dain_code = dain_identity.to_string()
        
        self.verifier = Verifier(self.registry)

    def test_successful_two_tier_verify(self):
        # FAST verification should pass
        token = ProofToken(
            agent_code=self.dain_code,
            birth_record=self.dain_birth.to_dict(),
            current_head="head_hash",
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            parent_birth_record=self.bain_birth.to_dict()
        )
        
        res = self.verifier.verify_fast(token)
        assert res.status == "PASS"

    def test_missing_parent_record_fails(self):
        token = ProofToken(
            agent_code=self.dain_code,
            birth_record=self.dain_birth.to_dict(),
            current_head="head_hash",
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            parent_birth_record=None
        )
        
        res = self.verifier.verify_fast(token)
        assert res.status == "HALT_HARD"
        assert "Parent BAIN record not provided" in res.reason

    def test_bain_revocation_implicitly_revokes_dain(self):
        self.central.revoke_agent(self.bain_code)
        self.registry.apply_snapshot(self.central.snapshot())
        
        token = ProofToken(
            agent_code=self.dain_code,
            birth_record=self.dain_birth.to_dict(),
            current_head="head_hash",
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            parent_birth_record=self.bain_birth.to_dict()
        )
        
        res = self.verifier.verify_fast(token)
        assert res.status == "REVOKED"
        # The agent_code inside the revocation failure belongs to the BAIN
        assert res.agent_code == self.bain_code
