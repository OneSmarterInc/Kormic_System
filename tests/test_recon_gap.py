import pytest
import time
import os
import socket
from kormic.manager import AgentManager
from kormic.crypto.software import SoftwareKeyCustody
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import RegionalReplicaRegistry, CentralRegistryAuthority
from kormic.verify.engine import Verifier
from kormic.models.verify import ProofToken
from kormic.runtime.sandbox import Sandbox
from meshkor.authority import LocalAuthority
from meshkor.receiver import ReceiverClient

class TestReconGap:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.central = CentralRegistryAuthority(self.key_custody)
        
        # Setup vendor
        from kormic.crypto.algorithms import MLDSASigner
        vpriv, vpub = MLDSASigner.generate_keypair()
        nonce = "recon-nonce"
        sig = MLDSASigner.sign(vpriv, f"{nonce}:vendor_recon".encode()).hex()
        self.central.enroll_vendor("vendor_recon", vpub.hex(), sig, "id-doc", nonce)
        
        self.store = SQLiteRecordStore(":memory:")
        self.registry = RegionalReplicaRegistry("test", self.key_custody.get_root_public_key(), local_only=True)
        self.registry.apply_snapshot(self.central.snapshot())
        
        self.manager = AgentManager(self.key_custody, self.store, registry_reader=self.registry)

        # Create BAIN
        self.bain_res = self.manager.register_new_agent(
            agent_type="BLD",
            entity_ref="vendor_recon",
            instance_num="v1",
            real_world_id="v_id",
            guardrails={"allowed_tools": ["search"]},
            read_scopes=["public_api", "reddit_changemyview"],
            allowed_egress=["api.reddit.com", "api.github.com"],
            artifact_signature=MLDSASigner.sign(vpriv, "vendor_reconv1digest1".encode()).hex(),
            vendor_pub_key=vpub.hex(),
            artifact_digest="digest1"
        )
        
        # Create DAIN within BAIN bounds
        self.dain_res = self.manager.register_new_agent(
            agent_type="DPL",
            entity_ref="hosp",
            instance_num="1",
            real_world_id="h_id",
            guardrails={"allowed_tools": ["search"]},
            read_scopes=["reddit_changemyview"],
            allowed_egress=["api.reddit.com"],
            derived_from=self.bain_res.agent_code,
            agent_pub_key=vpub.hex() # Just use vendor key for agent proof for simplicity
        )
        self.agent_priv = vpriv
        self.agent_pub = vpub.hex()
        
        self.verifier = Verifier(self.registry)
        self.authority = LocalAuthority(self.manager, self.verifier, self.central, self.registry)
        self.receiver = ReceiverClient(self.authority)

    def test_read_scope_containment(self):
        # Trying to deploy a DAIN with a read scope not in BAIN
        with pytest.raises(ValueError, match="outside parent envelope"):
            self.manager.register_new_agent(
                agent_type="DPL",
                entity_ref="hosp2",
                instance_num="1",
                real_world_id="h2_id",
                guardrails={"allowed_tools": ["search"]},
                read_scopes=["secret_internal_db"], # Not in BAIN
                derived_from=self.bain_res.agent_code
            )

    def test_sandbox_concurrency_isolation(self):
        # 1. Setup host environment
        os.environ["AWS_SECRET_KEY"] = "super-secret-key-123"
        os.environ["PUBLIC_VAR"] = "public"
        
        # Build tokens
        bain_ped_dict = self.store.get(self.bain_res.agent_code)
        
        # DAIN 1 (Allows reddit)
        dain1_res = self.manager.register_new_agent(
            agent_type="DPL", entity_ref="hosp", instance_num="1_conc",
            real_world_id="h1", guardrails={"allowed_tools": ["search"]}, read_scopes=[], allowed_egress=["api.reddit.com"],
            derived_from=self.bain_res.agent_code, agent_pub_key=self.agent_pub
        )
        nonce1 = self.verifier.generate_challenge()
        from kormic.crypto.algorithms import MLDSASigner
        sig1 = MLDSASigner.sign(self.agent_priv, ("head_hash" + nonce1).encode()).hex()
        token1 = ProofToken(
            agent_code=dain1_res.agent_code, birth_record=self.store.get(dain1_res.agent_code)["birth_record"],
            current_head="head_hash", history_length=0, freshness_timestamp=time.time(),
            authority_reference="test", parent_birth_record=bain_ped_dict["birth_record"],
            challenge=nonce1, signature=sig1
        )
        
        # DAIN 2 (Allows github)
        dain2_res = self.manager.register_new_agent(
            agent_type="DPL", entity_ref="hosp", instance_num="2_conc",
            real_world_id="h2", guardrails={"allowed_tools": ["search"]}, read_scopes=[], allowed_egress=["api.github.com"],
            derived_from=self.bain_res.agent_code, agent_pub_key=self.agent_pub
        )
        nonce2 = self.verifier.generate_challenge()
        sig2 = MLDSASigner.sign(self.agent_priv, ("head_hash" + nonce2).encode()).hex()
        token2 = ProofToken(
            agent_code=dain2_res.agent_code, birth_record=self.store.get(dain2_res.agent_code)["birth_record"],
            current_head="head_hash", history_length=0, freshness_timestamp=time.time(),
            authority_reference="test", parent_birth_record=bain_ped_dict["birth_record"],
            challenge=nonce2, signature=sig2
        )
        
        # 2. Stand up two sessions concurrently
        sandbox1 = Sandbox(self.verifier, token1)
        sandbox2 = Sandbox(self.verifier, token2)
        
        # Assertion 1: Neither session deletes or alters the host process os.environ
        assert "AWS_SECRET_KEY" in os.environ
        assert "PUBLIC_VAR" in os.environ
        assert os.environ["AWS_SECRET_KEY"] == "super-secret-key-123"
        
        # Assertion 1b: But their session_env and secure_vault are correctly isolated
        assert "AWS_SECRET_KEY" not in sandbox1.session_env
        assert sandbox1.secure_vault["AWS_SECRET_KEY"] == "super-secret-key-123"
        
        # Assertion 2: The second session does not block a host the first session is allowed to reach
        assert sandbox1.check_egress("api.reddit.com") is True
        
        # Assertion 3: The first session cannot reach a host only the second session is allowed to reach
        with pytest.raises(PermissionError):
            sandbox1.check_egress("api.github.com")
            
        with pytest.raises(PermissionError):
            sandbox2.check_egress("api.reddit.com")
            
        assert sandbox2.check_egress("api.github.com") is True

    def test_verified_reader_handshake(self):
        ped_dict = self.store.get(self.dain_res.agent_code)
        bain_ped_dict = self.store.get(self.bain_res.agent_code)
        
        nonce = self.verifier.generate_challenge()
        payload = ("head_hash" + nonce).encode()
        from kormic.crypto.algorithms import MLDSASigner
        sig = MLDSASigner.sign(self.agent_priv, payload).hex()
        
        token = ProofToken(
            agent_code=self.dain_res.agent_code,
            birth_record=ped_dict["birth_record"],
            current_head="head_hash",
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            parent_birth_record=bain_ped_dict["birth_record"],
            challenge=nonce,
            signature=sig
        )
        
        # Valid read
        verdict = self.receiver.validate(token, action_type="read", resource="reddit_changemyview")
        assert verdict.ok is True
        
        # Unauthorized read (not in DAIN's read scopes)
        nonce2 = self.verifier.generate_challenge()
        payload2 = ("head_hash" + nonce2).encode()
        sig2 = MLDSASigner.sign(self.agent_priv, payload2).hex()
        token2 = ProofToken(
            agent_code=self.dain_res.agent_code,
            birth_record=ped_dict["birth_record"],
            current_head="head_hash",
            history_length=0,
            freshness_timestamp=time.time(),
            authority_reference="test",
            parent_birth_record=bain_ped_dict["birth_record"],
            challenge=nonce2,
            signature=sig2
        )
        verdict = self.receiver.validate(token2, action_type="read", resource="reddit_politics")
        assert verdict.ok is False
        assert "not authorized to read resource" in verdict.reason
