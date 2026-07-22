import pytest
import os
import dataclasses
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.models.pedigree import Pedigree

from meshkor import MeshKorAgent, ReceiverClient, LocalAuthority

@pytest.fixture
def meshkor_system(tmp_path):
    db_path = str(tmp_path / "test_meshkor_sdk.db")
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub)
    verifier = Verifier(replica)
    authority = LocalAuthority(manager, verifier, central, replica)
    
    yield authority

def test_sdk_happy_path(meshkor_system):
    authority = meshkor_system
    
    manifest = {"allowed_tools": ["test"]}
    agent = MeshKorAgent.enroll(
        authority, "CMP", "test_co", "0001", "id123", manifest
    )
    
    agent.record_event("action 1")
    
    rc = ReceiverClient(authority)
    challenge = rc.new_challenge()
    
    token = agent.mint_token(challenge)
    verdict = rc.validate(token)
    
    assert verdict.ok is True
    assert verdict.status == "PASS"
    assert verdict.may_reach["allowed_tools"] == ["test"]

def test_sdk_interop_full_verify(meshkor_system):
    """FINDING 1 DoD: Prove SDK events advance actual history."""
    authority = meshkor_system
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    agent.record_event("action 1")
    agent.record_event("action 2")
    
    token = agent.mint_token()
    verifier = authority.get_verifier()
    
    ped_dict = authority.get_pedigree(agent.ain)
    history_links = Pedigree.from_dict(ped_dict).history
    result = verifier.verify_full(token, history_links)
    assert result.status == "PASS"

def test_sdk_mangled_token_signature_failure(meshkor_system):
    """Proves a token tampered in transit fails the signature check (Finding 2)."""
    authority = meshkor_system
    agent = MeshKorAgent.enroll(
        authority, "CMP", "test_co", "0001", "id123", {}
    )
    
    rc = ReceiverClient(authority)
    token = agent.mint_token(rc.new_challenge())
    
    # Attacker tampers with the head WITHOUT re-signing
    token = dataclasses.replace(token, current_head="0000000000000000000000000000000000000000000000000000000000000000")
    
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert verdict.status == "HALT_HARD"

def test_sdk_forged_but_signed_head(meshkor_system):
    """Proves FAST accepts signed heads, but FULL rejects them (Finding 2)."""
    authority = meshkor_system
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    rc = ReceiverClient(authority)
    
    # Forge a fake head
    fake_head = "0000000000000000000000000000000000000000000000000000000000000000"
    challenge = rc.new_challenge()
    
    # The attacker RE-SIGNS the forged head with their valid private key
    payload = (fake_head + challenge).encode('utf-8')
    forged_sig = MLDSASigner.sign(agent.private_key, payload).hex()
    
    forged_token = dataclasses.replace(
        agent.mint_token(challenge),
        current_head=fake_head,
        signature=forged_sig
    )
    
    fast_verdict = rc.validate(forged_token)
    assert fast_verdict.ok is True
    
    # PROTOCOL DECISION: Should FULL spend the nonce when it re-runs FAST internally?
    # Yes. Any genuine FAST->FULL escalation must require a fresh challenge-response 
    # to prove real-time liveness during the escalation. We mint a fresh token here 
    # to avoid the replay trap and test the actual head-matching logic.
    challenge_full = rc.new_challenge()
    payload_full = (fake_head + challenge_full).encode('utf-8')
    forged_sig_full = MLDSASigner.sign(agent.private_key, payload_full).hex()
    
    forged_token_full = dataclasses.replace(
        agent.mint_token(challenge_full),
        current_head=fake_head,
        signature=forged_sig_full
    )
    
    # FULL rejects it (Walks the actual history and sees the head mismatch)
    ped_dict = authority.get_pedigree(agent.ain)
    history_links = Pedigree.from_dict(ped_dict).history
    full_result = authority.get_verifier().verify_full(forged_token_full, history_links)
    
    assert full_result.status == "HALT_HARD"
    assert "does not match token head" in full_result.reason

def test_sdk_replayed_token(meshkor_system):
    authority = meshkor_system
    agent = MeshKorAgent.enroll(
        authority, "CMP", "test_co", "0001", "id123", {}
    )
    
    rc = ReceiverClient(authority)
    token = agent.mint_token(rc.new_challenge())
    
    # First time works
    verdict1 = rc.validate(token)
    assert verdict1.ok is True
    
    # Second time (Replay) fails
    verdict2 = rc.validate(token)
    assert verdict2.ok is False
    assert verdict2.status == "HALT_HARD"
    assert "Replay Attack Detected" in verdict2.reason

def test_sdk_wrong_key(meshkor_system):
    """DoD: wrong-key HALT."""
    authority = meshkor_system
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    
    # Swap out the agent's private key for a totally different one
    bad_priv_key, _ = MLDSASigner.generate_keypair()
    agent.private_key = bad_priv_key
    
    rc = ReceiverClient(authority)
    token = agent.mint_token(rc.new_challenge())
    
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert verdict.status == "HALT_HARD"

def test_sdk_revoked_agent(meshkor_system):
    """DoD: revoked agent."""
    authority = meshkor_system
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    
    # Revoke via central registry
    authority._central_registry.revoke_agent(agent.ain)
    authority._regional_replica.apply_snapshot(authority._central_registry.snapshot())
    
    rc = ReceiverClient(authority)
    token = agent.mint_token(rc.new_challenge())
    
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert verdict.status == "REVOKED"
