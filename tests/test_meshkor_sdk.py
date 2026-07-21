import pytest
import os
from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier

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

def test_sdk_tampered_head(meshkor_system):
    authority = meshkor_system
    agent = MeshKorAgent.enroll(
        authority, "CMP", "test_co", "0001", "id123", {}
    )
    
    rc = ReceiverClient(authority)
    token = agent.mint_token(rc.new_challenge())
    
    # Attacker tampers with the head
    import dataclasses
    token = dataclasses.replace(token, current_head="0000000000000000000000000000000000000000000000000000000000000000")
    
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert verdict.status == "HALT_HARD"

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
