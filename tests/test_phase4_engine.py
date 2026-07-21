import pytest
import time
import dataclasses
from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from meshkor import MeshKorAgent, LocalAuthority, ReceiverClient

@pytest.fixture
def phase4_system(tmp_path):
    db_path = str(tmp_path / "test_phase4.db")
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub)
    verifier = Verifier(replica)
    authority = LocalAuthority(manager, verifier, central, replica)
    
    yield manager, central, replica, verifier, authority

def test_gap3_clock_skew_future(phase4_system):
    """Test GAP 3: Token freshness timestamp is too far in the future (skew > 30s)"""
    manager, central, replica, verifier, authority = phase4_system
    
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    rc = ReceiverClient(authority)
    
    # Mint a token, but forge the timestamp to be 60 seconds in the future
    future_time = time.time() + 60
    token = agent.mint_token(rc.new_challenge())
    token = dataclasses.replace(token, freshness_timestamp=future_time)
    
    # Validation should fail because the token is from the future (skew < -30)
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert "Clock Skew" in verdict.reason

def test_gap3_clock_skew_expired(phase4_system):
    """Test GAP 3: Token is older than the TTL (skew > 300s)"""
    manager, central, replica, verifier, authority = phase4_system
    
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    rc = ReceiverClient(authority)
    
    # Mint a token, but forge the timestamp to be 10 minutes in the past
    past_time = time.time() - 600
    token = agent.mint_token(rc.new_challenge())
    token = dataclasses.replace(token, freshness_timestamp=past_time)
    
    verdict = rc.validate(token)
    assert verdict.ok is False
    assert "Clock Skew" in verdict.reason

def test_gap2_distributed_nonce_sync(phase4_system):
    """Test GAP 2: Spent nonces sync globally across replicas"""
    manager, central, replica, verifier, authority = phase4_system
    
    # Simulate spending a nonce on the Central Authority
    challenge = "global_spent_nonce_123"
    central.spend_nonce(challenge)
    
    # Sync the regional replica (this proves the state is distributed)
    replica.apply_snapshot(central.snapshot())
    
    # The verifier checks the regional replica. It should now know the nonce is spent.
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    token = agent.mint_token(challenge)
    
    verdict = rc = ReceiverClient(authority).validate(token)
    assert verdict.ok is False
    assert "Replay Attack Detected" in verdict.reason

def test_hash_only_anchoring_record(phase4_system):
    """Test Part 3: Engine accepts blind hashes instead of raw PII"""
    manager, central, replica, verifier, authority = phase4_system
    
    agent = MeshKorAgent.enroll(authority, "CMP", "test_co", "0001", "id123", {})
    
    # Instead of sending "get_patient_file", the sidecar sends the hash
    blinded_hash_event = "BLIND_HASH:5f4dcc3b5aa765d61d8327deb882cf99"
    authority.record_event(agent.ain, blinded_hash_event)
    
    ped_dict = authority.get_pedigree(agent.ain)
    assert len(ped_dict["history"]) == 1
    assert ped_dict["history"][0]["event"] == blinded_hash_event
