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

def test_gap2_distributed_nonce_sync(tmp_path):
    """Test GAP 2: Spent nonces sync globally across replicas"""
    db_path = str(tmp_path / "test_gap2.db")
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(db_path)
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    
    # Replica A (us-east) connected to Central
    replica_a = RegionalReplicaRegistry("us-east", keys._root_pub, central_sync=central)
    verifier_a = Verifier(replica_a)
    authority_a = LocalAuthority(manager, verifier_a, central, replica_a)
    rc_a = ReceiverClient(authority_a)
    
    # Replica B (eu-west) connected to Central
    replica_b = RegionalReplicaRegistry("eu-west", keys._root_pub, central_sync=central)
    verifier_b = Verifier(replica_b)
    authority_b = LocalAuthority(manager, verifier_b, central, replica_b)
    rc_b = ReceiverClient(authority_b)
    
    agent = MeshKorAgent.enroll(authority_a, "CMP", "test_co", "0001", "id123", {})
    
    # Generate a single token
    token = agent.mint_token(rc_a.new_challenge())
    
    # 1. Use the token in Region A (This should pass AND promote the spent nonce to Central)
    verdict_a = rc_a.validate(token)
    assert verdict_a.ok is True
    
    # 2. Sync Region B to get the latest snapshot from Central
    replica_b.apply_snapshot(central.snapshot())
    
    # 3. Attempt a replay attack using the SAME token in Region B
    verdict_b = rc_b.validate(token)
    assert verdict_b.ok is False
    assert "Replay Attack Detected" in verdict_b.reason

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
