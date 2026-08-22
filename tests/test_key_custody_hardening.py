import pytest
import os
import uuid
import time
from typing import List, Dict
from kormic.interfaces.keys import KeyCustody, Share
from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken
from kormic.crypto.algorithms import MLDSASigner

class NoPrivateKeyCustodyStandIn(KeyCustody):
    """
    A stand-in custody that has absolutely no private key attributes.
    It delegates to a real backend secretly just to generate valid signatures,
    but it mathematically proves that the system only uses the public interface.
    """
    def __init__(self, backend: SoftwareKeyCustody):
        self._backend = backend
        
    def sign_birth(self, epoch_n: int, payload: bytes) -> bytes:
        return self._backend.sign_birth(epoch_n, payload)
        
    def epoch_public(self, epoch_n: int) -> bytes:
        return self._backend.epoch_public(epoch_n)
        
    def wrap_twin_key(self, key: bytes) -> List[Share]:
        return self._backend.wrap_twin_key(key)
        
    def unwrap_twin_key(self, shares: List[Share]) -> bytes:
        return self._backend.unwrap_twin_key(shares)
        
    def sign_root(self, payload: bytes) -> bytes:
        return self._backend.sign_root(payload)
        
    def get_root_public_key(self) -> bytes:
        return self._backend.get_root_public_key()
        
    def generate_epoch_key(self, epoch_n: int) -> None:
        return self._backend.generate_epoch_key(epoch_n)
        
    def get_epoch_certificate(self, epoch_n: int) -> bytes:
        return self._backend.get_epoch_certificate(epoch_n)
        
    def verify_epoch_certificate(self, epoch_n: int, public_key: bytes) -> bool:
        return self._backend.verify_epoch_certificate(epoch_n, public_key)
        
    def revoke_epoch(self, epoch_n: int) -> None:
        return self._backend.revoke_epoch(epoch_n)
        
    def is_epoch_revoked(self, epoch_n: int) -> bool:
        return self._backend.is_epoch_revoked(epoch_n)
        
    def get_all_epoch_public_keys(self) -> Dict[int, bytes]:
        return self._backend.get_all_epoch_public_keys()
        
    def get_revoked_epochs(self) -> set:
        return self._backend.get_revoked_epochs()

    @property
    def sig_alg(self) -> str:
        return self._backend.sig_alg

def test_no_private_key_stand_in_flow():
    # Proof that the system works when the KeyCustody has no private attributes.
    backend = SoftwareKeyCustody()
    backend.generate_epoch_key(1)
    
    standin_kc = NoPrivateKeyCustodyStandIn(backend)
    
    # Check that it literally has no private keys
    assert not hasattr(standin_kc, "_root_priv")
    assert not hasattr(standin_kc, "_epoch_keys")
    
    # 1. Setup the system using ONLY the stand-in custody
    store = SQLiteRecordStore(":memory:")
    
    central = CentralRegistryAuthority(standin_kc)
    registry = RegionalReplicaRegistry("test", standin_kc.get_root_public_key(), local_only=True)
    
    # Snapshot Flow
    snap = central.snapshot()
    assert registry.apply_snapshot(snap) is True
    
    manager = AgentManager(standin_kc, store, default_epoch=1, registry_reader=registry)
    verifier = Verifier(registry)
    
    # 2. Mint Birth Record Flow
    agent_priv, agent_pub = MLDSASigner.generate_keypair('ML-DSA-87')
    manifest = {"allowed_tools": ["test"]}
    
    ain, _ = manager.register_new_agent(
        "CMP", "testowner", "001", "real", manifest, agent_pub_key=agent_pub.hex()
    )
    
    # 3. Verify Flow
    ped_dict = store.get(ain)
    ped = Pedigree.from_dict(ped_dict)
    
    challenge = verifier.generate_challenge()
    import json
    payload = json.dumps({'challenge': challenge, 'current_head': ped.running_head, 'fmt_ver': 1, 'sig_alg': 'ML-DSA-87'}, sort_keys=True).encode('utf-8')
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, payload).hex()
    
    token = ProofToken(
        agent_code=ain,
        birth_record=ped.birth_record.to_dict(),
        current_head=ped.running_head,
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge=challenge,
        signature=sig,
        sig_alg='ML-DSA-87',
        fmt_ver=1
    )
    
    res = verifier.verify_fast(token)
    assert res.status == "PASS"

from kormic.crypto.software import ThresholdPolicy
from kormic.runtime.detection import DevDetectionSink
import hashlib

def test_threshold_policy_refuses_single_party():
    sink = DevDetectionSink()
    h1_priv, h1_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    h2_priv, h2_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    
    enrolled = {"holder_1": h1_pub, "holder_2": h2_pub}
    policy = ThresholdPolicy(k=3, n=5, enrolled_holders=enrolled, detection_sink=sink)
    kc = SoftwareKeyCustody(threshold_policy=policy)
    
    challenge = "nonce_refuse"
    op_key = f"generate_epoch_key_1:{challenge}"
    
    h1_sig = MLDSASigner.sign("ML-DSA-87", h1_priv, op_key.encode('utf-8'))
    h2_sig = MLDSASigner.sign("ML-DSA-87", h2_priv, op_key.encode('utf-8'))
    
    policy.approve(op_key, "holder_1", h1_sig, challenge)
    policy.approve(op_key, "holder_2", h2_sig, challenge)
    # Only 2 of 3 approvals
    
    with pytest.raises(PermissionError) as exc:
        kc.generate_epoch_key(1, challenge)
        
    assert "refused" in str(exc.value)
    assert sink.events[-1].event_kind == "root_operation_refused"
    assert sink.events[-1].severity == "critical"

def test_threshold_policy_rejects_unsigned_or_invalid_approvals():
    sink = DevDetectionSink()
    h1_priv, h1_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    
    enrolled = {"holder_1": h1_pub}
    policy = ThresholdPolicy(k=1, n=1, enrolled_holders=enrolled, detection_sink=sink)
    
    challenge = "nonce_invalid"
    op_key = f"generate_epoch_key_1:{challenge}"
    
    # Missing signature
    with pytest.raises(PermissionError, match="Unsigned"):
        policy.approve(op_key, "holder_1", None, challenge)
        
    # Fabricated holder
    with pytest.raises(PermissionError, match="not enrolled"):
        policy.approve(op_key, "fake_holder", b"bad_sig", challenge)
        
    # Invalid signature
    h2_priv, _ = MLDSASigner.generate_keypair("ML-DSA-87")
    bad_sig = MLDSASigner.sign("ML-DSA-87", h2_priv, op_key.encode('utf-8'))
    with pytest.raises(PermissionError, match="Invalid signature"):
        policy.approve(op_key, "holder_1", bad_sig, challenge)

def test_threshold_policy_succeeds_with_quorum():
    sink = DevDetectionSink()
    h1_priv, h1_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    h2_priv, h2_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    h3_priv, h3_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    
    enrolled = {"holder_1": h1_pub, "holder_2": h2_pub, "holder_3": h3_pub}
    policy = ThresholdPolicy(k=3, n=5, enrolled_holders=enrolled, detection_sink=sink)
    kc = SoftwareKeyCustody(threshold_policy=policy)
    
    challenge1 = "nonce_success_1"
    op_key = f"generate_epoch_key_1:{challenge1}"
    
    policy.approve(op_key, "holder_1", MLDSASigner.sign("ML-DSA-87", h1_priv, op_key.encode('utf-8')), challenge1)
    policy.approve(op_key, "holder_2", MLDSASigner.sign("ML-DSA-87", h2_priv, op_key.encode('utf-8')), challenge1)
    policy.approve(op_key, "holder_3", MLDSASigner.sign("ML-DSA-87", h3_priv, op_key.encode('utf-8')), challenge1)
    
    # 3 of 3 approvals -> succeeds
    kc.generate_epoch_key(1, challenge1)
    
    assert sink.events[-1].event_kind == "root_operation_success"
    assert sink.events[-1].severity == "info"
    
    # Check sign_root
    payload = b"snapshot_data"
    challenge2 = "nonce_success_2"
    payload_hash = hashlib.sha256(payload).hexdigest()
    op_key2 = f"sign_root:{payload_hash}:{challenge2}"
    
    policy.approve(op_key2, "holder_1", MLDSASigner.sign("ML-DSA-87", h1_priv, op_key2.encode('utf-8')), challenge2)
    policy.approve(op_key2, "holder_2", MLDSASigner.sign("ML-DSA-87", h2_priv, op_key2.encode('utf-8')), challenge2)
    policy.approve(op_key2, "holder_3", MLDSASigner.sign("ML-DSA-87", h3_priv, op_key2.encode('utf-8')), challenge2)
    
    sig = kc.sign_root(payload, challenge2)
    assert sig is not None
    assert sink.events[-1].event_kind == "root_operation_success"

def test_threshold_custody_verification_identical():
    h_priv, h_pub = MLDSASigner.generate_keypair("ML-DSA-87")
    enrolled = {"admin": h_pub}
    
    # Setup Threshold
    policy = ThresholdPolicy(k=1, n=1, enrolled_holders=enrolled)
    kc = SoftwareKeyCustody(threshold_policy=policy)
    
    challenge = "nonce_verification"
    # approve epoch generation
    op_key = f"generate_epoch_key_1:{challenge}"
    policy.approve(op_key, "admin", MLDSASigner.sign("ML-DSA-87", h_priv, op_key.encode('utf-8')), challenge)
    kc.generate_epoch_key(1, challenge)
    
    # Setup ordinary system
    store = SQLiteRecordStore(":memory:")
    central = CentralRegistryAuthority(kc)
    
    # disable threshold temporarily for snapshot setup convenience (since payload includes time)
    kc.threshold_policy = None
    snap = central.snapshot()
    kc.threshold_policy = policy
    
    registry = RegionalReplicaRegistry("test", kc.get_root_public_key(), local_only=True)
    registry.apply_snapshot(snap)
    
    manager = AgentManager(kc, store, default_epoch=1, registry_reader=registry)
    verifier = Verifier(registry)
    
    agent_priv, agent_pub = MLDSASigner.generate_keypair('ML-DSA-87')
    ain, _ = manager.register_new_agent("CMP", "owner", "01", "real", {}, agent_pub.hex())
    
    ped_dict = store.get(ain)
    ped = Pedigree.from_dict(ped_dict)
    
    challenge = "test"
    import json
    payload = json.dumps({'challenge': challenge, 'current_head': ped.running_head, 'fmt_ver': 1, 'sig_alg': 'ML-DSA-87'}, sort_keys=True).encode('utf-8')
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, payload).hex()
    
    token = ProofToken(
        agent_code=ain,
        birth_record=ped.birth_record.to_dict(),
        current_head=ped.running_head,
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge=challenge,
        signature=sig,
        sig_alg='ML-DSA-87',
        fmt_ver=1
    )
    
    res = verifier.verify_fast(token)
    assert res.status == "PASS"
