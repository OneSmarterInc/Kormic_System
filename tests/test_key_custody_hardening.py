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
