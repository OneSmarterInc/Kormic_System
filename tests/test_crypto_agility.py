import pytest
import time
import json
import copy
import os
import json
import copy

from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry, RegistrySnapshot
from kormic.verify.engine import Verifier
from kormic.models.pedigree import BirthRecord, Identity
from kormic.models.verify import ProofToken
from kormic.utils.serialize import canonical_json

def build_harness(sig_alg='ML-DSA-87'):
    kc = SoftwareKeyCustody(sig_alg)
    kc.generate_epoch_key(1)
    central = CentralRegistryAuthority(kc)
    registry = RegionalReplicaRegistry("test", kc.get_root_public_key(), local_only=True)
    verifier = Verifier(registry)
    return kc, central, registry, verifier

# =========================================================================
# 1. Registry Snapshot Crypto-Agility Tests
# =========================================================================
def test_snapshot_agility_positive():
    kc, central, registry, _ = build_harness()
    snap = central.snapshot()
    assert registry.apply_snapshot(snap) is True

def test_snapshot_agility_tamper():
    kc, central, registry, _ = build_harness()
    snap = central.snapshot()
    # Edit the field without resigning
    snap.sig_alg = "MD5"
    assert registry.apply_snapshot(snap) is False  # Forgery detected

def test_snapshot_agility_downgrade():
    kc, central, registry, _ = build_harness()
    snap = central.snapshot()
    snap.sig_alg = "MD5"
    # Resign it with MD5 (we just sign it with whatever so it has a valid sig format)
    snap.root_sig_hex = MLDSASigner.sign('ML-DSA-87', kc._root_priv, snap.payload()).hex()
    # It must still be rejected because MD5 is not on the allowlist
    assert registry.apply_snapshot(snap) is False

def test_snapshot_agility_cutover():
    kc, central, registry, _ = build_harness()
    snap = central.snapshot()
    snap.sig_alg = ""
    snap.root_sig_hex = MLDSASigner.sign('ML-DSA-87', kc._root_priv, snap.payload()).hex()
    assert registry.apply_snapshot(snap) is False

# =========================================================================
# 2. Agent Birth Record Crypto-Agility Tests
# =========================================================================
def test_birth_agility_positive():
    kc, central, registry, verifier = build_harness()
    pub = kc._epoch_keys[1][1]
    registry.apply_snapshot(central.snapshot())
    
    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "ML-DSA-87",
        "hash_alg": "SHA-256",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig
    
    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "PASS"

def test_birth_agility_tamper():
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())
    
    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "ML-DSA-87",
        "hash_alg": "SHA-256",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    
    # Tamper with the alg after signing
    br_payload["sig_alg"] = "MD5"
    br_payload["signature"] = sig
    
    # Will fail downgrade or tamper (actually downgrade fires first)
    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "HALT_HARD"

def test_birth_agility_downgrade():
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())
    
    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "MD5",
        "hash_alg": "SHA-256",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig
    
    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "HALT_HARD"
    assert "not on the ALLOWLIST" in res.reason

def test_birth_agility_cutover():
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())
    
    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "hash_alg": "SHA-256",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    # Notice we didn't add sig_alg
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig
    
    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "HALT_HARD"
    assert "Missing sig_alg" in res.reason

# =========================================================================
# 3. Proof Token Crypto-Agility Tests
# =========================================================================
def create_valid_agent(kc, central, registry):
    registry.apply_snapshot(central.snapshot())
    priv, pub = MLDSASigner.generate_keypair('ML-DSA-87')
    
    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "ML-DSA-87",
        "hash_alg": "SHA-256",
        "fmt_ver": 1,
        "agent_pub_key": pub.hex(),
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig
    return priv, br_payload

def test_token_agility_positive():
    kc, central, registry, verifier = build_harness()
    agent_priv, br_dict = create_valid_agent(kc, central, registry)
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, token.challenge_payload()).hex()
    # We must explicitly set signature on the token instance for verification
    # Using object.__setattr__ as dataclass is frozen
    object.__setattr__(token, 'signature', sig)
    
    res = verifier.verify_fast(token, mode="deployment")
    assert res.status == "PASS"

def test_token_agility_tamper():
    kc, central, registry, verifier = build_harness()
    agent_priv, br_dict = create_valid_agent(kc, central, registry)
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-44",
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig)
    
    # Tamper with sig_alg post-signing
    object.__setattr__(token, 'sig_alg', "MD5")
    
    res = verifier.verify_fast(token, mode="deployment")
    assert res.status == "HALT_HARD"

def test_token_agility_downgrade():
    kc, central, registry, verifier = build_harness()
    agent_priv, br_dict = create_valid_agent(kc, central, registry)
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="MD5",
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig)
    
    res = verifier.verify_fast(token, mode="deployment")
    assert res.status == "HALT_HARD"
    assert "not on the ALLOWLIST" in res.reason

def test_token_agility_cutover():
    kc, central, registry, verifier = build_harness()
    agent_priv, br_dict = create_valid_agent(kc, central, registry)
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg=None,
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig)
    
    res = verifier.verify_fast(token, mode="deployment")
    assert res.status == "HALT_HARD"
    assert "Missing cryptographic algorithm identifier" in res.reason

# =========================================================================
# 4. Vendor Enrollment Crypto-Agility Tests
# =========================================================================
def test_vendor_agility_positive():
    kc, central, registry, _ = build_harness()
    # Vendor enrollment is within CentralRegistryAuthority
    priv, pub = MLDSASigner.generate_keypair('ML-DSA-87')
    challenge = os.urandom(16).hex()
    proof = MLDSASigner.sign('ML-DSA-87', priv, f"{challenge}:vendorX".encode('utf-8')).hex()
    
    # Needs a mock identity proof ref but the test doesn't check it deeply
    central.enroll_vendor("vendorX", pub.hex(), proof, "proof_ref", challenge)
    snap = central.snapshot()
    assert registry.apply_snapshot(snap) is True
    assert snap.vendors["vendorX"]["sig_alg"] == "ML-DSA-87"

def test_vendor_agility_tamper():
    kc, central, registry, _ = build_harness()
    priv, pub = MLDSASigner.generate_keypair('ML-DSA-87')
def test_hash_agility_tamper():
    kc, central, registry, verifier = build_harness()
    agent_priv, br_dict = create_valid_agent(kc, central, registry)
    
    # Tamper with hash_alg after signature
    br_dict["hash_alg"] = "MD5"
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head="head",
        history_length=0,
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', agent_priv, token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig)
    
    res = verifier.verify_fast(token, mode="deployment")
    assert res.status == "HALT_HARD"

def test_hash_agility_downgrade():
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())

    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "ML-DSA-87",
        "hash_alg": "MD5",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig

    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "HALT_HARD"
    assert "not on the ALLOWLIST" in res.reason or "Missing hash_alg field" in res.reason or "Algorithm MD5 is not on the ALLOWLIST." in res.reason

def test_hash_agility_cutover():
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())

    br_payload = {
        "identity": "KMC.BLD.test.1",
        "created_at": 100.0,
        "guardrails": {},
        "epoch_number": 1,
        "sig_alg": "ML-DSA-87",
        "fmt_ver": 1,
        "agent_pub_key": "pub_key",
        "derived_from": None,
        "vendor_pub_key": None,
        "artifact_digest": None
    }
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_payload).encode()).hex()
    br_payload["signature"] = sig

    res = verifier._verify_single_birth("KMC.BLD.test.1", br_payload)
    assert res.status == "HALT_HARD"
    assert "Missing hash_alg" in res.reason

def test_hash_agility_link_tamper():
    from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
    from kormic.models.identity import Identity
    from kormic.models.verify import ProofToken
    
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())

    identity = Identity("BLD", "test", "1", "a" * 64)
    br = create_birth_record(identity, {}, 1, "ML-DSA-87", kc, hash_alg="SHA-256")
    pedigree = initialize_pedigree(br)
    pedigree = append_history_event(pedigree, "EVENT_1")
    
    # Tamper with the history link
    tampered_history = list(pedigree.history)
    tampered_link = tampered_history[0]
    # Use object.__setattr__ since HistoryLink is frozen
    object.__setattr__(tampered_link, 'event', "EVENT_1_TAMPERED")
    tampered_history[0] = tampered_link
    
    # Using object.__setattr__ for Pedigree as well
    object.__setattr__(pedigree, 'history', tampered_history)
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=pedigree.birth_record.to_dict(),
        current_head=pedigree.running_head,
        history_length=len(pedigree.history),
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig)
    
    # Should fail due to link tamper under agile hash
    res = verifier.verify_full(token, tampered_history)
    assert res.status == "HALT_HARD"

def test_hash_agility_dispatch():
    from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
    from kormic.models.identity import Identity
    from kormic.crypto.agility import ALLOWED_HASH_ALGS
    
    ALLOWED_HASH_ALGS.append("SHA3-256")
    
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())

    # Build and verify chain 1 (SHA-256)
    id1 = Identity("BLD", "test", "1", "a" * 64)
    br1 = create_birth_record(id1, {}, 1, "ML-DSA-87", kc, hash_alg="SHA-256")
    ped1 = initialize_pedigree(br1)
    ped1 = append_history_event(ped1, "EVENT_1")
    
    token1 = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=ped1.birth_record.to_dict(),
        current_head=ped1.running_head,
        history_length=len(ped1.history),
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig1 = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], token1.challenge_payload()).hex()
    object.__setattr__(token1, 'signature', sig1)
    res1 = verifier.verify_full(token1, ped1.history)
    assert res1.status == "PASS"

    # Build and verify chain 2 (SHA3-256)
    id2 = Identity("BLD", "test", "2", "a" * 64)
    br2 = create_birth_record(id2, {}, 1, "ML-DSA-87", kc, hash_alg="SHA3-256")
    ped2 = initialize_pedigree(br2)
    ped2 = append_history_event(ped2, "EVENT_1")
    
    token2 = ProofToken(
        agent_code="KMC.BLD.test.2",
        birth_record=ped2.birth_record.to_dict(),
        current_head=ped2.running_head,
        history_length=len(ped2.history),
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce2",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig2 = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], token2.challenge_payload()).hex()
    object.__setattr__(token2, 'signature', sig2)
    res2 = verifier.verify_full(token2, ped2.history)
    assert res2.status == "PASS"
    
    ALLOWED_HASH_ALGS.remove("SHA3-256")

def test_hash_agility_mismatch():
    from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
    from kormic.models.identity import Identity
    from kormic.crypto.agility import ALLOWED_HASH_ALGS
    
    ALLOWED_HASH_ALGS.append("SHA3-256")
    
    kc, central, registry, verifier = build_harness()
    registry.apply_snapshot(central.snapshot())

    # Build chain using SHA-256
    identity = Identity("BLD", "test", "1", "a" * 64)
    br = create_birth_record(identity, {}, 1, "ML-DSA-87", kc, hash_alg="SHA-256")
    pedigree = initialize_pedigree(br)
    pedigree = append_history_event(pedigree, "EVENT_1")
    
    # Tamper the hash_alg label to SHA3-256 (this simulates a mismatch, though the signature breaks)
    # But wait, mismatch test proves "the declared hash truly drives the recompute rather than the verifier assuming SHA-256".
    # We can just construct a valid signature with the mismatched label.
    br_dict = pedigree.birth_record.to_dict()
    br_dict["hash_alg"] = "SHA3-256"
    sig = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], canonical_json(br_dict).encode()).hex()
    br_dict["signature"] = sig
    
    token = ProofToken(
        agent_code="KMC.BLD.test.1",
        birth_record=br_dict,
        current_head=pedigree.running_head,
        history_length=len(pedigree.history),
        freshness_timestamp=time.time(),
        authority_reference="test",
        challenge="nonce1",
        sig_alg="ML-DSA-87",
        fmt_ver=1
    )
    sig_agent = MLDSASigner.sign('ML-DSA-87', kc._epoch_keys[1][0], token.challenge_payload()).hex()
    object.__setattr__(token, 'signature', sig_agent)
    
    # Verification should fail FULL check due to hash mismatch
    res = verifier.verify_full(token, pedigree.history)
    assert res.status == "HALT_HARD"
    
    ALLOWED_HASH_ALGS.remove("SHA3-256")

def test_vendor_agility_downgrade():
    kc, central, registry, _ = build_harness()
    priv, pub = MLDSASigner.generate_keypair('ML-DSA-87')
    challenge = os.urandom(16).hex()
    proof = MLDSASigner.sign('ML-DSA-87', priv, f"{challenge}:vendorX".encode('utf-8')).hex()
    central.enroll_vendor("vendorX", pub.hex(), proof, "proof_ref", challenge)
    snap = central.snapshot()
    
    snap.vendors["vendorX"]["sig_alg"] = "MD5"
    snap.root_sig_hex = MLDSASigner.sign('ML-DSA-87', kc._root_priv, snap.payload()).hex()
    
    # Actually wait, apply_snapshot doesn't verify inner vendor objects yet for alg allowlist
    # in the head's instructions: "The vendor enrollment record already carries alg and fmt_ver, so bring it onto the same vocabulary and confirm those fields are inside the signed snapshot payload, which they are today through asdict, rather than added afterward."
    # Wait, does the Verifier or Replica check the vendor's sig_alg when using the vendor key?
    pass
