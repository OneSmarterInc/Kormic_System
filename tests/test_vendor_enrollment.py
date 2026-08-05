import pytest
import time
from kormic.crypto.algorithms import MLDSASigner
from kormic.crypto.software import SoftwareKeyCustody
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry

class TestVendorEnrollment:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.central = CentralRegistryAuthority(self.key_custody)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody._root_pub, self.central)

        self.vendor_priv, self.vendor_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.vendor_pub_hex = self.vendor_pub.hex()

    def test_enroll_valid_possession_proof(self):
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof-domain-com", challenge_nonce)
        self.replica.apply_snapshot(self.central.snapshot())
        
        # Verify it succeeds and is visible in replica
        assert self.replica.get_enrolled_vendor("acme").get('public_key') == self.vendor_pub_hex

    def test_enroll_bad_possession_proof_refused(self):
        challenge_nonce = "test-nonce-1"
        # Bad signature
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, b"wrong-challenge").hex()
        
        with pytest.raises(ValueError, match="Proof of possession failed"):
            self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof", challenge_nonce)

    def test_rebind_squat_refused(self):
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof1", challenge_nonce)
        
        attacker_priv, attacker_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        challenge_nonce2 = "test-nonce-2"
        attacker_sig = MLDSASigner.sign('ML-DSA-87', attacker_priv, f"{challenge_nonce2}:acme".encode('utf-8')).hex()
        
        with pytest.raises(ValueError, match="has already been bound"):
            self.central.enroll_vendor("acme", attacker_pub.hex(), attacker_sig, "proof2", challenge_nonce2)

    def test_revoke_does_not_reopen_name(self):
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof1", challenge_nonce)
        
        self.central.revoke_vendor("acme")
        
        challenge_nonce2 = "test-nonce-2"
        possession_sig2 = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce2}:acme".encode('utf-8')).hex()
        
        with pytest.raises(ValueError, match="has already been bound"):
            self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig2, "proof2", challenge_nonce2)

        self.replica.apply_snapshot(self.central.snapshot())
        assert self.replica.get_enrolled_vendor("acme") is None

    def test_rotate_vendor_key_stub(self):
        with pytest.raises(NotImplementedError):
            self.central.rotate_vendor_key()

    def test_snapshot_provenance_tampering(self):
        challenge_nonce = "test-nonce-1"
        possession_sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{challenge_nonce}:acme".encode('utf-8')).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, possession_sig, "proof1", challenge_nonce)
        
        snap = self.central.snapshot()
        # Tamper with snapshot
        snap.vendors["acme"]["public_key"] = "tampered"
        
        # Replica should reject it
        assert self.replica.apply_snapshot(snap) is False
        assert self.replica.get_enrolled_vendor("acme") is None

    def test_unknown_vendor_fail_closed(self):
        self.replica.apply_snapshot(self.central.snapshot())
        assert self.replica.get_enrolled_vendor("unknown") is None

    def test_possession_proof_cannot_be_replayed_under_new_name(self):
        nonce = "n1"
        sig = MLDSASigner.sign('ML-DSA-87', self.vendor_priv, f"{nonce}:acme".encode()).hex()
        self.central.enroll_vendor("acme", self.vendor_pub_hex, sig, "id-doc", nonce)
        # same key, same captured proof, different name -> must be refused
        with pytest.raises(ValueError):
            self.central.enroll_vendor("acme-payments", self.vendor_pub_hex, sig, "id-doc2", nonce)
        assert "acme-payments" not in self.central.vendors
