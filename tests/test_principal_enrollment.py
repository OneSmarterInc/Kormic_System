import pytest
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry

class TestPrincipalEnrollment:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.central = CentralRegistryAuthority(self.key_custody)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody.get_root_public_key(), central_sync=self.central)

        self.principal_priv, self.principal_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.principal_pub_hex = self.principal_pub.hex()

    def test_enroll_principal_success(self):
        challenge = "nonce-1"
        payload = f"{challenge}:alice".encode("utf-8")
        sig = MLDSASigner.sign('ML-DSA-87', self.principal_priv, payload).hex()

        self.central.enroll_principal("alice", self.principal_pub_hex, sig, "proof-ref", challenge)
        self.replica.apply_snapshot(self.central.snapshot())

        principal = self.replica.get_enrolled_principal("alice")
        assert principal is not None
        assert principal['public_key'] == self.principal_pub_hex

    def test_enroll_principal_duplicate_fails(self):
        challenge = "nonce-1"
        payload = f"{challenge}:alice".encode("utf-8")
        sig = MLDSASigner.sign('ML-DSA-87', self.principal_priv, payload).hex()
        self.central.enroll_principal("alice", self.principal_pub_hex, sig, "proof-ref", challenge)

        challenge2 = "nonce-2"
        payload2 = f"{challenge2}:alice".encode("utf-8")
        sig2 = MLDSASigner.sign('ML-DSA-87', self.principal_priv, payload2).hex()

        with pytest.raises(ValueError, match="already been bound"):
            self.central.enroll_principal("alice", self.principal_pub_hex, sig2, "proof-ref-2", challenge2)

    def test_enroll_principal_bad_proof(self):
        challenge = "nonce-1"
        payload = f"{challenge}:wrong-name".encode("utf-8")
        sig = MLDSASigner.sign('ML-DSA-87', self.principal_priv, payload).hex()

        with pytest.raises(ValueError, match="Proof of possession failed"):
            self.central.enroll_principal("alice", self.principal_pub_hex, sig, "proof-ref", challenge)
