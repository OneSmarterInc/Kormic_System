import pytest
import time
from kormic.crypto.software import SoftwareKeyCustody
from kormic.crypto.algorithms import MLDSASigner
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.models.approval import DelegationAssertion
from kormic.verify.approval import verify_delegation_assertion

class TestApprovalVerification:
    def setup_method(self):
        self.key_custody = SoftwareKeyCustody()
        self.key_custody.generate_epoch_key(1)
        self.central = CentralRegistryAuthority(self.key_custody)
        self.replica = RegionalReplicaRegistry("test-region", self.key_custody.get_root_public_key(), central_sync=self.central)

        self.principal_priv, self.principal_pub = MLDSASigner.generate_keypair('ML-DSA-87')
        self.principal_pub_hex = self.principal_pub.hex()

        challenge = "nonce-enroll"
        payload = f"{challenge}:alice".encode("utf-8")
        sig = MLDSASigner.sign('ML-DSA-87', self.principal_priv, payload).hex()
        self.central.enroll_principal("alice", self.principal_pub_hex, sig, "proof-ref", challenge)
        self.replica.apply_snapshot(self.central.snapshot())

    def _create_assertion(self, action, target, expiry, nonce, priv_key=None, principal_ref="alice"):
        if priv_key is None:
            priv_key = self.principal_priv
        
        assertion = DelegationAssertion(
            principal_ref=principal_ref,
            action=action,
            target=target,
            expiry=expiry,
            nonce=nonce,
            sig_alg="ML-DSA-87",
            fmt_ver=1
        )
        sig = MLDSASigner.sign('ML-DSA-87', priv_key, assertion.signable_payload()).hex()
        # Create a new assertion with the signature
        return DelegationAssertion(
            principal_ref=assertion.principal_ref,
            action=assertion.action,
            target=assertion.target,
            expiry=assertion.expiry,
            nonce=assertion.nonce,
            signature=sig,
            sig_alg=assertion.sig_alg,
            fmt_ver=assertion.fmt_ver
        )

    def test_verify_assertion_success(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1")
        assert verify_delegation_assertion(assertion, self.replica, "release", "artifact_123") == True

    def test_verify_assertion_wrong_action(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1")
        with pytest.raises(ValueError, match="Action mismatch"):
            verify_delegation_assertion(assertion, self.replica, "approve", "artifact_123")

    def test_verify_assertion_wrong_target(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1")
        with pytest.raises(ValueError, match="Target mismatch"):
            verify_delegation_assertion(assertion, self.replica, "release", "artifact_456")

    def test_verify_assertion_expired(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() - 300, "nonce-1")
        with pytest.raises(ValueError, match="expired"):
            verify_delegation_assertion(assertion, self.replica, "release", "artifact_123")

    def test_verify_assertion_wrong_key(self):
        rogue_priv, _ = MLDSASigner.generate_keypair('ML-DSA-87')
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1", priv_key=rogue_priv)
        with pytest.raises(ValueError, match="signature verification failed"):
            verify_delegation_assertion(assertion, self.replica, "release", "artifact_123")

    def test_verify_assertion_unenrolled_principal(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1", principal_ref="bob")
        with pytest.raises(ValueError, match="not enrolled"):
            verify_delegation_assertion(assertion, self.replica, "release", "artifact_123")

    def test_verify_assertion_replayed(self):
        assertion = self._create_assertion("release", "artifact_123", time.time() + 300, "nonce-1")
        assert verify_delegation_assertion(assertion, self.replica, "release", "artifact_123") == True
        # The replica should have synced the spend if local
        with pytest.raises(ValueError, match="spent"):
            verify_delegation_assertion(assertion, self.replica, "release", "artifact_123")
