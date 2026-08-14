import time
from kormic.models.approval import DelegationAssertion
from kormic.crypto.algorithms import MLDSASigner
from kormic.interfaces.registry import RegistryReader

def verify_delegation_assertion(
    assertion: DelegationAssertion,
    registry: RegistryReader,
    expected_action: str,
    expected_target: str
) -> bool:
    """
    Verifies that a delegation assertion is valid for the expected action and target.
    Raises ValueError on failure, or returns True on success.
    """
    if assertion.action != expected_action:
        raise ValueError(f"Action mismatch: expected '{expected_action}', got '{assertion.action}'")
    
    if assertion.target != expected_target:
        raise ValueError(f"Target mismatch: expected '{expected_target}', got '{assertion.target}'")

    if time.time() > assertion.expiry:
        raise ValueError("Delegation assertion has expired")

    if hasattr(registry, "spent_nonces") and assertion.nonce in registry.spent_nonces:
        raise ValueError("Delegation assertion nonce has already been spent")

    principal = registry.get_enrolled_principal(assertion.principal_ref)
    if not principal:
        raise ValueError(f"Principal '{assertion.principal_ref}' is not enrolled or is revoked")

    try:
        pub_bytes = bytes.fromhex(principal['public_key'])
        sig_bytes = bytes.fromhex(assertion.signature)
    except ValueError:
        raise ValueError("Invalid hex formatting in key or signature")

    if not MLDSASigner.verify(assertion.sig_alg, pub_bytes, assertion.signable_payload(), sig_bytes):
        raise ValueError("Delegation assertion signature verification failed")

    # Mark the nonce as spent
    if hasattr(registry, "spend_nonce"):
        registry.spend_nonce(assertion.nonce)

    return True
