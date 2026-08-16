import time
from kormic.models.approval import DelegationAssertion
from kormic.crypto.algorithms import MLDSASigner
from kormic.interfaces.registry import RegistryReader

from kormic.crypto.agility import require_allowed_algorithm

def verify_delegation_assertion(
    assertion: DelegationAssertion,
    registry: RegistryReader,
    expected_action: str,
    expected_target: str,
    spend_nonce: bool = True
) -> bool:
    """
    Verifies that a delegation assertion is valid for the expected action and target.
    Raises ValueError on failure, or returns True on success.
    
    The single-use guarantee of the nonce is enforced per-replica within the 
    nonce time-to-live window.
    """
    if assertion.action != expected_action:
        raise ValueError(f"Action mismatch: expected '{expected_action}', got '{assertion.action}'")
    
    if assertion.target != expected_target:
        raise ValueError(f"Target mismatch: expected '{expected_target}', got '{assertion.target}'")

    if time.time() > assertion.expiry:
        raise ValueError("Delegation assertion has expired")

    # Fix 3: Assertion expiry bounded by nonce TTL
    if assertion.expiry > time.time() + 300:
        raise ValueError("Delegation assertion expiry exceeds nonce TTL")

    if spend_nonce and hasattr(registry, "spent_nonces") and assertion.nonce in registry.spent_nonces:
        raise ValueError("Delegation assertion nonce has already been spent")

    principal = registry.get_enrolled_principal(assertion.principal_ref)
    if not principal:
        raise ValueError(f"Principal '{assertion.principal_ref}' is not enrolled or is revoked")

    # Fix 2: Guard assertion's declared algorithm
    require_allowed_algorithm(assertion.sig_alg)
    if assertion.sig_alg != principal.get("sig_alg"):
        raise ValueError("Delegation assertion algorithm does not match enrolled principal")

    try:
        pub_bytes = bytes.fromhex(principal['public_key'])
        sig_bytes = bytes.fromhex(assertion.signature)
    except ValueError:
        raise ValueError("Invalid hex formatting in key or signature")

    if not MLDSASigner.verify(assertion.sig_alg, pub_bytes, assertion.signable_payload(), sig_bytes):
        raise ValueError("Delegation assertion signature verification failed")

    # Mark the nonce as spent
    if spend_nonce and hasattr(registry, "spend_nonce"):
        registry.spend_nonce(assertion.nonce)

    return True
