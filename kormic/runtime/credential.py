import os
import time
from typing import Dict, Any
from kormic.models.verify import ProofToken
from kormic.verify.engine import Verifier

class CredentialRoot:
    """
    MeshKor Credential Issuer.
    Enforces C2 (No Ambient Authority).
    Issues short-lived, scoped credentials gated exclusively by a passing FAST verification.
    """
    def __init__(self, verifier: Verifier):
        self.verifier = verifier

    def issue_scoped_credential(self, token: ProofToken, requested_scope: str, is_irreversible: bool = False) -> Dict[str, Any]:
        """
        Issues a temporary API credential if the scope is in the agent's sealed manifest.
        """
        # 1. Verification Gate
        verify_res = self.verifier.verify_fast(token)
        if verify_res.status != "PASS":
            return {"granted": False, "reason": f"Verification failed: {verify_res.reason}"}
            
        if not token.birth_record.get("agent_pub_key"):
            return {"granted": False, "reason": "Verification failed: Birth record carries no agent_pub_key. Keyless birth refused."}
            
        manifest = token.birth_record.get("guardrails", {})
        
        # 2. Scope Gate
        if requested_scope not in manifest.get("credential_scopes", []):
            return {"granted": False, "reason": "Scope not explicitly declared in birth manifest"}
            
        # 3. Irreversible Action Gate (Replit Countermeasure)
        if is_irreversible:
            irreversible_scopes = manifest.get("irreversible_scopes", [])
            if requested_scope not in irreversible_scopes:
                return {"granted": False, "reason": "Action requested is irreversible, but scope is not flagged as irreversible in manifest"}
                
        # 4. Issue Short-Lived Credential (e.g. 5 minutes)
        # In a real system, this would be a JWT or IAM session token.
        return {
            "granted": True, 
            "scope": requested_scope,
            "token": f"scoped:{requested_scope}:{os.urandom(8).hex()}", 
            "ttl_sec": 300
        }
