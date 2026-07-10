import os
from typing import Dict, Any, List
import hashlib
from kormic.crypto.algorithms import MLDSASigner
from kormic.models.verify import ProofToken
from kormic.verify.engine import Verifier
from kormic.interfaces.registry import RegistryReader

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

class Sandbox:
    """
    Kormic Runtime Sandbox Wrapper.
    Enforces C1 (Manifest Isolation).
    Any action outside the manifest is blocked and logged.
    """
    def __init__(self, verifier: Verifier, token: ProofToken):
        self.verifier = verifier
        self.token = token
        
        # 1. FAST Verification (Validates Challenge-Response)
        verify_res = self.verifier.verify_fast(self.token)
        if verify_res.status != "PASS":
            raise PermissionError(f"Session refused: FAST verification failed. Reason: {verify_res.reason}")
            
        self.manifest = self.token.birth_record.get("guardrails", {})
            
        # 3. Action log (feeds the drift chain)
        self.action_log = []

    def use_tool(self, tool: str) -> str:
        """C1: Manifest Isolation for Tools"""
        allowed_tools = self.manifest.get("allowed_tools", [])
        ok = tool in allowed_tools
        self.action_log.append(("tool", tool, ok))
        
        if not ok:
            raise PermissionError(f"BLOCKED: Tool '{tool}' not in this agent's sealed manifest.")
        return f"Tool {tool} executed"

    def call_endpoint(self, endpoint: str) -> str:
        """C1: Manifest Isolation for Network Endpoints"""
        allowed_endpoints = self.manifest.get("allowed_endpoints", [])
        ok = endpoint in allowed_endpoints
        self.action_log.append(("endpoint", endpoint, ok))
        
        if not ok:
            raise PermissionError(f"BLOCKED: Endpoint '{endpoint}' not in sealed manifest. Cross-agent/shared-runtime reach denied.")
        return f"Endpoint {endpoint} reached"
        
    def drift_detected(self) -> bool:
        """Returns True if any out-of-manifest action was attempted."""
        return any(ok is False for _, _, ok in self.action_log)
