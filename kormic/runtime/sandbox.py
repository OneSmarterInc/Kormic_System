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
            
        if not self.token.birth_record.get("agent_pub_key"):
            raise PermissionError("Session refused: Birth record carries no agent_pub_key. Keyless birth refused.")
            
        self.manifest = self.token.birth_record.get("guardrails", {})
        self.allowed_egress = self.token.birth_record.get("allowed_egress", [])
            
        # 3. Action log (feeds the drift chain)
        self.action_log = []
        
        # 4. Reconnaissance Countermeasures
        self._evaporate_environment()
        self._apply_egress_firewall()

    def _evaporate_environment(self):
        """Drops standing credentials from os.environ into a memory-only vault."""
        self.secure_vault = {}
        sensitive_keywords = ["SECRET", "KEY", "TOKEN", "AWS", "PASSWORD", "CREDENTIAL"]
        keys_to_remove = []
        for k, v in os.environ.items():
            if any(kw in k.upper() for kw in sensitive_keywords):
                self.secure_vault[k] = v
                keys_to_remove.append(k)
        for k in keys_to_remove:
            del os.environ[k]

    def _apply_egress_firewall(self):
        """Hooks low-level sockets to mathematically block unauthorized network egress."""
        import socket
        if not hasattr(socket.socket, "_original_connect"):
            socket.socket._original_connect = socket.socket.connect
            
        original_connect = socket.socket._original_connect
        
        def guarded_connect(sock, address):
            if isinstance(address, tuple):
                host = address[0]
                # Allow local testing interfaces implicitly
                if host not in self.allowed_egress and host not in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]:
                    self.action_log.append(("egress_firewall", host, False))
                    raise PermissionError(f"FIREWALL BLOCKED: Egress to {host} is not in allowed_egress manifest.")
                self.action_log.append(("egress_firewall", host, True))
            return original_connect(sock, address)
            
        socket.socket.connect = guarded_connect

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
