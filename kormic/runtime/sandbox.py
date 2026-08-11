import os
import time
from typing import Dict, Any, List
import hashlib
from kormic.crypto.algorithms import MLDSASigner
from kormic.models.verify import ProofToken
from kormic.verify.engine import Verifier
from kormic.interfaces.registry import RegistryReader
from kormic.runtime.detection import DetectionSink, DetectionEvent

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

class Sandbox:
    """
    Kormic Runtime Sandbox Wrapper.
    Enforces C1 (Manifest Isolation).
    Any action outside the manifest is blocked and logged.
    """
    def __init__(self, verifier: Verifier, token: ProofToken, env: Dict[str, str] = None, 
                 detection_sink: DetectionSink = None, enforcement_mode: str = "enforced",
                 recon_window: float = 60.0, recon_threshold: int = 5):
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
        
        # 4. Reconnaissance Countermeasures (Session-Scoped)
        self.secure_vault = {}
        self.session_env = dict(env) if env is not None else dict(os.environ)
        self._evaporate_environment()
        
        # Detection Plane
        self.detection_sink = detection_sink
        self.enforcement_mode = enforcement_mode
        self.recon_window = recon_window
        self.recon_threshold = recon_threshold
        self.out_of_scope_targets = {}
        self._recon_emitted = False

    def _evaporate_environment(self):
        sensitive_keywords = ["SECRET", "KEY", "TOKEN", "AWS", "PASSWORD", "CREDENTIAL"]
        keys_to_remove = []
        for k, v in self.session_env.items():
            if any(kw in k.upper() for kw in sensitive_keywords):
                self.secure_vault[k] = v
                keys_to_remove.append(k)
        for k in keys_to_remove:
            del self.session_env[k]

    def _emit_detection(self, kind: str, target: str, reason: str):
        if self.detection_sink:
            ev = DetectionEvent(
                event_kind=kind,
                identity=self.token.agent_code,
                action_target=target,
                reason=reason,
                mode=self.enforcement_mode,
                timestamp=time.time()
            )
            self.detection_sink.emit(ev)

    def _track_recon(self, target: str):
        now = time.time()
        self.out_of_scope_targets = {k: v for k, v in self.out_of_scope_targets.items() if now - v <= self.recon_window}
        if target not in self.out_of_scope_targets:
            self.out_of_scope_targets[target] = now
            
        if len(self.out_of_scope_targets) >= self.recon_threshold and not self._recon_emitted:
            self._emit_detection("reconnaissance_breadth", f"{self.recon_threshold}_targets", "Reconnaissance breadth threshold crossed")
            self._recon_emitted = True

    def check_egress(self, host: str) -> bool:
        if host not in self.allowed_egress and host not in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]:
            self.action_log.append(("egress_firewall", host, False))
            self._emit_detection("out_of_scope_egress", host, f"Egress to {host} is not in allowed_egress manifest.")
            self._track_recon(host)
            if self.enforcement_mode == "enforced":
                raise PermissionError(f"FIREWALL BLOCKED: Egress to {host} is not in allowed_egress manifest.")
            # Advisory mode: proceeds
            return True
        self.action_log.append(("egress_firewall", host, True))
        return True

    def use_tool(self, tool: str) -> str:
        allowed_tools = self.manifest.get("allowed_tools", [])
        ok = tool in allowed_tools
        self.action_log.append(("tool", tool, ok))
        
        if not ok:
            self._emit_detection("out_of_scope_tool", tool, f"Tool '{tool}' not in this agent's sealed manifest.")
            self._track_recon(tool)
            if self.enforcement_mode == "enforced":
                raise PermissionError(f"BLOCKED: Tool '{tool}' not in this agent's sealed manifest.")
        return f"Tool {tool} executed"

    def call_endpoint(self, endpoint: str) -> str:
        allowed_endpoints = self.manifest.get("allowed_endpoints", [])
        ok = endpoint in allowed_endpoints
        self.action_log.append(("endpoint", endpoint, ok))
        
        if not ok:
            self._emit_detection("out_of_scope_endpoint", endpoint, f"Endpoint '{endpoint}' not in sealed manifest.")
            self._track_recon(endpoint)
            if self.enforcement_mode == "enforced":
                raise PermissionError(f"BLOCKED: Endpoint '{endpoint}' not in sealed manifest. Cross-agent/shared-runtime reach denied.")
        return f"Endpoint {endpoint} reached"
        
    def drift_detected(self) -> bool:
        return any(ok is False for _, _, ok in self.action_log)
