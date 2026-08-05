import time
import os
import hashlib
from typing import Optional
from .authority import Authority
from kormic.crypto.algorithms import MLDSASigner
from kormic.models.verify import ProofToken

class MeshKorAgent:
    """
    The Core Wrapper for AI Builders. Handles keys and history locally.
    """
    def __init__(self, authority: Authority, ain: str, birth_record: dict, 
                 private_key: bytes, current_head: str):
        self.authority = authority
        self.ain = ain
        self.birth_record = birth_record
        self.private_key = private_key
        self.current_head = current_head
        self.history_length = 0
        self.sig_alg = birth_record.get("sig_alg", "ML-DSA-87")
        
    @classmethod
    def enroll(cls, authority: Authority, agent_type: str, entity_ref: str, 
               instance: str, real_world_id: str, manifest: dict):
        """
        Enrolls a new agent. Generates Post-Quantum keys locally, 
        registers the public key, and returns the agent instance.
        """
        sig_alg = manifest.get("sig_alg", "ML-DSA-87")
        priv_key, pub_key = MLDSASigner.generate_keypair(sig_alg)
        
        ain = authority.enroll_pubkey(
            agent_type, entity_ref, instance, real_world_id, manifest, pub_key.hex()
        )
        
        # For v1 Local Authority, pull the birth record via the interface seam
        ped_dict = authority.get_pedigree(ain)
        
        return cls(
            authority=authority,
            ain=ain,
            birth_record=ped_dict['birth_record'],
            private_key=priv_key,
            current_head=ped_dict['running_head']
        )
        
    def record_event(self, event_description: str):
        """Advances the Tamper-Evident History chain on the Authority."""
        self.current_head = self.authority.record_event(self.ain, event_description)
        self.history_length += 1
        
    def mint_token(self, challenge: Optional[str] = None) -> ProofToken:
        """
        Mints a verifiable ProofToken. 
        If challenge is None, uses Async mode (self-generated nonce).
        If challenge is provided, uses Interactive mode (receiver-generated nonce).
        """
        nonce = challenge if challenge else os.urandom(16).hex()
        
        # Build the token without the signature first to get the payload
        token = ProofToken(
            agent_code=self.ain,
            birth_record=self.birth_record,
            current_head=self.current_head,
            history_length=self.history_length,
            freshness_timestamp=time.time(),
            authority_reference="v1-local",
            challenge=nonce,
            sig_alg=self.sig_alg,
            fmt_ver=1
        )
        
        # Sign the structured payload using the local private key
        signature = MLDSASigner.sign(self.sig_alg, self.private_key, token.challenge_payload()).hex()
        
        # We must return a new ProofToken with the signature, as dataclasses are frozen
        return ProofToken(
            agent_code=self.ain,
            birth_record=self.birth_record,
            current_head=self.current_head,
            history_length=self.history_length,
            freshness_timestamp=token.freshness_timestamp,
            authority_reference="v1-local",
            challenge=nonce,
            signature=signature,
            sig_alg=self.sig_alg,
            fmt_ver=1
        )

# ==========================================
# 3 Attachment Styles (Plain, Mixin, Decorator)
# ==========================================

class MeshKorAgentMixin:
    """Allows integrating MeshKor into a class via Inheritance."""
    def setup_meshkor(self, authority: Authority, agent_type: str, entity_ref: str, 
                      instance: str, real_world_id: str, manifest: dict):
        self._meshkor_agent = MeshKorAgent.enroll(
            authority, agent_type, entity_ref, instance, real_world_id, manifest
        )
        
    def record_event(self, event_description: str):
        if hasattr(self, '_meshkor_agent'):
            self._meshkor_agent.record_event(event_description)
            
    def mint_token(self, challenge: Optional[str] = None) -> ProofToken:
        if not hasattr(self, '_meshkor_agent'):
            raise RuntimeError("Must call setup_meshkor() first.")
        return self._meshkor_agent.mint_token(challenge)

def meshkor_verified(authority: Authority, agent_type: str, entity_ref: str, 
                     instance: str, real_world_id: str, manifest: dict):
    """Allows integrating MeshKor into a class via Decorator."""
    def decorator(cls):
        original_init = cls.__init__
        
        def new_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            self._meshkor_agent = MeshKorAgent.enroll(
                authority, agent_type, entity_ref, instance, real_world_id, manifest
            )
            
        def record_event(self, event_description: str):
            self._meshkor_agent.record_event(event_description)
            
        def mint_token(self, challenge: Optional[str] = None) -> ProofToken:
            return self._meshkor_agent.mint_token(challenge)
            
        cls.__init__ = new_init
        cls.record_event = record_event
        cls.mint_token = mint_token
        return cls
    return decorator
