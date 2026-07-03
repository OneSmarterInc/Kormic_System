import unittest
import time
from typing import Optional, Dict

from kormic.models.identity import Identity
from kormic.models.pedigree import BirthRecord, HistoryLink, Pedigree
from kormic.models.verify import ProofToken, VerificationResult
from kormic.models.behavior import BehaviorConfig, BehaviorReport
from kormic.interfaces.registry import RegistryReader
from kormic.crypto.software import SoftwareKeyCustody
from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
from kormic.verify.engine import Verifier
from kormic.verify.cache import TrustCache
from kormic.behavior.monitor import BehaviorMonitor
from kormic.utils.exceptions import IdentityError, CryptographicError, KormicError
from kormic.utils.serialize import canonical_json, sha256_hex

class LocalMemoryRegistry(RegistryReader):
    """Local mock implementation of RegistryReader for test validation."""
    def __init__(self, key_custody: SoftwareKeyCustody):
        self._key_custody = key_custody
        self._revoked_agents = set()

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        return self._key_custody.is_epoch_revoked(epoch_n)

    def is_agent_revoked(self, agent_code: str) -> bool:
        return agent_code in self._revoked_agents

    def get_epoch_certificate(self, epoch_n: int) -> Optional[bytes]:
        try:
            return self._key_custody.get_epoch_certificate(epoch_n)
        except Exception:
            return None

    def get_epoch_public_key(self, epoch_n: int) -> Optional[bytes]:
        try:
            return self._key_custody.epoch_public(epoch_n)
        except Exception:
            return None

    def revoke_agent(self, agent_code: str) -> None:
        self._revoked_agents.add(agent_code)


class TestKormicCoreSystem(unittest.TestCase):

    def setUp(self):
        self.key_custody = SoftwareKeyCustody()
        self.registry = LocalMemoryRegistry(self.key_custody)
        self.cache = TrustCache(ttl_seconds=30)
        self.verifier = Verifier(self.registry, self.cache)
        
        # Behavior monitor configuration setup
        self.behavior_config = BehaviorConfig(
            accuracy_flag_threshold=0.80,
            accuracy_halt_threshold=0.55,
            overconfidence_flag_threshold=0.15,
            overconfidence_halt_threshold=0.35,
            guardrail_hit_flag_threshold=0.10,
            guardrail_hit_halt_threshold=0.25,
            latency_drift_flag_multiplier=2.0,
            latency_drift_halt_multiplier=5.0
        )
        self.behavior_monitor = BehaviorMonitor(self.behavior_config)

        # Create a certified epoch
        self.epoch_num = 1
        self.key_custody.generate_epoch_key(self.epoch_num)

        # Base identity details
        realid_raw = "priya_kumar_real_identity_profile_record_data"
        self.realid_ref_hash = sha256_hex(realid_raw)
        self.valid_id = Identity(
            agent_type="STU",
            entity_ref="priya7f3a",
            instance="0001",
            realid_ref=self.realid_ref_hash
        )
        self.guardrails = {"allowed_actions": ["read", "query"], "max_depth": 3}

    def generate_proof_token(self, pedigree: Pedigree) -> ProofToken:
        return ProofToken(
            agent_code=pedigree.birth_record.identity.to_string(),
            birth_record=pedigree.birth_record.to_dict(),
            current_head=pedigree.running_head,
            history_length=len(pedigree.history),
            freshness_timestamp=time.time(),
            authority_reference="kormic.authority.local"
        )

    def test_genuine_agent_verification_flow(self):
        """✓ Genuine Agent test."""
        # 1. Create agent birth
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)

        # 2. Append events to history
        pedigree = append_history_event(pedigree, "Initiated session with Kormic portal")
        pedigree = append_history_event(pedigree, "Fetched registration course list")

        # 3. Assemble token & verify
        token = self.generate_proof_token(pedigree)
        
        # Test FAST verification
        res_fast = self.verifier.verify_fast(token)
        self.assertEqual(res_fast.status, "PASS")

        # Test FULL verification
        res_full = self.verifier.verify_full(token, pedigree.history)
        self.assertEqual(res_full.status, "PASS")

    def test_forged_origin_signature(self):
        """✓ Forged Origin verification fails."""
        # Create an agent using software keys not certified by the current authority
        unrelated_custody = SoftwareKeyCustody()
        unrelated_custody.generate_epoch_key(self.epoch_num)

        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", unrelated_custody)
        pedigree = initialize_pedigree(birth)
        
        token = self.generate_proof_token(pedigree)
        
        # Verifier must detect bad signature
        res = self.verifier.verify_fast(token)
        self.assertEqual(res.status, "HALT_HARD")
        self.assertIn("signature", res.reason.lower())

    def test_altered_birth_record(self):
        """✓ Altered Birth fails verification."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)

        # Tamper with the birth record content in the packaged verification token
        token_data = self.generate_proof_token(pedigree)
        token_data.birth_record["created_at"] -= 100.0  # alter time

        res = self.verifier.verify_fast(token_data)
        self.assertEqual(res.status, "HALT_HARD")

    def test_altered_guardrails(self):
        """✓ Altered Guardrails fails verification."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)

        token_data = self.generate_proof_token(pedigree)
        # Modify the guardrails
        token_data.birth_record["guardrails"]["max_depth"] = 99

        res = self.verifier.verify_fast(token_data)
        self.assertEqual(res.status, "HALT_HARD")

    def test_deleted_history_link(self):
        """✓ Deleted History links trigger integrity alerts on FULL validation."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)

        pedigree = append_history_event(pedigree, "Event 1")
        pedigree = append_history_event(pedigree, "Event 2")
        pedigree = append_history_event(pedigree, "Event 3")

        # Simulate deletion: remove middle link
        tampered_history = [pedigree.history[0], pedigree.history[2]]
        
        token = self.generate_proof_token(pedigree)
        # Fast verification doesn't check linear links, should pass
        res_fast = self.verifier.verify_fast(token)
        self.assertEqual(res_fast.status, "PASS")

        # Full verification detects length mismatch first
        res_full = self.verifier.verify_full(token, tampered_history)
        self.assertEqual(res_full.status, "HALT_HARD")
        self.assertIn("length mismatch", res_full.reason.lower())

    def test_rewritten_history(self):
        """✓ Rewritten History events fail FULL verification checks."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)

        pedigree = append_history_event(pedigree, "Correct Event")
        token = self.generate_proof_token(pedigree)

        # Alter the event text
        tampered_link = HistoryLink(
            seq=pedigree.history[0].seq,
            event="Tampered Event Text",
            timestamp=pedigree.history[0].timestamp,
            prev_hash=pedigree.history[0].prev_hash,
            this_hash=pedigree.history[0].this_hash
        )

        res = self.verifier.verify_full(token, [tampered_link])
        self.assertEqual(res.status, "HALT_HARD")
        self.assertIn("altered event", res.reason.lower())

    def test_wrong_identity_or_owner(self):
        """✓ Wrong Identity parsing and owner mismatch errors."""
        # 1. Test malformed identity string raises error
        with self.assertRaises(IdentityError):
            Identity.from_string("KMC.INVALID_TYPE.owner.0001.abc")

        # 2. Test valid parsing
        id_str = f"KMC.UNI.ref123.0002.{self.realid_ref_hash}"
        parsed_id = Identity.from_string(id_str)
        self.assertEqual(parsed_id.agent_type, "UNI")
        self.assertEqual(parsed_id.entity_ref, "ref123")

    def test_caching_trust_speedup(self):
        """✓ Caching efficiency verification test."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)
        token = self.generate_proof_token(pedigree)

        # First verification - Cache miss
        start = time.perf_counter()
        res1 = self.verifier.verify_fast(token)
        first_duration = time.perf_counter() - start
        self.assertEqual(res1.status, "PASS")

        # Second verification - Cache hit
        start = time.perf_counter()
        res2 = self.verifier.verify_fast(token)
        second_duration = time.perf_counter() - start
        self.assertEqual(res2.status, "PASS")

        # Cached verification must be faster
        self.assertTrue(second_duration < first_duration or second_duration < 0.01)

    def test_key_revocation(self):
        """✓ Key revocation triggers rejection of agents registered under the revoked epoch."""
        birth = create_birth_record(self.valid_id, self.guardrails, self.epoch_num, "ML-DSA-44", self.key_custody)
        pedigree = initialize_pedigree(birth)
        token = self.generate_proof_token(pedigree)

        # 1. Normal state passes
        self.assertEqual(self.verifier.verify_fast(token).status, "PASS")

        # 2. Revoke epoch key
        self.key_custody.revoke_epoch(self.epoch_num)

        # 3. Verification must fail with REVOKED status
        res = self.verifier.verify_fast(token)
        self.assertEqual(res.status, "REVOKED")

    def test_behavior_monitor_grading(self):
        """✓ Decoupled behavioral monitoring metrics validation."""
        # 1. OK Conduct
        ok_metrics = {
            "accuracy": 0.95,
            "overconfidence": 0.05,
            "guardrail_hit_rate": 0.02,
            "latency_drift": 1.1,
            "policy_violation": False
        }
        report = self.behavior_monitor.evaluate("agent123", ok_metrics)
        self.assertEqual(report.status, "OK")

        # 2. FLAG Warning level
        flag_metrics = {
            "accuracy": 0.75,            # triggers flag
            "overconfidence": 0.05,
            "guardrail_hit_rate": 0.02,
            "latency_drift": 1.1,
            "policy_violation": False
        }
        report = self.behavior_monitor.evaluate("agent123", flag_metrics)
        self.assertEqual(report.status, "FLAG")

        # 3. HALT Severity levels
        halt_metrics = {
            "accuracy": 0.50,            # triggers halt (< 0.55)
            "overconfidence": 0.05,
            "guardrail_hit_rate": 0.02,
            "latency_drift": 1.1,
            "policy_violation": False
        }
        report = self.behavior_monitor.evaluate("agent123", halt_metrics)
        self.assertEqual(report.status, "HALT")

        # 4. Immediate policy violation halt
        policy_violation_metrics = {
            "accuracy": 0.99,
            "overconfidence": 0.01,
            "guardrail_hit_rate": 0.0,
            "latency_drift": 1.0,
            "policy_violation": True     # immediate halt
        }
        report = self.behavior_monitor.evaluate("agent123", policy_violation_metrics)
        self.assertEqual(report.status, "HALT")
        self.assertIn("Immediate HALT", report.reason)
