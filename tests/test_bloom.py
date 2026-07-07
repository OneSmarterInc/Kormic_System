import unittest
import string
import random
from kormic.utils.bloom import ScalableRevocationFilter

class TestScalableRevocation(unittest.TestCase):
    def test_bloom_filter_no_false_negatives(self):
        """
        Prove that the Bloom Filter never misses a true revocation (no false negatives).
        Also verify that the 2-tier check correctly filters false positives.
        """
        filter = ScalableRevocationFilter(capacity=1000, error_rate=0.01)
        
        # 1. Create a set of revoked agent codes
        revoked_agents = [f"KMC.STU.agent{i:04d}.1234.hash" for i in range(100)]
        for agent in revoked_agents:
            filter.add(agent)
            
        # 2. Verify all revoked agents are correctly identified (NO FALSE NEGATIVES)
        for agent in revoked_agents:
            self.assertTrue(filter.is_revoked(agent), f"False negative on {agent}!")
            
        # 3. Create a set of non-revoked agents and test for false positives
        non_revoked_agents = [f"KMC.STU.good{i:04d}.1234.hash" for i in range(1000)]
        
        # We simulate checking just the raw bloom filter to count false positives
        raw_bloom_false_positives = 0
        for agent in non_revoked_agents:
            if agent in filter._bloom:
                raw_bloom_false_positives += 1
                
        # The raw bloom filter should have roughly 1% false positives (around 10 out of 1000)
        # But our two-tier is_revoked() MUST filter them all out
        for agent in non_revoked_agents:
            self.assertFalse(filter.is_revoked(agent), f"False positive bypassed two-tier check on {agent}!")
            
        print(f"\n[Bloom Test] Raw Bloom False Positives: {raw_bloom_false_positives}/1000 (Expected ~1%)")
        print("[Bloom Test] Two-Tier Check False Positives: 0/1000 (Perfect)")
        print("[Bloom Test] False Negatives (Missed Revocations): 0/100 (Perfect)")

if __name__ == '__main__':
    unittest.main()
