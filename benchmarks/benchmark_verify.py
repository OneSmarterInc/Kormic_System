import time
from kormic.models.identity import Identity
from kormic.models.pedigree import Pedigree
from kormic.models.verify import ProofToken
from kormic.crypto.software import SoftwareKeyCustody
from kormic.pedigree.builder import create_birth_record, initialize_pedigree, append_history_event
from kormic.verify.engine import Verifier
from kormic.verify.cache import TrustCache
from kormic.utils.serialize import sha256_hex

class LocalRegistryStub:
    def __init__(self, key_custody):
        self._key_custody = key_custody

    def is_epoch_revoked(self, epoch_n: int) -> bool:
        return False

    def is_agent_revoked(self, agent_code: str) -> bool:
        return False

    def get_epoch_certificate(self, epoch_n: int):
        return self._key_custody.epoch_public(epoch_n)

def run_performance_benchmarks():
    print("==================================================")
    print("   KORMIC VERIFICATION PERFORMANCE BENCHMARKS    ")
    print("==================================================")

    # 1. Setup
    key_custody = SoftwareKeyCustody()
    key_custody.generate_epoch_key(1)
    registry = LocalRegistryStub(key_custody)
    cache = TrustCache(ttl_seconds=60)
    verifier = Verifier(registry, cache)

    valid_id = Identity(
        agent_type="STU",
        entity_ref="priya7f3a",
        instance="0001",
        realid_ref=sha256_hex("profile_data")
    )
    birth = create_birth_record(valid_id, {}, 1, "ML-DSA-44", key_custody)
    pedigree = initialize_pedigree(birth)

    # Grow history scales
    print("\n[FAST vs FULL Verification Cost Comparison]")
    print(f"{'History Size':<15} | {'FAST Mode (ms)':<15} | {'FULL Mode (ms)':<15}")
    print("-" * 53)

    for history_size in [10, 100, 1000]:
        # Append events up to target size
        while len(pedigree.history) < history_size:
            pedigree = append_history_event(pedigree, f"Event action log: {len(pedigree.history)}")

        token = ProofToken(
            agent_code=pedigree.birth_record.identity.to_string(),
            birth_record=pedigree.birth_record.to_dict(),
            current_head=pedigree.running_head,
            history_length=len(pedigree.history),
            freshness_timestamp=time.time(),
            authority_reference="kormic.authority.local"
        )

        # Measure FAST
        start = time.perf_counter()
        # Clean cache to measure real signature computation cost
        if verifier._cache:
            verifier._cache.invalidate(token.agent_code, bytes.fromhex(pedigree.birth_record.signature.hex()))
        
        verifier.verify_fast(token)
        fast_ms = (time.perf_counter() - start) * 1000.0

        # Measure FULL
        start = time.perf_counter()
        verifier.verify_full(token, pedigree.history)
        full_ms = (time.perf_counter() - start) * 1000.0

        print(f"{history_size:<15} | {fast_ms:<15.4f} | {full_ms:<15.4f}")

    # 2. Caching Speedup Benchmark
    print("\n[Caching Verification Efficiency Benchmark]")
    token = ProofToken(
        agent_code=pedigree.birth_record.identity.to_string(),
        birth_record=pedigree.birth_record.to_dict(),
        current_head=pedigree.running_head,
        history_length=len(pedigree.history),
        freshness_timestamp=time.time(),
        authority_reference="kormic.authority.local"
    )

    # Uncached speed
    if verifier._cache:
        verifier._cache.invalidate(token.agent_code, bytes.fromhex(pedigree.birth_record.signature.hex()))
    
    start = time.perf_counter()
    verifier.verify_fast(token)
    uncached_duration = time.perf_counter() - start

    # Cached speed
    start = time.perf_counter()
    verifier.verify_fast(token)
    cached_duration = time.perf_counter() - start

    speedup = (uncached_duration / (cached_duration or 1e-9))
    print(f"Uncached signature verification: {uncached_duration * 1000.0:.4f} ms")
    print(f"Cached verification (with bypass):  {cached_duration * 1000.0:.4f} ms")
    print(f"Resulting Speedup Multiplier:     {speedup:.2f}x faster")
    print("==================================================\n")

if __name__ == "__main__":
    run_performance_benchmarks()
