"""
Regression tests for the round-4 audit findings.

FINDING A: concurrent record_event on one agent silently dropped events, and the
truncated chain still passed verify_full. These tests assert every concurrent write
lands and the chain still verifies. They are RED on commit 065d3b3 and GREEN after
the per-agent lock + connection-lock fix.

FINDING C: the same-version snapshot fast-path replaced the spent-nonce set, so a
stale snapshot delivered after a spend wiped it and reopened the replay window. The
union test asserts a spend survives a stale snapshot.
"""
import threading
import time
import pytest

from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import CentralRegistryAuthority, RegionalReplicaRegistry
from kormic.verify.engine import Verifier
from kormic.models.pedigree import Pedigree
from meshkor import MeshKorAgent, LocalAuthority


def _system(tmp_path, name):
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(str(tmp_path / f"{name}.db"))
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub, central_sync=central)
    verifier = Verifier(replica)
    authority = LocalAuthority(manager, verifier, central, replica)
    replica.apply_snapshot(central.snapshot())
    return authority, verifier, central, replica


# ---------------------------------------------------------------------------
# FINDING A: no event may be silently lost under concurrency, and the chain
# that results must still verify.
# ---------------------------------------------------------------------------
def test_concurrent_events_none_lost(tmp_path):
    authority, verifier, _, _ = _system(tmp_path, "conc")
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0001", "id", {})

    n_threads, n_each = 8, 40
    expected = n_threads * n_each
    errors = []

    def worker(tid):
        for i in range(n_each):
            try:
                authority.record_event(agent.ain, f"t{tid}-e{i}")
            except Exception as e:  # pragma: no cover - fails the test below
                errors.append(repr(e))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"record_event raised under concurrency: {errors[:3]}"

    ped = Pedigree.from_dict(authority.get_pedigree(agent.ain))
    assert len(ped.history) == expected, (
        f"Lost events: expected {expected}, stored {len(ped.history)}"
    )

    # sequence numbers must be a clean 1..expected with no gaps or duplicates
    seqs = sorted(link.seq for link in ped.history)
    assert seqs == list(range(1, expected + 1))


def test_concurrent_chain_still_verifies_full(tmp_path):
    authority, verifier, _, _ = _system(tmp_path, "conc_verify")
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0002", "id", {})

    n_threads, n_each = 6, 30
    threads = [
        threading.Thread(
            target=lambda tid=t: [
                authority.record_event(agent.ain, f"t{tid}-e{i}") for i in range(n_each)
            ]
        )
        for t in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ped = Pedigree.from_dict(authority.get_pedigree(agent.ain))
    assert len(ped.history) == n_threads * n_each

    # sync the SDK view to the stored head and prove FULL verification accepts it
    agent.current_head = ped.running_head
    agent.history_length = len(ped.history)
    token = agent.mint_token(verifier.generate_challenge())
    result = verifier.verify_full(token, ped.history)
    assert result.status == "PASS"


def test_concurrent_distinct_agents_parallel(tmp_path):
    """Different agents must NOT serialize against each other (per-agent lock, not global)."""
    authority, _, _, _ = _system(tmp_path, "parallel")
    agents = [
        MeshKorAgent.enroll(authority, "CMP", "acme", f"{i:04d}", "id", {})
        for i in range(4)
    ]

    def worker(a):
        for i in range(50):
            authority.record_event(a.ain, f"e{i}")

    threads = [threading.Thread(target=worker, args=(a,)) for a in agents]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for a in agents:
        ped = Pedigree.from_dict(authority.get_pedigree(a.ain))
        assert len(ped.history) == 50


# ---------------------------------------------------------------------------
# FINDING C: a stale same-version snapshot must not erase a locally-spent nonce.
# ---------------------------------------------------------------------------
def test_stale_snapshot_does_not_erase_spent_nonce(tmp_path):
    authority, verifier, central, replica = _system(tmp_path, "union")
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0003", "id", {})

    # Capture a snapshot BEFORE the spend (models a sync already in flight).
    stale = central.snapshot()
    time.sleep(0.01)

    # Spend a nonce via a real verification.
    token = agent.mint_token(verifier.generate_challenge())
    assert verifier.verify_fast(token).status == "PASS"
    assert token.challenge in replica.spent_nonces

    # The pre-spend snapshot lands late. It must NOT wipe the spend.
    replica.apply_snapshot(stale)
    assert token.challenge in replica.spent_nonces, (
        "Stale snapshot erased a spent nonce — replay window reopened."
    )

    # A fresh verifier instance on the same replica must still reject the replay.
    fresh_verifier = Verifier(replica)
    assert fresh_verifier.verify_fast(token).status == "HALT_HARD"
