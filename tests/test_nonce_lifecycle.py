"""
Nonce lifecycle tests — round-5 findings.

These cover two defects in the round-4 union fix:

  FINDING A: the replica held spent nonces in a plain set with no expiry, so merging
  from snapshots could only ever grow it. Central purged; the replica never did.

  FINDING B: only the same-version apply_snapshot path was changed to merge. The
  version-bump path still replaced the set wholesale, so a revocation snapshot cut
  before a local spend erased that spend and reopened the replay window. The round-4
  test only walked the same-version path, which is why it stayed green.

Both paths that touch spent_nonces are exercised here. The rule these encode: a spend
must survive any snapshot, and the set must still be able to shrink with age.
"""
import time
import pytest

from kormic.crypto.software import SoftwareKeyCustody
from kormic.manager import AgentManager
from kormic.storage.sqlite import SQLiteRecordStore
from kormic.registry.distributed import (
    CentralRegistryAuthority,
    RegionalReplicaRegistry,
    NONCE_TTL_SECONDS,
)
from kormic.verify.engine import Verifier
from meshkor import MeshKorAgent, LocalAuthority


@pytest.fixture
def system(tmp_path):
    keys = SoftwareKeyCustody()
    keys.generate_epoch_key(1)
    store = SQLiteRecordStore(str(tmp_path / "nonce_lifecycle.db"))
    manager = AgentManager(keys, store, default_epoch=1)
    central = CentralRegistryAuthority(keys)
    replica = RegionalReplicaRegistry("us-east", keys._root_pub, central_sync=central)
    verifier = Verifier(replica)
    authority = LocalAuthority(manager, verifier, central, replica)
    replica.apply_snapshot(central.snapshot())
    return authority, verifier, central, replica


# ---------------------------------------------------------------------------
# FINDING A: the replica set must be able to shrink.
# ---------------------------------------------------------------------------
def test_replica_nonce_set_purges_with_age(system):
    authority, verifier, central, replica = system
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0001", "id", {})

    for _ in range(25):
        verifier.verify_fast(agent.mint_token(verifier.generate_challenge()))
    replica.apply_snapshot(central.snapshot())
    assert len(replica.spent_nonces) == 25

    # Age every entry past the TTL and force a purge via a fresh spend.
    stale = time.time() - (NONCE_TTL_SECONDS + 10)
    replica.spent_nonces = {n: stale for n in replica.spent_nonces}
    replica.spend_nonce("a-fresh-nonce")

    assert len(replica.spent_nonces) == 1, (
        f"Replica nonce set did not purge: {len(replica.spent_nonces)} entries retained"
    )
    assert "a-fresh-nonce" in replica.spent_nonces


def test_replica_does_not_resurrect_purged_nonces_from_snapshot(system):
    """A merge must not re-add nonces that are already older than the TTL."""
    authority, verifier, central, replica = system
    stale_at = time.time() - (NONCE_TTL_SECONDS + 10)

    snap = central.snapshot()
    replica._merge_spent_nonces(["ancient-nonce"], stale_at)
    assert "ancient-nonce" not in replica.spent_nonces


# ---------------------------------------------------------------------------
# FINDING B: a spend must survive BOTH snapshot paths.
# ---------------------------------------------------------------------------
def test_spend_survives_stale_same_version_snapshot(system):
    authority, verifier, central, replica = system
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0002", "id", {})

    stale = central.snapshot()          # cut BEFORE the spend
    time.sleep(0.01)

    token = agent.mint_token(verifier.generate_challenge())
    assert verifier.verify_fast(token).status == "PASS"
    assert token.challenge in replica.spent_nonces

    replica.apply_snapshot(stale)       # same-version path
    assert token.challenge in replica.spent_nonces

    assert Verifier(replica).verify_fast(token).status == "HALT_HARD"


def test_spend_survives_stale_version_bumped_snapshot(system):
    """
    The path round 4 missed. A revocation bumps the version, so this snapshot takes the
    full-apply branch — which used to replace spent_nonces wholesale.
    """
    authority, verifier, central, replica = system
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0003", "id", {})
    other = MeshKorAgent.enroll(authority, "CMP", "acme", "0004", "id", {})

    central.revoke_agent(other.ain)     # bumps version
    stale_bumped = central.snapshot()   # cut BEFORE the spend
    time.sleep(0.01)

    token = agent.mint_token(verifier.generate_challenge())
    assert verifier.verify_fast(token).status == "PASS"
    assert token.challenge in replica.spent_nonces

    replica.apply_snapshot(stale_bumped)   # version-bump path
    assert token.challenge in replica.spent_nonces, (
        "Version-bumped snapshot erased a spent nonce — replay window reopened."
    )

    result = Verifier(replica).verify_fast(token)
    assert result.status == "HALT_HARD"
    assert "replay" in result.reason.lower()


def test_version_bumped_snapshot_still_applies_revocations(system):
    """Merging nonces must not have broken the actual purpose of the full-apply path."""
    authority, verifier, central, replica = system
    agent = MeshKorAgent.enroll(authority, "CMP", "acme", "0005", "id", {})

    token = agent.mint_token(verifier.generate_challenge())
    assert verifier.verify_fast(token).status == "PASS"

    central.revoke_agent(agent.ain)
    replica.apply_snapshot(central.snapshot())

    result = verifier.verify_fast(agent.mint_token(verifier.generate_challenge()))
    assert result.status == "REVOKED"
