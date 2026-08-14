import time
from typing import Dict, Any, List, Optional
from kormic.models.identity import Identity
from kormic.models.pedigree import BirthRecord, HistoryLink, Pedigree
from kormic.interfaces.keys import KeyCustody
from kormic.utils.serialize import canonical_json, hash_hex, sha256_hex
from kormic.utils.exceptions import PedigreeIntegrityError

def create_birth_record(
    identity: Identity,
    guardrails: Dict[str, Any],
    epoch_number: int,
    sig_alg: str,
    key_custody: KeyCustody,
    hash_alg: str = "SHA-256",
    agent_pub_key: str = "",
    created_at: float = None,
    derived_from: Optional[str] = None,
    vendor_pub_key: Optional[str] = None,
    artifact_digest: Optional[str] = None,
    approval_assertion: Optional[Dict[str, Any]] = None,
    read_scopes: Optional[List[str]] = None,
    allowed_egress: Optional[List[str]] = None
) -> BirthRecord:
    """
    Creates and signs a sealed BirthRecord for the agent.
    Satisfies Section 5.1 & 5.2.
    """
    if created_at is None:
        created_at = time.time()

    # Birth payload mapping (excludes signature)
    birth_payload = {
        "identity": identity.to_string(),
        "created_at": created_at,
        "guardrails": guardrails,
        "epoch_number": epoch_number,
        "sig_alg": sig_alg,
        "hash_alg": hash_alg,
        "fmt_ver": 1,
        "agent_pub_key": agent_pub_key,
        "derived_from": derived_from,
        "vendor_pub_key": vendor_pub_key,
        "artifact_digest": artifact_digest
    }
    
    if approval_assertion is not None:
        birth_payload["approval_assertion"] = approval_assertion
    
    if read_scopes is not None:
        birth_payload["read_scopes"] = read_scopes
    if allowed_egress is not None:
        birth_payload["allowed_egress"] = allowed_egress

    # Canonical serialization
    serialized_payload = canonical_json(birth_payload)
    
    # Compute signature via key custody interface
    signature = key_custody.sign_birth(epoch_number, serialized_payload.encode('utf-8'))

    return BirthRecord(
        identity=identity,
        created_at=created_at,
        guardrails=guardrails,
        epoch_number=epoch_number,
        sig_alg=sig_alg,
        hash_alg=hash_alg,
        fmt_ver=1,
        agent_pub_key=agent_pub_key,
        signature=signature,
        derived_from=derived_from,
        vendor_pub_key=vendor_pub_key,
        artifact_digest=artifact_digest,
        approval_assertion=approval_assertion,
        read_scopes=read_scopes,
        allowed_egress=allowed_egress
    )

def initialize_pedigree(birth_record: BirthRecord) -> Pedigree:
    """
    Initializes a Pedigree wrapper and anchors the running head to the birth record hash.
    head_0 = SHA256(birth_hash)
    """
    hash_alg = birth_record.hash_alg
    serialized_payload = canonical_json(birth_record.to_payload_dict())
    birth_hash = hash_hex(hash_alg, serialized_payload)
    head_0 = hash_hex(hash_alg, birth_hash)
    
    return Pedigree(
        birth_record=birth_record,
        history=[],
        running_head=head_0
    )

def append_history_event(
    pedigree: Pedigree,
    event: str,
    timestamp: float = None
) -> Pedigree:
    """
    Appends a new Event to the history chain and recalculates the running head.
    Satisfies Section 2.3 & 3.
    """
    if timestamp is None:
        timestamp = time.time()

    seq = len(pedigree.history) + 1
    
    hash_alg = pedigree.birth_record.hash_alg
    
    # Compute previous hash anchorage
    if len(pedigree.history) == 0:
        birth_serialized = canonical_json(pedigree.birth_record.to_payload_dict())
        prev_hash = hash_hex(hash_alg, birth_serialized)
    else:
        prev_hash = pedigree.history[-1].this_hash

    # Calculate this_hash for structural integrity
    link_payload = {
        "seq": seq,
        "event": event,
        "timestamp": timestamp,
        "prev_hash": prev_hash
    }
    this_hash = hash_hex(hash_alg, canonical_json(link_payload))
    new_link = HistoryLink(
        seq=seq,
        event=event,
        timestamp=timestamp,
        prev_hash=prev_hash,
        this_hash=this_hash
    )

    # Recalculate running head O(1)
    # head_n = SHA256(head_{n-1} || canonical_json({seq, event, timestamp}))
    event_payload = {
        "seq": seq,
        "event": event,
        "timestamp": timestamp
    }
    head_input = pedigree.running_head + canonical_json(event_payload)
    new_head = hash_hex(hash_alg, head_input)

    # Construct new immutable Pedigree
    updated_history = list(pedigree.history) + [new_link]
    return Pedigree(
        birth_record=pedigree.birth_record,
        history=updated_history,
        running_head=new_head
    )
