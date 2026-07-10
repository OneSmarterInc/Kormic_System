import time
from typing import Dict, Any, List
from kormic.models.identity import Identity
from kormic.models.pedigree import BirthRecord, HistoryLink, Pedigree
from kormic.interfaces.keys import KeyCustody
from kormic.utils.serialize import canonical_json, sha256_hex
from kormic.utils.exceptions import PedigreeIntegrityError

def create_birth_record(
    identity: Identity,
    guardrails: Dict[str, Any],
    epoch_number: int,
    sig_alg: str,
    key_custody: KeyCustody,
    agent_pub_key: str = "",
    created_at: float = None
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
        "agent_pub_key": agent_pub_key
    }

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
        agent_pub_key=agent_pub_key,
        signature=signature
    )

def initialize_pedigree(birth_record: BirthRecord) -> Pedigree:
    """
    Initializes a Pedigree wrapper and anchors the running head to the birth record hash.
    head_0 = SHA256(birth_hash)
    """
    serialized_payload = canonical_json(birth_record.to_payload_dict())
    birth_hash = sha256_hex(serialized_payload)
    head_0 = sha256_hex(birth_hash)
    
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
    
    # Compute previous hash anchorage
    if len(pedigree.history) == 0:
        birth_serialized = canonical_json(pedigree.birth_record.to_payload_dict())
        prev_hash = sha256_hex(birth_serialized)
    else:
        prev_hash = pedigree.history[-1].this_hash

    # Calculate this_hash for structural integrity
    link_payload = {
        "seq": seq,
        "event": event,
        "timestamp": timestamp,
        "prev_hash": prev_hash
    }
    this_hash = sha256_hex(canonical_json(link_payload))
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
    new_head = sha256_hex(head_input)

    # Construct new immutable Pedigree
    updated_history = list(pedigree.history) + [new_link]
    return Pedigree(
        birth_record=pedigree.birth_record,
        history=updated_history,
        running_head=new_head
    )
