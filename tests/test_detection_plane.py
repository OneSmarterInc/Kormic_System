import pytest
import time
import threading
from kormic.runtime.detection import DevDetectionSink
from kormic.runtime.sandbox import Sandbox
from kormic.models.verify import ProofToken
from kormic.verify.engine import VerificationResult
from unittest.mock import Mock

@pytest.fixture
def mock_verifier():
    v = Mock()
    v.verify_fast.return_value = VerificationResult(status="PASS", agent_code="AGENT1", reason="OK")
    return v

@pytest.fixture
def mock_token():
    return ProofToken(
        agent_code="AGENT1",
        birth_record={
            "agent_pub_key": "pub",
            "guardrails": {
                "allowed_tools": ["toolA"],
                "allowed_endpoints": ["endpointA"]
            },
            "allowed_egress": ["10.0.0.1"]
        },
        current_head="abc",
        history_length=1,
        freshness_timestamp=0.0,
        authority_reference="auth"
    )

def test_in_scope_emits_nothing(mock_verifier, mock_token):
    sink = DevDetectionSink()
    sandbox = Sandbox(mock_verifier, mock_token, detection_sink=sink)
    sandbox.use_tool("toolA")
    sandbox.call_endpoint("endpointA")
    sandbox.check_egress("10.0.0.1")
    assert len(sink.events) == 0

def test_out_of_scope_emits_in_enforced_mode(mock_verifier, mock_token):
    sink = DevDetectionSink()
    sandbox = Sandbox(mock_verifier, mock_token, detection_sink=sink, enforcement_mode="enforced")
    
    with pytest.raises(PermissionError):
        sandbox.use_tool("toolB")
    
    assert len(sink.events) == 1
    ev = sink.events[0]
    assert ev.event_kind == "out_of_scope_tool"
    assert ev.action_target == "toolB"
    assert ev.mode == "enforced"

def test_out_of_scope_emits_in_advisory_mode(mock_verifier, mock_token):
    sink = DevDetectionSink()
    sandbox = Sandbox(mock_verifier, mock_token, detection_sink=sink, enforcement_mode="advisory")
    
    # Should not raise exception
    res = sandbox.use_tool("toolB")
    assert "Tool toolB executed" in res
    
    assert len(sink.events) == 1
    ev = sink.events[0]
    assert ev.event_kind == "out_of_scope_tool"
    assert ev.mode == "advisory"

def test_reconnaissance_breadth_emits_once(mock_verifier, mock_token):
    sink = DevDetectionSink()
    sandbox = Sandbox(mock_verifier, mock_token, detection_sink=sink, enforcement_mode="advisory", recon_threshold=3)
    
    sandbox.check_egress("10.0.0.2") # 1
    sandbox.check_egress("10.0.0.3") # 2
    
    # Not yet 3 targets, so no recon event. (Just the 2 out_of_scope_egress events)
    assert len(sink.events) == 2
    
    sandbox.check_egress("10.0.0.4") # 3 -> crosses threshold
    
    assert len(sink.events) == 4
    recon_ev = sink.events[-1]
    assert recon_ev.event_kind == "reconnaissance_breadth"
    
    # More hits should not emit recon event again
    sandbox.check_egress("10.0.0.5")
    assert len([e for e in sink.events if e.event_kind == "reconnaissance_breadth"]) == 1

def test_concurrent_sessions_isolated_counters(mock_verifier):
    token1 = ProofToken(agent_code="A1", birth_record={"agent_pub_key": "k1"}, current_head="abc", history_length=1, freshness_timestamp=0.0, authority_reference="auth")
    token2 = ProofToken(agent_code="A2", birth_record={"agent_pub_key": "k2"}, current_head="abc", history_length=1, freshness_timestamp=0.0, authority_reference="auth")
    
    sink1 = DevDetectionSink()
    sink2 = DevDetectionSink()
    
    s1 = Sandbox(mock_verifier, token1, detection_sink=sink1, enforcement_mode="advisory", recon_threshold=3)
    s2 = Sandbox(mock_verifier, token2, detection_sink=sink2, enforcement_mode="advisory", recon_threshold=3)
    
    def worker1():
        s1.check_egress("10.0.1.1")
        s1.check_egress("10.0.1.2")
        
    def worker2():
        s2.check_egress("10.0.2.1")
        s2.check_egress("10.0.2.2")
        
    t1 = threading.Thread(target=worker1)
    t2 = threading.Thread(target=worker2)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    
    # Both hit 2 targets, neither crossed threshold of 3
    assert not any(e.event_kind == "reconnaissance_breadth" for e in sink1.events)
    assert not any(e.event_kind == "reconnaissance_breadth" for e in sink2.events)

def test_receiver_out_of_scope_read(mock_verifier, mock_token):
    from meshkor.receiver import ReceiverClient
    from meshkor.authority import Authority
    
    auth = Mock(spec=Authority)
    auth.get_verifier.return_value = mock_verifier
    
    sink = DevDetectionSink()
    client = ReceiverClient(auth, detection_sink=sink, enforcement_mode="advisory")
    
    # mock_token has no read_scopes
    verdict = client.validate(mock_token, action_type="read", resource="db1")
    
    assert verdict.ok is True # advisory mode allows it? Wait, let's check ReceiverClient.
    assert len(sink.events) == 1
    assert sink.events[0].event_kind == "out_of_scope_read"

def test_receiver_out_of_scope_read_enforced(mock_verifier, mock_token):
    from meshkor.receiver import ReceiverClient
    from meshkor.authority import Authority
    
    auth = Mock(spec=Authority)
    auth.get_verifier.return_value = mock_verifier
    
    sink = DevDetectionSink()
    client = ReceiverClient(auth, detection_sink=sink, enforcement_mode="enforced")
    
    verdict = client.validate(mock_token, action_type="read", resource="db1")
    
    assert verdict.ok is False
    assert len(sink.events) == 1
    assert sink.events[0].event_kind == "out_of_scope_read"
