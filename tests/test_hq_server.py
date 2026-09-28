import pytest
from fastapi.testclient import TestClient
import os

# Set a dummy key before importing hq_server
os.environ['MESHKOR_API_KEY'] = 'test-key-123'

from hq_backend.hq_server import app

client = TestClient(app)

def test_enrollment_seals_constitution_hash():
    # Finding C test: enroll with a hash, fetch the pedigree, assert the hash is in the sealed birth
    payload = {
        "agent_type": "STU",
        "entity_ref": "test_student_1",
        "instance": "instance_1",
        "real_world_id": "test_student_1",
        "manifest": {"permissions": ["read"]},
        "constitution_hash": "abc123sealedhash",
        "agent_pub_key": "advisory_mode_no_local_key"
    }

    # Enrollment requires auth now (Finding B fix)
    headers = {"Authorization": "Bearer test-key-123"}
    
    response = client.post("/enroll", json=payload, headers=headers)
    assert response.status_code == 200, response.text
    
    data = response.json()
    assert "ain" in data
    pedigree = data["pedigree"]
    
    # Assert the constitution_hash was securely merged into the manifest (Finding C)
    assert "birth_record" in pedigree
    assert pedigree["birth_record"].get("guardrails") is not None
    assert pedigree["birth_record"]["guardrails"].get("constitution_hash") == "abc123sealedhash" or pedigree["birth_record"]["guardrails"].get("manifest", {}).get("constitution_hash") == "abc123sealedhash"

