import pytest
from fastapi.testclient import TestClient
import os

# Set a dummy key before importing hq_server
os.environ['MESHKOR_API_KEY'] = 'test-key-123'

from hq_backend.hq_server import app

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

    headers = {"Authorization": "Bearer test-key-123"}
    
    with TestClient(app) as client:
        response = client.post("/enroll", json=payload, headers=headers)
        assert response.status_code == 200, response.text
        
        data = response.json()
        assert "ain" in data
        pedigree = data["pedigree"]
        
        # Assert the constitution_hash was securely merged into the manifest (Finding C)
        assert "birth_record" in pedigree
        assert pedigree["birth_record"].get("guardrails") is not None
        assert pedigree["birth_record"]["guardrails"].get("constitution_hash") == "abc123sealedhash" or pedigree["birth_record"]["guardrails"].get("manifest", {}).get("constitution_hash") == "abc123sealedhash"

def test_production_key_guard():
    import importlib
    import hq_backend.hq_server
    
    old_key = os.environ.get('MESHKOR_API_KEY')
    old_mode = os.environ.get('KORMIC_DEPLOYMENT_MODE')
    
    try:
        os.environ['KORMIC_DEPLOYMENT_MODE'] = 'production'
        if 'MESHKOR_API_KEY' in os.environ:
            del os.environ['MESHKOR_API_KEY']
            
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(hq_backend.hq_server)
            
        assert "CRITICAL: MESHKOR_API_KEY is not set" in str(excinfo.value)
    finally:
        if old_key:
            os.environ['MESHKOR_API_KEY'] = old_key
        else:
            if 'MESHKOR_API_KEY' in os.environ:
                del os.environ['MESHKOR_API_KEY']
        
        if old_mode:
            os.environ['KORMIC_DEPLOYMENT_MODE'] = old_mode
        else:
            if 'KORMIC_DEPLOYMENT_MODE' in os.environ:
                del os.environ['KORMIC_DEPLOYMENT_MODE']
                
        # reload to clean state for subsequent tests
        os.environ['MESHKOR_API_KEY'] = 'test-key-123'
        importlib.reload(hq_backend.hq_server)

def test_production_db_guard():
    import importlib
    import hq_backend.hq_db
    
    old_url = os.environ.get('MESHKOR_DATABASE_URL')
    old_mode = os.environ.get('KORMIC_DEPLOYMENT_MODE')
    
    try:
        os.environ['KORMIC_DEPLOYMENT_MODE'] = 'production'
        if 'MESHKOR_DATABASE_URL' in os.environ:
            del os.environ['MESHKOR_DATABASE_URL']
            
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(hq_backend.hq_db)
            
        assert "CRITICAL: MESHKOR_DATABASE_URL is not set" in str(excinfo.value)
    finally:
        if old_url:
            os.environ['MESHKOR_DATABASE_URL'] = old_url
        else:
            if 'MESHKOR_DATABASE_URL' in os.environ:
                del os.environ['MESHKOR_DATABASE_URL']
        
        if old_mode:
            os.environ['KORMIC_DEPLOYMENT_MODE'] = old_mode
        else:
            if 'KORMIC_DEPLOYMENT_MODE' in os.environ:
                del os.environ['KORMIC_DEPLOYMENT_MODE']
                
        importlib.reload(hq_backend.hq_db)

@pytest.mark.asyncio
async def test_event_ordering():
    import hq_backend.hq_db as db
    import time
    
    await db.init_pool()
    await db.init_db()
    
    # insert two events 0.5s apart
    await db.log_event("test_ain_1", "type1", {"data": "1"})
    time.sleep(0.5)
    await db.log_event("test_ain_1", "type2", {"data": "2"})
    
    events = await db.get_events(limit=2)
    assert len(events) >= 2
    assert events[0]['event_type'] == 'type2'
    assert events[1]['event_type'] == 'type1'
    assert events[0]['timestamp'] > events[1]['timestamp']
    
    await db.close_pool()
