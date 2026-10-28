"""HQ authorization regressions; no real credentials or external services."""
import hashlib
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from hq_backend import hq_server as hq


@pytest.fixture
def admin_client(monkeypatch):
    private = ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    monkeypatch.setattr(hq, "ADMIN_PUBKEY_SHA256", hashlib.sha256(der).hexdigest())
    monkeypatch.setattr(hq, "admin_challenges", {})
    monkeypatch.setattr(hq, "active_admin_sessions", {})
    # No lifespan is needed for these authentication-only endpoint tests.
    return TestClient(hq.app), private


def signed_request(private, challenge):
    return {
        "challenge": challenge,
        "signature_hex": private.sign(challenge.encode(), ec.ECDSA(hashes.SHA256())).hex(),
        "pub_key_pem": private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    }


def test_unpinned_key_is_401_and_pinned_key_gets_session(admin_client):
    client, private = admin_client
    challenge = client.get('/admin/challenge').json()['challenge']
    attacker = ec.generate_private_key(ec.SECP256R1())
    assert client.post('/admin/auth', json=signed_request(attacker, challenge)).status_code == 401
    assert not hq.active_admin_sessions
    challenge = client.get('/admin/challenge').json()['challenge']
    response = client.post('/admin/auth', json=signed_request(private, challenge))
    assert response.status_code == 200
    assert hq.active_admin_sessions[response.json()['session_token']]['role'] == 'SUPER_ADMIN'
    assert client.post('/admin/auth', json=signed_request(private, challenge)).status_code == 401


def test_admin_challenge_expires_at_sixty_seconds(admin_client, monkeypatch):
    client, private = admin_client
    monkeypatch.setattr(hq.time, 'monotonic', lambda: 100.0)
    data = client.get('/admin/challenge').json()
    assert data['expires_in'] == 60
    monkeypatch.setattr(hq.time, 'monotonic', lambda: 160.0)
    assert client.post('/admin/auth', json=signed_request(private, data['challenge'])).status_code == 401
    assert not hq.active_admin_sessions


def test_missing_pin_blocks_production_before_database(monkeypatch):
    monkeypatch.setattr(hq, 'KORMIC_DEPLOYMENT_MODE', 'production')
    monkeypatch.setattr(hq, 'ADMIN_PUBKEY_SHA256', '')
    init = AsyncMock()
    monkeypatch.setattr(hq.db, 'init_pool', init)
    with pytest.raises(RuntimeError, match='MESHKOR_ADMIN_PUBKEY_SHA256'):
        with TestClient(hq.app):
            pass
    init.assert_not_called()


def test_malformed_pin_blocks_startup(monkeypatch):
    monkeypatch.setattr(hq, 'ADMIN_PUBKEY_SHA256', 'not-a-fingerprint')
    with pytest.raises(RuntimeError, match='SHA-256'):
        hq.validate_admin_key_configuration()

@pytest.fixture
def postgres_client(setup_meshkor_db, monkeypatch):
    monkeypatch.setattr(hq, 'active_admin_sessions', {})
    monkeypatch.setattr(hq.central, 'revoked_agents', set())
    with TestClient(hq.app) as client:
        yield client


def signup(client, label):
    import secrets
    email = f'{label}-{secrets.token_hex(6)}@example.test'
    password = secrets.token_urlsafe(24)
    response = client.post('/api/v1/auth/signup', json={
        'name': label, 'email': email, 'password': password,
    })
    assert response.status_code == 200
    login = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert login.status_code == 200
    assert 'api_key' not in login.json()
    return response.json(), login.json()['session_token']


def test_cross_org_all_four_routes_leave_database_and_registry_unchanged(postgres_client):
    client = postgres_client
    org_a, token_a = signup(client, 'A')
    org_b, token_b = signup(client, 'B')
    ain = 'test-' + org_b['org_id']
    client.portal.call(hq.db.add_twin, ain, {}, 'encrypted-test-payload', org_b['org_id'], 1)
    client.portal.call(hq.db.flag_suspect, ain, 'test', org_b['org_id'])
    hq.central.revoked_agents.add(ain)
    version = hq.central.version

    async def state():
        async with hq.db.pool.acquire() as conn:
            return (dict(await conn.fetchrow('SELECT * FROM twins WHERE ain=$1', ain)),
                    dict(await conn.fetchrow('SELECT * FROM suspects WHERE ain=$1', ain) or {}))

    before = client.portal.call(state)
    for path in ['/admin/revoke', '/admin/unblock', f'/admin/twins/{ain}/wake']:
        assert client.post(path, json={'token': token_a, 'ain': ain}).status_code == 403
    assert client.get(f'/admin/twins/{ain}/download', params={'token': token_a}).status_code == 403
    assert client.portal.call(state) == before
    assert hq.central.revoked_agents == {ain}
    assert hq.central.version == version
    # The legitimate owner can download and perform every operation.
    assert client.get(f'/admin/twins/{ain}/download', params={'token': token_b}).json() == {
        'encrypted_payload': 'encrypted-test-payload'}
    for path in ['/admin/unblock', '/admin/revoke', f'/admin/twins/{ain}/wake']:
        assert client.post(path, json={'token': token_b, 'ain': ain}).status_code == 200
    assert ain not in hq.central.revoked_agents
    assert client.portal.call(state)[0]['status'] == 'active'
    hq.active_admin_sessions['super-test'] = {'role': 'SUPER_ADMIN'}
    assert client.post('/admin/revoke', json={'token': 'super-test', 'ain': ain}).status_code == 200


def test_signup_key_works_and_legacy_environment_key_is_rejected(postgres_client, monkeypatch):
    client = postgres_client
    monkeypatch.setenv('MESHKOR_API_KEY', 'legacy-environment-test-key')
    org, token = signup(client, 'Kormic local test')
    assert org['api_key'].startswith('mk_live_')

    async def authenticate(key):
        return await hq.authenticate_api_key('Bearer ' + key)

    assert client.portal.call(authenticate, org['api_key'])['org_id'] == org['org_id']
    from fastapi import HTTPException
    for key in ['Meshkor-2026', 'legacy-environment-test-key', 'mk_live_unregistered']:
        with pytest.raises(HTTPException) as error:
            client.portal.call(authenticate, key)
        assert error.value.status_code == 401
        # Dependency must translate denial to a real HTTP response, not 200.
        assert client.post('/enroll', json={}, headers={
            'Authorization': 'Bearer ' + key,
        }).status_code == 401

    async def stored_hash():
        async with hq.db.pool.acquire() as conn:
            return await conn.fetchval('SELECT api_key_hash FROM organizations WHERE org_id=$1', org['org_id'])
    assert client.portal.call(stored_hash) == hashlib.sha256(org['api_key'].encode()).hexdigest()



@pytest.mark.parametrize('field,value', [('signature_hex', 'invalid-hex'), ('pub_key_pem', 'invalid-pem')])
def test_invalid_admin_proof_returns_401(admin_client, field, value):
    client, private = admin_client
    challenge = client.get('/admin/challenge').json()['challenge']
    request = signed_request(private, challenge)
    request[field] = value
    assert client.post('/admin/auth', json=request).status_code == 401
    assert not hq.active_admin_sessions


def test_no_configured_pin_cannot_authenticate_in_development(admin_client, monkeypatch):
    client, private = admin_client
    monkeypatch.setattr(hq, 'ADMIN_PUBKEY_SHA256', '')
    challenge = client.get('/admin/challenge').json()['challenge']
    assert client.post('/admin/auth', json=signed_request(private, challenge)).status_code == 401
