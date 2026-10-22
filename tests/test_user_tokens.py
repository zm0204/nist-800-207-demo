import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def keys(tmp_path, monkeypatch):
    monkeypatch.setenv('STATE_DIR', str(tmp_path))
    from app import user_tokens as tokens
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / 'signing.pem'
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setenv('USER_SIGNING_KEY_FILE', str(path))
    public = tmp_path / 'jwks.json'
    public.write_text(json.dumps(tokens.public_jwks()))
    monkeypatch.setenv('USER_JWKS_FILE', str(public))
    return tokens, private


def claims():
    now = int(time.time())
    return dict(iss='https://zta.example/identity', sub='alice', aud='zta-hr',
                iat=now, exp=now+120, jti='unique', scope='salary:read profile:read',
                role='employee', device_id='device-a', auth_time=now, sid='session-ref')


def test_signed_tokens_are_short_lived_and_jwks_is_public(keys):
    tokens, _ = keys
    token = tokens.issue(claims())
    assert tokens.verify(token)['sub'] == 'alice'
    assert 'PRIVATE' not in json.dumps(tokens.public_jwks())
    assert not set(tokens.public_jwks()['keys'][0]) & {'d', 'p', 'q'}


@pytest.mark.parametrize('change', [dict(exp=1), dict(aud='other'), dict(iss='evil'),
    dict(iat=int(time.time())+60), dict(exp=int(time.time())+1000), dict(sub=''), dict(scope=[])])
def test_invalid_claims_never_authenticate(keys, change):
    tokens, private = keys
    payload = {**claims(), **change}
    token = jwt.encode(payload, private, algorithm='RS256', headers={'kid': tokens.public_jwks()['keys'][0]['kid']})
    with pytest.raises(ValueError):
        tokens.verify(token)


def test_missing_claim_signature_algorithm_and_key_confusion(keys):
    tokens, private = keys
    payload = claims()
    del payload['jti']
    for token in [jwt.encode(payload, private, algorithm='RS256', headers={'kid': tokens.public_jwks()['keys'][0]['kid']}),
                  jwt.encode(claims(), 'attacker-secret-that-is-at-least-32-bytes', algorithm='HS256', headers={'kid': 'invented'}),
                  jwt.encode(claims(), key='', algorithm='none'), 'forged']:
        with pytest.raises(ValueError):
            tokens.verify(token)


def test_unknown_signing_key_never_creates_private_key(tmp_path, monkeypatch):
    from app import user_tokens
    path = tmp_path / 'missing.pem'
    monkeypatch.setenv('USER_SIGNING_KEY_FILE', str(path))
    with pytest.raises((OSError, ValueError)):
        user_tokens.issue(claims())
    assert not path.exists()
