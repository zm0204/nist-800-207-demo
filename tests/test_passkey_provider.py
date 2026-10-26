import hashlib
import json
from tests.test_identity import identity, enroll
from tests.authenticator import Authenticator, b64


def invitation_options(client, subject='alice'):
    invite = client.post('/enrollment/invite', json={'subject':subject}, headers={'x-service-key':'test-key'}).json()
    return client.post('/register/options', json={'invitation':invite['invitation']}).json()


def test_invited_passkey_supports_password_managers_without_usb_attachment(identity):
    old = Authenticator()
    assert enroll(identity, old).status_code == 200
    opts = invitation_options(identity)
    p = opts['publicKey']
    assert p['rp']['id'] == 'localhost'
    assert p['authenticatorSelection']['residentKey'] == 'required'
    assert p['authenticatorSelection']['requireResidentKey'] is True
    assert p['authenticatorSelection']['userVerification'] == 'required'
    assert p['authenticatorSelection'].get('authenticatorAttachment') is None
    assert p['hints'] == ['client-device']
    assert p['excludeCredentials'] == [{'id':b64(old.id),'type':'public-key','transports':['internal']}]
    new = Authenticator()
    credential = new.register(p)
    credential['response']['transports'] = ['internal','hybrid']
    assert identity.post('/register/verify', json={'ceremony':opts['ceremony'],'credential':credential}).status_code == 200
    login = identity.post('/login/options', json={'subject':'alice'}).json()['publicKey']
    assert login['userVerification'] == 'required'
    by_id = {c['id']: c for c in login['allowCredentials']}
    assert by_id[b64(new.id)]['transports'] == ['internal','hybrid']
    assert b64(old.id) in by_id
    # Existing and newly added credentials both still verify real signatures.
    for auth in (old,new):
        o = identity.post('/login/options', json={'subject':'alice'}).json()
        assert identity.post('/login/verify', json={'ceremony':o['ceremony'],'credential':auth.login(o['publicKey'])}).status_code == 200


def test_new_environment_user_handle_does_not_replace_legacy_localhost_passkey(identity, monkeypatch):
    legacy = identity.post('/register/options', json={}).json()['publicKey']['user']['id']
    monkeypatch.setenv('PASSKEY_ACCOUNT_NAMESPACE','portal-p0')
    first = invitation_options(identity)['publicKey']['user']
    second = invitation_options(identity)['publicKey']['user']
    assert first['id'] != legacy
    assert first['id'] == second['id'] == b64(hashlib.sha256(b'portal-p0\0alice').digest())
    assert first['name'] == 'alice@portal-p0'


def test_legacy_unknown_transport_remains_unspecified_and_credential_unchanged(identity):
    from app.common import db
    auth = Authenticator()
    opts = invitation_options(identity)
    credential = auth.register(opts['publicKey'])
    credential['response'].pop('transports')
    assert identity.post('/register/verify', json={'ceremony':opts['ceremony'],'credential':credential}).status_code == 200
    with db('identity') as c:
        before = tuple(c.execute('SELECT id,public_key,counter,subject FROM credential').fetchone())
    from app.identity import initialize
    initialize()
    with db('identity') as c:
        assert tuple(c.execute('SELECT id,public_key,counter,subject FROM credential').fetchone()) == before
    descriptor = identity.post('/login/options', json={}).json()['publicKey']['allowCredentials'][0]
    assert not descriptor.get('transports')  # Unknown is not relabeled as USB or internal.
